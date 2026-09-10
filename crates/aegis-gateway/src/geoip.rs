//! GeoIP tagging — resolves a source IP to country/city/ASN using local
//! MaxMind GeoLite2 `.mmdb` files.
//!
//! Both databases are optional and loaded independently: a missing or
//! malformed file is logged once at startup and treated as "this lookup
//! type is disabled," never as a reason to fail startup or refuse
//! connections. GeoIP is cosmetic telemetry attached to `SessionStartEvent`
//! — nothing about the honeypot's core function should ever depend on it
//! being present.

use aegis_common::GeoIpInfo;
use maxminddb::geoip2;
use std::net::IpAddr;
use tracing::{info, warn};

pub struct GeoIpLookup {
    city: Option<maxminddb::Reader<Vec<u8>>>,
    asn: Option<maxminddb::Reader<Vec<u8>>>,
}

impl GeoIpLookup {
    /// Load the configured `.mmdb` files, if any are configured and readable.
    pub async fn load(city_path: Option<&str>, asn_path: Option<&str>) -> Self {
        let city = load_one(city_path, "GeoLite2-City").await;
        let asn = load_one(asn_path, "GeoLite2-ASN").await;
        if city.is_none() && asn.is_none() {
            info!("GeoIP tagging disabled (no geoip.geoip_db_path / asn_db_path configured)");
        }
        Self { city, asn }
    }

    /// Resolve `ip`. Private/loopback/link-local addresses are never sent to
    /// the database — they'd never resolve to anything real — and are
    /// tagged `country: "Local"` instead, distinguishing "we didn't look
    /// this up" from "we looked it up and MaxMind has no record."
    pub fn lookup(&self, ip: IpAddr) -> Option<GeoIpInfo> {
        if is_private_or_local(ip) {
            return Some(GeoIpInfo {
                country: Some("Local".into()),
                ..Default::default()
            });
        }

        let mut info = GeoIpInfo::default();
        let mut found = false;

        if let Some(reader) = &self.city {
            if let Some(city) = decode::<geoip2::City>(reader, ip) {
                info.country = city
                    .country
                    .names
                    .english
                    .map(String::from)
                    .or_else(|| city.country.iso_code.map(String::from));
                info.city = city.city.names.english.map(String::from);
                info.lat = city.location.latitude;
                info.lon = city.location.longitude;
                found = true;
            }
        }

        if let Some(reader) = &self.asn {
            if let Some(asn) = decode::<geoip2::Asn>(reader, ip) {
                info.asn = asn
                    .autonomous_system_organization
                    .map(String::from)
                    .or_else(|| asn.autonomous_system_number.map(|n| format!("AS{n}")));
                found = true;
            }
        }

        found.then_some(info)
    }
}

fn decode<'r, T>(reader: &'r maxminddb::Reader<Vec<u8>>, ip: IpAddr) -> Option<T>
where
    T: serde::Deserialize<'r>,
{
    reader.lookup(ip).ok()?.decode().ok().flatten()
}

fn is_private_or_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_unspecified() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

async fn load_one(path: Option<&str>, label: &str) -> Option<maxminddb::Reader<Vec<u8>>> {
    let path = path?;
    let path_owned = path.to_string();
    let label_owned = label.to_string();

    // GeoLite2-City can be tens of MB; read it off the async runtime's
    // worker threads rather than blocking one during startup.
    let result = tokio::task::spawn_blocking(move || maxminddb::Reader::open_readfile(&path_owned)).await;

    match result {
        Ok(Ok(reader)) => {
            info!("Loaded {label} database from {path}");
            Some(reader)
        }
        Ok(Err(e)) => {
            warn!("Failed to load {label} database at {path} ({e}) — continuing without it");
            None
        }
        Err(join_err) => {
            warn!("{label_owned} database load task panicked: {join_err}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn private_and_loopback_addresses_are_tagged_local_without_a_db() {
        let geoip = GeoIpLookup::load(None, None).await;

        for ip in [
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)),
        ] {
            let info = geoip.lookup(ip).expect("private IPs are always tagged, never skipped");
            assert_eq!(info.country.as_deref(), Some("Local"));
            assert_eq!(info.city, None);
            assert_eq!(info.asn, None);
        }
    }

    #[tokio::test]
    async fn public_ip_with_no_database_loaded_returns_none() {
        let geoip = GeoIpLookup::load(None, None).await;
        let public_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(geoip.lookup(public_ip), None);
    }

    #[tokio::test]
    async fn missing_database_file_does_not_panic_or_block_startup() {
        // Nonexistent path — must degrade to "disabled," never error out.
        let geoip = GeoIpLookup::load(Some("/nonexistent/GeoLite2-City.mmdb"), None).await;
        let public_ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(geoip.lookup(public_ip), None);
    }

    /// MaxMind's own public test fixture (Apache-2.0, from maxmind/MaxMind-DB)
    /// — a real, valid `.mmdb` with a handful of known sample records, so this
    /// exercises the actual decode path against real data instead of only the
    /// "no database" fallback the tests above cover.
    #[tokio::test]
    async fn real_database_resolves_a_known_test_record() {
        let db_path = concat!(env!("CARGO_MANIFEST_DIR"), "/test-data/GeoIP2-City-Test.mmdb");
        let geoip = GeoIpLookup::load(Some(db_path), None).await;

        // Documented sample record in MaxMind's test fixture: Linköping, Sweden.
        let ip: IpAddr = "89.160.20.128".parse().unwrap();
        let info = geoip.lookup(ip).expect("known test IP must resolve");

        assert_eq!(info.country.as_deref(), Some("Sweden"));
        assert_eq!(info.city.as_deref(), Some("Linköping"));
        assert_eq!(info.lat, Some(58.4167));
        assert_eq!(info.lon, Some(15.6167));
        // The test fixture has no ASN data at all — only City.
        assert_eq!(info.asn, None);
    }
}
