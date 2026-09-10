//! `aegis-common` — Shared types, telemetry event schemas, and error definitions
//! consumed by every crate in the aegis-honeypot workspace.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use thiserror::Error;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Error Type
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum AegisError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("SSH error: {0}")]
    Ssh(String),

    #[error("Sandbox error: {0}")]
    Sandbox(String),

    #[error("eBPF error: {0}")]
    Ebpf(String),

    #[error("Forensics error: {0}")]
    Forensics(String),

    #[error("Config error: {0}")]
    Config(String),

    #[error("Channel closed")]
    ChannelClosed,
}

pub type AegisResult<T> = Result<T, AegisError>;

// ---------------------------------------------------------------------------
// Session Identity
// ---------------------------------------------------------------------------

/// Unique per-connection identity assigned by the gateway.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SessionId(pub String);

impl SessionId {
    pub fn new() -> Self {
        SessionId(Uuid::new_v4().simple().to_string()[..12].to_string())
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// Session Metadata
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMeta {
    pub session_id: SessionId,
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub start_ts: DateTime<Utc>,
}

impl SessionMeta {
    pub fn new(client_ip: IpAddr, client_port: u16) -> Self {
        Self {
            session_id: SessionId::new(),
            client_ip,
            client_port,
            start_ts: Utc::now(),
        }
    }
}

// ---------------------------------------------------------------------------
// Telemetry Events
// ---------------------------------------------------------------------------

/// All structured events emitted by the honeypot pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TelemetryEvent {
    SessionStart(SessionStartEvent),
    SessionEnd(SessionEndEvent),
    CredentialHarvest(CredentialHarvestEvent),
    CommandRun(CommandRunEvent),
    SyscallExecve(SyscallExecveEvent),
    SyscallConnect(SyscallConnectEvent),
    SyscallMemfdCreate(SyscallMemfdCreateEvent),
    PayloadCaptured(PayloadCapturedEvent),
}

impl TelemetryEvent {
    pub fn session_id(&self) -> Option<&SessionId> {
        match self {
            Self::SessionStart(e) => Some(&e.session_id),
            Self::SessionEnd(e) => Some(&e.session_id),
            Self::CredentialHarvest(e) => Some(&e.session_id),
            Self::CommandRun(e) => Some(&e.session_id),
            Self::SyscallExecve(e) => Some(&e.session_id),
            Self::SyscallConnect(e) => Some(&e.session_id),
            Self::SyscallMemfdCreate(e) => Some(&e.session_id),
            Self::PayloadCaptured(e) => Some(&e.session_id),
        }
    }
}

// --- Individual event structs ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStartEvent {
    pub timestamp: DateTime<Utc>,
    pub session_id: SessionId,
    pub ip: IpAddr,
    pub port: u16,
    /// Looked up once per session against a local MaxMind GeoLite2 database.
    /// `None` when GeoIP isn't configured, the lookup failed, or the DB has
    /// no record for this IP — never blocks or fails the session either way.
    pub geo: Option<GeoIpInfo>,
}

/// Resolved GeoIP data for one source IP. Every field is independently
/// optional: a City database gives country/city/lat/lon, an ASN database
/// (always a *separate* MaxMind download — never bundled into City) gives
/// `asn`, and either or both may be absent, missing, or not cover a given
/// address. Private/loopback/link-local addresses are tagged
/// `country: Some("Local")` with everything else `None` rather than being
/// sent to the database at all, where they'd never resolve to anything real.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct GeoIpInfo {
    pub country: Option<String>,
    pub city: Option<String>,
    pub asn: Option<String>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEndEvent {
    pub timestamp: DateTime<Utc>,
    pub session_id: SessionId,
    pub ip: IpAddr,
    pub duration_secs: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialHarvestEvent {
    pub timestamp: DateTime<Utc>,
    pub session_id: SessionId,
    pub ip: IpAddr,
    pub username: String,
    pub password: Option<String>,
    pub auth_method: AuthMethod,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    Password,
    PublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandRunEvent {
    pub timestamp: DateTime<Utc>,
    pub session_id: SessionId,
    pub ip: IpAddr,
    pub command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallExecveEvent {
    pub timestamp: DateTime<Utc>,
    pub session_id: SessionId,
    pub ip: IpAddr,
    pub pid: u32,
    pub filename: String,
    pub argv: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallConnectEvent {
    pub timestamp: DateTime<Utc>,
    pub session_id: SessionId,
    pub ip: IpAddr,
    pub pid: u32,
    pub dest_ip: IpAddr,
    pub dest_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallMemfdCreateEvent {
    pub timestamp: DateTime<Utc>,
    pub session_id: SessionId,
    pub ip: IpAddr,
    pub pid: u32,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadCapturedEvent {
    pub timestamp: DateTime<Utc>,
    pub session_id: SessionId,
    pub ip: IpAddr,
    pub source_url: Option<String>,
    pub sha256: String,
    pub size_bytes: u64,
    pub quarantine_path: String,
    pub file_type: PayloadFileType,
    pub iocs: IocFindings,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadFileType {
    Elf,
    Shell,
    Pe,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IocFindings {
    pub strings_preview: Vec<String>,
    pub ip_addresses: Vec<String>,
    pub urls: Vec<String>,
    pub base64_blobs: Vec<String>,
    pub monero_wallets: Vec<String>,
}

// ---------------------------------------------------------------------------
// eBPF RingBuffer Wire Format (C-repr, shared with kernel-side programs)
// ---------------------------------------------------------------------------

/// Event type tags matching the eBPF kernel programs.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelEventType {
    Execve = 1,
    Connect = 2,
    MemfdCreate = 3,
}

/// Fixed-size struct written into the RingBuf by eBPF programs.
/// Must stay layout-compatible with the kernel-side `struct kernel_event`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KernelEvent {
    pub event_type: u32,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub ns_pid: u32,           // PID inside the sandbox namespace
    pub dest_ip: u32,          // For connect events (big-endian)
    pub dest_port: u16,        // For connect events (big-endian)
    pub _pad: u16,
    pub filename: [u8; 128],   // execve filename / memfd name
    pub argv: [u8; 256],       // execve argv (space-joined, null-terminated)
}

impl KernelEvent {
    pub fn filename_str(&self) -> &str {
        let end = self.filename.iter().position(|&b| b == 0).unwrap_or(128);
        std::str::from_utf8(&self.filename[..end]).unwrap_or("<invalid>")
    }

    pub fn argv_str(&self) -> &str {
        let end = self.argv.iter().position(|&b| b == 0).unwrap_or(256);
        std::str::from_utf8(&self.argv[..end]).unwrap_or("<invalid>")
    }

    pub fn dest_ip_addr(&self) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::from(u32::from_be(self.dest_ip))
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AegisConfig {
    pub gateway: GatewayConfig,
    pub vmm: VmmConfig,
    pub forensics: ForensicsConfig,
    pub logging: LoggingConfig,
    /// The `aegis-dashboard` binary is a separate, unprivileged process; it
    /// reads this same config purely for `bind`/`port` plus the `forensics`
    /// paths above (it tails `attacks_log` and reports on `quarantine_dir`).
    #[serde(default = "default_dashboard_config")]
    pub dashboard: DashboardConfig,
    #[serde(default)]
    pub geoip: GeoIpConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GeoIpConfig {
    /// Path to a local GeoLite2-City `.mmdb` file (gives country/city/lat/lon).
    /// Free from MaxMind — see the README's GeoIP section. Omit, or point at
    /// a file that doesn't exist, to disable GeoIP tagging entirely; nothing
    /// else about the honeypot depends on this being present.
    pub geoip_db_path: Option<String>,
    /// Path to a local GeoLite2-ASN `.mmdb` file (gives the network/ASN).
    /// A separate free download from MaxMind — ASN data is never bundled
    /// into the City database. Independently optional from `geoip_db_path`.
    pub asn_db_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardConfig {
    pub bind_addr: String,
    pub port: u16,
    /// Require a bearer token (`Authorization: Bearer <token>`, or `?token=`
    /// on the SSE endpoint since `EventSource` can't set headers) on every
    /// request. Defaults to true; only disable for local dev where the
    /// dashboard never leaves loopback.
    #[serde(default = "default_require_auth")]
    pub require_auth: bool,
    /// Path to the persistent bearer token. Generated on first run if
    /// missing and reused across restarts — same pattern as the gateway's
    /// `host_key_path`.
    #[serde(default = "default_token_path")]
    pub token_path: String,
}

fn default_dashboard_config() -> DashboardConfig {
    DashboardConfig {
        bind_addr: "127.0.0.1".into(),
        port: 8080,
        require_auth: default_require_auth(),
        token_path: default_token_path(),
    }
}

fn default_require_auth() -> bool {
    true
}

fn default_token_path() -> String {
    "./dashboard_token".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    pub bind_addr: String,
    pub port: u16,
    /// Hard cap on total concurrent SSH sessions across all clients.
    pub max_sessions: usize,
    /// Hard cap on concurrent SSH sessions from a single source IP. `0` disables the check.
    #[serde(default = "default_max_sessions_per_ip")]
    pub max_sessions_per_ip: u32,
    /// Max new connections accepted from a single source IP per rolling 60s window. `0` disables the check.
    #[serde(default = "default_max_connects_per_min_per_ip")]
    pub max_connects_per_min_per_ip: u32,
    /// Path to a persistent Ed25519 host key (PEM). Generated on first run if missing.
    /// Leave unset for an ephemeral key regenerated on every restart (not recommended —
    /// a host key that changes across reconnects is a fingerprintable honeypot tell).
    pub host_key_path: Option<String>,
}

fn default_max_sessions_per_ip() -> u32 {
    8
}

fn default_max_connects_per_min_per_ip() -> u32 {
    20
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmmConfig {
    pub rootfs_path: String,
    pub overlay_base: String,
    pub memory_limit_mb: u64,
    pub cpu_quota_percent: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicsConfig {
    pub quarantine_dir: String,
    pub sessions_dir: String,
    pub attacks_log: String,
    pub string_min_len: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub json: bool,
}

impl Default for AegisConfig {
    fn default() -> Self {
        Self {
            gateway: GatewayConfig {
                bind_addr: "0.0.0.0".into(),
                port: 2222,
                max_sessions: 256,
                max_sessions_per_ip: default_max_sessions_per_ip(),
                max_connects_per_min_per_ip: default_max_connects_per_min_per_ip(),
                host_key_path: Some("./host_key.pem".into()),
            },
            vmm: VmmConfig {
                rootfs_path: "./rootfs".into(),
                overlay_base: "./overlay".into(),
                memory_limit_mb: 256,
                cpu_quota_percent: 20,
            },
            forensics: ForensicsConfig {
                quarantine_dir: "./quarantine".into(),
                sessions_dir: "./sessions".into(),
                attacks_log: "./attacks.json".into(),
                string_min_len: 6,
            },
            logging: LoggingConfig {
                level: "info".into(),
                json: false,
            },
            dashboard: default_dashboard_config(),
            geoip: GeoIpConfig::default(),
        }
    }
}

impl AegisConfig {
    pub fn from_file(path: &str) -> AegisResult<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| AegisError::Config(format!("cannot read {path}: {e}")))?;
        toml::from_str(&content)
            .map_err(|e| AegisError::Config(format!("parse error in {path}: {e}")))
    }
}
