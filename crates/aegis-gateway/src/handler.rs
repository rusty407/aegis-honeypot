//! `aegis-gateway` — Async SSH frontend with OpenSSH 9.6p1 anti-fingerprint spoofing.
//!
//! Each incoming connection gets:
//!   - A unique `SessionId`
//!   - An isolated OverlayFS-backed `SandboxHandle`
//!   - A live `VirtualFileSystem` instance mapped to the sandbox mount
//!   - A `SessionRecorder` tracking terminal I/O in Asciinema v2 format
//!   - An automated forensics teardown hook analyzing upperdir on disconnect

use aegis_common::{
    AegisConfig, AuthMethod, CommandRunEvent, CredentialHarvestEvent, IocFindings,
    PayloadCapturedEvent, PayloadFileType, SessionEndEvent, SessionMeta, SessionStartEvent,
    TelemetryEvent,
};
use aegis_collector::EventSender;
use aegis_forensics::ForensicsEngine;
use aegis_vmm::SandboxHandle;
use async_trait::async_trait;
use chrono::Utc;
use regex::Regex;
use russh::server::{Auth, Handler, Msg, Server, Session};
use russh::{Channel, ChannelId};
use russh_keys::key::KeyPair;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// SSRF Guard & Payload Interception
// ---------------------------------------------------------------------------

static RE_DOWNLOAD: OnceLock<Regex> = OnceLock::new();
static RE_URL: OnceLock<Regex> = OnceLock::new();
static RE_PIPE_SHELL: OnceLock<Regex> = OnceLock::new();

fn re_download() -> &'static Regex {
    RE_DOWNLOAD.get_or_init(|| Regex::new(r"(?:wget|curl|tftp)\s").unwrap())
}
fn re_url() -> &'static Regex {
    RE_URL.get_or_init(|| Regex::new(r"https?://[^\s;&|<>']+").unwrap())
}
fn re_pipe_shell() -> &'static Regex {
    RE_PIPE_SHELL.get_or_init(|| Regex::new(r"(?:wget|curl).+\|\s*(?:sh|bash|python3?|perl)").unwrap())
}

fn is_private_addr(host: &str) -> bool {
    use std::net::ToSocketAddrs;
    if matches!(host.to_lowercase().as_str(), "localhost" | "localhost.localdomain") {
        return true;
    }
    if let Ok(mut addrs) = format!("{host}:80").to_socket_addrs() {
        if let Some(addr) = addrs.next() {
            let ip = addr.ip();
            let blocked = ip.is_loopback() || ip.is_unspecified() || match ip {
                std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
                std::net::IpAddr::V6(v6) => v6.is_loopback(),
            };
            return blocked;
        }
    }
    false
}

fn fake_wget_progress(url: &str, size_kb: usize) -> String {
    let filename = url.rsplit('/').next().unwrap_or("payload");
    let filename = if filename.is_empty() { "index.html" } else { filename };
    let size_kb = if size_kb == 0 { 64 } else { size_kb };
    let host = url.split('/').nth(2).unwrap_or("example.com");
    let size_bytes = size_kb * 1024;
    format!(
        "--2026-08-27 18:25:00--  {url}\r\nResolving {host} ({host})... 192.0.2.1\r\nConnecting to {host}|192.0.2.1|:80... connected.\r\nHTTP request sent, awaiting response... 200 OK\r\nLength: {size_bytes} ({size_kb}K) [application/octet-stream]\r\nSaving to: '{filename}'\r\n\r\n{filename}   100%[===================>]  {size_kb}.00K  --.-KB/s    in 0.1s\r\n\r\n2026-08-27 18:25:01 (512 KB/s) - '{filename}' saved [{size_bytes}]\r\n"
    )
}

// Modules declared at crate root in main.rs
use crate::vfs::VirtualFileSystem;
use crate::shell::dispatch;

// ---------------------------------------------------------------------------
// Connection Admission Control (global cap + per-IP concurrency/rate limits)
// ---------------------------------------------------------------------------

struct IpEntry {
    active: u32,
    recent_connects: VecDeque<Instant>,
}

/// Tracks concurrent sessions and connection rate per source IP so a single
/// botnet host can't monopolize the global session pool or hammer the
/// listener with reconnects. Cheap, lock-guarded, non-blocking — never held
/// across an `.await`.
pub struct IpConnectionGuard {
    max_per_ip: u32,
    max_per_minute: u32,
    entries: StdMutex<HashMap<IpAddr, IpEntry>>,
}

impl IpConnectionGuard {
    pub fn new(max_per_ip: u32, max_per_minute: u32) -> Self {
        Self {
            max_per_ip,
            max_per_minute,
            entries: StdMutex::new(HashMap::new()),
        }
    }

    /// Attempt to admit a new connection from `ip`. On success the caller
    /// takes ownership of one admitted "slot" and must call `release(ip)`
    /// exactly once when the connection ends (or admission is abandoned).
    fn try_admit(&self, ip: IpAddr) -> bool {
        let mut map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let entry = map.entry(ip).or_insert_with(|| IpEntry {
            active: 0,
            recent_connects: VecDeque::new(),
        });

        let now = Instant::now();
        while matches!(entry.recent_connects.front(), Some(t) if now.duration_since(*t) > Duration::from_secs(60))
        {
            entry.recent_connects.pop_front();
        }

        if self.max_per_ip > 0 && entry.active >= self.max_per_ip {
            return false;
        }
        if self.max_per_minute > 0 && entry.recent_connects.len() as u32 >= self.max_per_minute {
            return false;
        }

        entry.active += 1;
        entry.recent_connects.push_back(now);
        true
    }

    fn release(&self, ip: IpAddr) {
        let mut map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = map.get_mut(&ip) {
            entry.active = entry.active.saturating_sub(1);
            if entry.active == 0 && entry.recent_connects.is_empty() {
                map.remove(&ip);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Shared Server State
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AegisServer {
    pub config: Arc<AegisConfig>,
    pub event_tx: EventSender,
    pub forensics: Arc<ForensicsEngine>,
    pub session_semaphore: Arc<Semaphore>,
    pub ip_guard: Arc<IpConnectionGuard>,
    pub geoip: Arc<crate::geoip::GeoIpLookup>,
}

// ---------------------------------------------------------------------------
// Per-Connection Handler
// ---------------------------------------------------------------------------

/// A fully provisioned, admitted session: sandbox, VFS, recorder, and the
/// admission-control handles it must release on drop.
pub struct ActiveSession {
    meta: SessionMeta,
    session_start: Instant,
    vfs: VirtualFileSystem,
    cmd_buffer: String,
    escape_seq: bool,
    last_byte: u8,
    event_tx: EventSender,
    config: Arc<AegisConfig>,
    recorder: aegis_collector::SessionRecorder,
    forensics: Arc<ForensicsEngine>,
    sandbox: Option<SandboxHandle>,
    is_ended: bool,
    /// Held for the lifetime of the session; releases the global session
    /// slot back to the pool when the handler is dropped.
    _permit: OwnedSemaphorePermit,
    ip_guard: Arc<IpConnectionGuard>,
    geoip: Arc<crate::geoip::GeoIpLookup>,
}

impl Drop for ActiveSession {
    fn drop(&mut self) {
        self.ip_guard.release(self.meta.client_ip);
    }
}

impl ActiveSession {
    async fn send_output(&mut self, channel: ChannelId, data: &str, session: &mut Session) {
        session.data(channel, russh::CryptoVec::from(data.as_bytes().to_vec()));
        let _ = self.recorder.record_output(data).await;
    }

    fn get_prompt(&self) -> String {
        let dir = if self.vfs.current_path == vec!["root".to_string()] {
            "~".into()
        } else if self.vfs.current_path.first().map(|s| s.as_str()) == Some("root") {
            format!("~/{}", self.vfs.current_path[1..].join("/"))
        } else if self.vfs.current_path.is_empty() {
            "/".into()
        } else {
            format!("/{}", self.vfs.current_path.join("/"))
        };
        format!("root@ubuntu-server-01:{dir}# ")
    }

    async fn teardown_session(&mut self) {
        if self.is_ended {
            return;
        }
        self.is_ended = true;
        let duration = self.session_start.elapsed().as_secs_f64();
        self.event_tx.send(TelemetryEvent::SessionEnd(SessionEndEvent {
            timestamp: Utc::now(),
            session_id: self.meta.session_id.clone(),
            ip: self.meta.client_ip,
            duration_secs: duration,
        })).await;

        let _ = self.recorder.close().await;

        // OverlayFS teardown & Forensics Analysis
        if let Some(sandbox) = self.sandbox.take() {
            if let Ok(Some(upper_dir)) = sandbox.teardown().await {
                info!("Running forensics scan on upperdir: {}", upper_dir.display());
                let _ = self.forensics.analyze_upperdir(&upper_dir, &self.meta).await;

                // Clean up session temporary directory after forensics completes
                if let Some(session_dir) = upper_dir.parent() {
                    let _ = tokio::fs::remove_dir_all(session_dir).await;
                }
            }
        }
    }
}

#[async_trait]
impl Handler for ActiveSession {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        self.event_tx.send(TelemetryEvent::CredentialHarvest(CredentialHarvestEvent {
            timestamp: Utc::now(),
            session_id: self.meta.session_id.clone(),
            ip: self.meta.client_ip,
            username: user.to_owned(),
            password: Some(password.to_owned()),
            auth_method: AuthMethod::Password,
        })).await;
        Ok(Auth::Accept)
    }

    async fn auth_publickey(&mut self, user: &str, public_key: &russh_keys::key::PublicKey) -> Result<Auth, Self::Error> {
        self.event_tx.send(TelemetryEvent::CredentialHarvest(CredentialHarvestEvent {
            timestamp: Utc::now(),
            session_id: self.meta.session_id.clone(),
            ip: self.meta.client_ip,
            username: user.to_owned(),
            password: Some(format!("pubkey:{}", public_key.name())),
            auth_method: AuthMethod::PublicKey,
        })).await;
        Ok(Auth::Accept)
    }

    async fn channel_open_session(&mut self, _channel: Channel<Msg>, _session: &mut Session) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn pty_request(&mut self, _channel: ChannelId, _term: &str, _col_width: u32, _row_height: u32, _pix_width: u32, _pix_height: u32, _modes: &[(russh::Pty, u32)], _session: &mut Session) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        self.event_tx.send(TelemetryEvent::SessionStart(SessionStartEvent {
            timestamp: Utc::now(),
            session_id: self.meta.session_id.clone(),
            ip: self.meta.client_ip,
            port: self.meta.client_port,
            geo: self.geoip.lookup(self.meta.client_ip),
        })).await;

        let banner = "\r\nLinux ubuntu-server-01 5.15.0-72-generic #79-Ubuntu SMP x86_64\r\nWelcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-72-generic x86_64)\r\n\r\n * Documentation:  https://help.ubuntu.com\r\n * Management:     https://landscape.canonical.com\r\n * Support:        https://ubuntu.com/advantage\r\n\r\nLast login: Mon Aug 26 22:14:07 2026 from 192.0.2.100\r\n\r\n";
        self.send_output(channel, banner, session).await;
        let prompt = self.get_prompt();
        self.send_output(channel, &prompt, session).await;
        Ok(())
    }

    async fn data(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        for &byte in data {
            if byte == 0x1b {
                self.escape_seq = true;
                self.last_byte = byte;
                continue;
            }
            if self.escape_seq {
                if byte.is_ascii_alphabetic() || matches!(byte, b'~' | b'A' | b'B' | b'C' | b'D') {
                    self.escape_seq = false;
                }
                self.last_byte = byte;
                continue;
            }

            match byte {
                b'\r' | b'\n' => {
                    if byte == b'\n' && self.last_byte == b'\r' {
                        self.last_byte = byte;
                        continue;
                    }
                    self.last_byte = byte;
                    session.data(channel, russh::CryptoVec::from(b"\r\n".to_vec()));
                    let _ = self.recorder.record_output("\r\n").await;

                    let cmd = self.cmd_buffer.trim().to_owned();
                    self.cmd_buffer.clear();

                    if !cmd.is_empty() {
                        let _ = self.recorder.record_input(&(cmd.clone() + "\n")).await;
                        self.event_tx.send(TelemetryEvent::CommandRun(CommandRunEvent {
                            timestamp: Utc::now(),
                            session_id: self.meta.session_id.clone(),
                            ip: self.meta.client_ip,
                            command: cmd.clone(),
                        })).await;

                        if cmd.trim() == "exit" || cmd.trim() == "logout" {
                            self.send_output(channel, "logout\r\n", session).await;
                            session.close(channel);
                            self.teardown_session().await;
                            return Ok(());
                        }

                        let response = if re_download().is_match(&cmd) {
                            let urls: Vec<&str> = re_url().find_iter(&cmd).map(|m| m.as_str()).collect();
                            if urls.is_empty() {
                                let tool = cmd.split_whitespace().next().unwrap_or("wget");
                                format!("{tool}: missing URL\r\n")
                            } else {
                                let url = urls[0].to_owned();
                                let host = url.split('/').nth(2).unwrap_or("").to_owned();
                                let meta = self.meta.clone();
                                let event_tx2 = self.event_tx.clone();
                                let qdir = self.config.forensics.quarantine_dir.clone();
                                let is_pipe = re_pipe_shell().is_match(&cmd);
                                let url2 = url.clone();
                                let mount_root = self.vfs.mount_root.clone();

                                let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
                                tokio::task::spawn_blocking(move || {
                                    let result = fetch_payload_blocking(&url, &host, &meta, &qdir, mount_root.as_deref());
                                    let _ = resp_tx.send(result);
                                });

                                match tokio::time::timeout(std::time::Duration::from_secs(7), resp_rx).await {
                                    Ok(Ok((progress, payload_info))) => {
                                        if let Some((sha256, size_bytes, qpath, iocs)) = payload_info {
                                            event_tx2.send(TelemetryEvent::PayloadCaptured(PayloadCapturedEvent {
                                                timestamp: Utc::now(),
                                                session_id: self.meta.session_id.clone(),
                                                ip: self.meta.client_ip,
                                                source_url: Some(url2),
                                                sha256,
                                                size_bytes,
                                                quarantine_path: qpath,
                                                file_type: PayloadFileType::Unknown,
                                                iocs,
                                            })).await;
                                        }
                                        let mut out = progress;
                                        if is_pipe {
                                            out.push_str("[*] Attempting install...\r\nbash: ./setup.sh: Permission denied\r\n");
                                        }
                                        out
                                    }
                                    _ => fake_wget_progress(&url2, 64),
                                }
                            }
                        } else {
                            dispatch(&cmd, &mut self.vfs)
                        };

                        self.send_output(channel, &response, session).await;
                    }
                    let prompt = self.get_prompt();
                    self.send_output(channel, &prompt, session).await;
                }

                0x7f | 0x08 => {
                    self.last_byte = byte;
                    if !self.cmd_buffer.is_empty() {
                        self.cmd_buffer.pop();
                        session.data(channel, russh::CryptoVec::from(b"\x08 \x08".to_vec()));
                        // Recorded as visual output (what the terminal actually showed),
                        // not input, so session replay renders the correction faithfully.
                        let _ = self.recorder.record_output("\x08 \x08").await;
                    }
                }

                0x03 => {
                    self.last_byte = byte;
                    self.cmd_buffer.clear();
                    self.send_output(channel, "^C\r\n", session).await;
                    let prompt = self.get_prompt();
                    self.send_output(channel, &prompt, session).await;
                }

                0x04 => {
                    self.last_byte = byte;
                    if self.cmd_buffer.is_empty() {
                        self.send_output(channel, "logout\r\n", session).await;
                        session.close(channel);
                        self.teardown_session().await;
                    }
                }

                c if c.is_ascii_graphic() || c == b' ' => {
                    self.last_byte = byte;
                    let ch = char::from(byte);
                    self.cmd_buffer.push(ch);
                    session.data(channel, russh::CryptoVec::from(vec![byte]));
                    // Echoed character is what appears on the attacker's screen, so it
                    // belongs in the "o" (visual) stream for faithful session replay.
                    let _ = self.recorder.record_output(&ch.to_string()).await;
                }

                _ => { self.last_byte = byte; }
            }
        }
        // Flush once per network read rather than per character/write: bounds
        // worst-case data loss on an abrupt disconnect to at most this one
        // read's worth of typing, without paying a syscall per keystroke.
        let _ = self.recorder.flush().await;
        Ok(())
    }

    async fn channel_close(&mut self, _channel: ChannelId, _session: &mut Session) -> Result<(), Self::Error> {
        self.teardown_session().await;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Public Handler Facade — admits a real ActiveSession, or a Rejected stub
// for connections turned away by admission control (see `new_client` below).
// The `Rejected` arm relies entirely on `Handler`'s built-in defaults, which
// already reject every auth method and refuse every channel — so it needs
// no method bodies beyond `type Error`.
// ---------------------------------------------------------------------------

pub enum SessionHandler {
    Active(Box<ActiveSession>),
    Rejected,
}

#[async_trait]
impl Handler for SessionHandler {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        match self {
            Self::Active(s) => s.auth_password(user, password).await,
            Self::Rejected => Ok(Auth::Reject { proceed_with_methods: None }),
        }
    }

    async fn auth_publickey(&mut self, user: &str, public_key: &russh_keys::key::PublicKey) -> Result<Auth, Self::Error> {
        match self {
            Self::Active(s) => s.auth_publickey(user, public_key).await,
            Self::Rejected => Ok(Auth::Reject { proceed_with_methods: None }),
        }
    }

    async fn channel_open_session(&mut self, channel: Channel<Msg>, session: &mut Session) -> Result<bool, Self::Error> {
        match self {
            Self::Active(s) => s.channel_open_session(channel, session).await,
            Self::Rejected => Ok(false),
        }
    }

    async fn pty_request(&mut self, channel: ChannelId, term: &str, col_width: u32, row_height: u32, pix_width: u32, pix_height: u32, modes: &[(russh::Pty, u32)], session: &mut Session) -> Result<(), Self::Error> {
        match self {
            Self::Active(s) => s.pty_request(channel, term, col_width, row_height, pix_width, pix_height, modes, session).await,
            Self::Rejected => Ok(()),
        }
    }

    async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        match self {
            Self::Active(s) => s.shell_request(channel, session).await,
            Self::Rejected => Ok(()),
        }
    }

    async fn data(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        match self {
            Self::Active(s) => s.data(channel, data, session).await,
            Self::Rejected => Ok(()),
        }
    }

    async fn channel_close(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        match self {
            Self::Active(s) => s.channel_close(channel, session).await,
            Self::Rejected => Ok(()),
        }
    }
}

// ---------------------------------------------------------------------------
// Blocking payload fetch
// ---------------------------------------------------------------------------

fn fetch_payload_blocking(
    url: &str,
    host: &str,
    _meta: &SessionMeta,
    quarantine_dir: &str,
    mount_root: Option<&Path>,
) -> (String, Option<(String, u64, String, IocFindings)>) {
    if is_private_addr(host) {
        return (fake_wget_progress(url, 64), None);
    }
    let client = match reqwest::blocking::Client::builder()
        .user_agent("Wget/1.21.2 (linux-gnu)")
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return (fake_wget_progress(url, 64), None),
    };
    match client.get(url).send() {
        Ok(resp) => {
            let bytes = resp.bytes().unwrap_or_default();
            let size_bytes = bytes.len() as u64;
            let size_kb = (size_bytes / 1024) as usize;
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let sha256 = hex::encode(hasher.finalize());
            let qpath = format!("{quarantine_dir}/{sha256}");

            // 1. Quarantine copy with restricted permissions
            if let Ok(()) = std::fs::write(&qpath, &bytes) {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&qpath, std::fs::Permissions::from_mode(0o600));
            }

            // 2. Also save to session live mount root for attacker inspection & OverlayFS capture
            if let Some(mount) = mount_root {
                let filename = url.rsplit('/').next().unwrap_or("payload");
                let filename = if filename.is_empty() { "index.html" } else { filename };
                let target_path = mount.join("root").join(filename);
                let _ = std::fs::write(&target_path, &bytes);
            }

            let iocs = extract_iocs_from_bytes(&bytes);
            (fake_wget_progress(url, size_kb), Some((sha256, size_bytes, qpath, iocs)))
        }
        Err(_) => (fake_wget_progress(url, 64), None),
    }
}

fn extract_iocs_from_bytes(data: &[u8]) -> IocFindings {
    static RE_IP: OnceLock<Regex> = OnceLock::new();
    static RE_URL_IOC: OnceLock<Regex> = OnceLock::new();
    let re_ip = RE_IP.get_or_init(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap());
    let re_url = RE_URL_IOC.get_or_init(|| Regex::new(r"https?://[^\s'<>]+").unwrap());
    let text: String = data.iter()
        .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { ' ' })
        .collect();
    let ip_addresses: Vec<String> = re_ip.find_iter(&text).map(|m| m.as_str().to_owned())
        .collect::<std::collections::HashSet<_>>().into_iter().collect();
    let urls: Vec<String> = re_url.find_iter(&text).map(|m| m.as_str().to_owned())
        .collect::<std::collections::HashSet<_>>().into_iter().collect();
    IocFindings { strings_preview: vec![], ip_addresses, urls, base64_blobs: vec![], monero_wallets: vec![] }
}

// ---------------------------------------------------------------------------
// Server Implementation
// ---------------------------------------------------------------------------

impl Server for AegisServer {
    type Handler = SessionHandler;

    fn new_client(&mut self, peer_addr: Option<SocketAddr>) -> Self::Handler {
        let addr = peer_addr.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
        let ip = addr.ip();

        // Admission control: per-IP concurrency/rate limit first (cheap, avoids
        // spinning up a sandbox+recorder for connections we're about to drop),
        // then the global concurrent-session cap.
        if !self.ip_guard.try_admit(ip) {
            warn!(
                "Rejecting connection from {ip}: per-IP session/rate limit exceeded (max {}/ip, {}/min)",
                self.config.gateway.max_sessions_per_ip, self.config.gateway.max_connects_per_min_per_ip
            );
            return SessionHandler::Rejected;
        }
        let permit = match self.session_semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                warn!(
                    "Rejecting connection from {ip}: global session limit reached ({})",
                    self.config.gateway.max_sessions
                );
                self.ip_guard.release(ip);
                return SessionHandler::Rejected;
            }
        };

        let meta = SessionMeta::new(ip, addr.port());
        let session_id = meta.session_id.clone();
        info!("New client: {} -> {}", addr, session_id);

        let sessions_dir = PathBuf::from(&self.config.forensics.sessions_dir);
        let cast_path = sessions_dir.join(format!("{session_id}.cast"));

        // Initialize session recorder and OverlayFS sandbox
        let (recorder, sandbox) = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let rec = aegis_collector::SessionRecorder::open(cast_path, session_id.clone())
                    .await
                    .expect("Failed to open session recorder");

                let lower_dir = Path::new(&self.config.vmm.rootfs_path);
                let overlay_base = Path::new(&self.config.vmm.overlay_base);
                let sb = aegis_vmm::spawn_sandbox(&meta, lower_dir, overlay_base)
                    .await
                    .ok();

                (rec, sb)
            })
        });

        let mount_root = sandbox.as_ref().map(|s| s.root_dir.clone());
        let lower_root = Some(PathBuf::from(&self.config.vmm.rootfs_path));
        let vfs = VirtualFileSystem::with_roots(mount_root, lower_root);

        SessionHandler::Active(Box::new(ActiveSession {
            meta,
            session_start: Instant::now(),
            vfs,
            cmd_buffer: String::new(),
            escape_seq: false,
            last_byte: 0,
            event_tx: self.event_tx.clone(),
            config: self.config.clone(),
            recorder,
            forensics: self.forensics.clone(),
            sandbox,
            is_ended: false,
            _permit: permit,
            ip_guard: self.ip_guard.clone(),
            geoip: self.geoip.clone(),
        }))
    }
}

pub fn build_russh_config(keypair: KeyPair) -> russh::server::Config {
    russh::server::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
        auth_rejection_time: std::time::Duration::from_millis(800),
        auth_rejection_time_initial: Some(std::time::Duration::from_millis(200)),
        keys: vec![keypair],
        ..Default::default()
    }
}

#[cfg(test)]
mod admission_tests {
    use super::IpConnectionGuard;

    fn ip(n: u8) -> std::net::IpAddr {
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, n))
    }

    #[test]
    fn admits_up_to_per_ip_concurrency_cap() {
        let guard = IpConnectionGuard::new(2, 0);
        let a = ip(1);
        assert!(guard.try_admit(a));
        assert!(guard.try_admit(a));
        assert!(!guard.try_admit(a), "third concurrent session from the same IP must be rejected");

        guard.release(a);
        assert!(guard.try_admit(a), "releasing a slot should free capacity again");
    }

    #[test]
    fn per_ip_cap_does_not_affect_other_ips() {
        let guard = IpConnectionGuard::new(1, 0);
        let a = ip(1);
        let b = ip(2);
        assert!(guard.try_admit(a));
        assert!(!guard.try_admit(a));
        assert!(guard.try_admit(b), "a different source IP must have its own budget");
    }

    #[test]
    fn enforces_connect_rate_limit() {
        let guard = IpConnectionGuard::new(0, 3);
        let a = ip(1);
        assert!(guard.try_admit(a));
        assert!(guard.try_admit(a));
        assert!(guard.try_admit(a));
        assert!(!guard.try_admit(a), "a 4th connect within the same window must be rejected");
    }

    #[test]
    fn zero_means_unlimited() {
        let guard = IpConnectionGuard::new(0, 0);
        let a = ip(1);
        for _ in 0..50 {
            assert!(guard.try_admit(a));
        }
    }

    #[test]
    fn release_is_idempotent_safe_on_unknown_ip() {
        // Releasing an IP that was never admitted (e.g. a defensive double-release)
        // must not panic.
        let guard = IpConnectionGuard::new(1, 0);
        guard.release(ip(9));
    }
}
