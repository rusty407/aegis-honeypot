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
use chrono::Utc;
use regex::Regex;
use russh::keys::{HashAlg, PrivateKey, PublicKey};
use russh::server::{Auth, ChannelOpenHandle, Handler, Msg, Server, Session};
use russh::{Channel, ChannelId, ChannelOpenFailure};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Attacker-input limits
//
// Every one of these bounds a value an attacker controls directly. Without
// them the corresponding buffer, file or map grows for as long as the client
// keeps talking, which is the whole DoS surface of a honeypot: it must survive
// being abused, because being abused is its job.
// ---------------------------------------------------------------------------

/// Hard cap on a single command line assembled from attacker keystrokes.
///
/// `cmd_buffer` only clears on a newline or Ctrl-C, so without a cap a client
/// that types without ever sending `\n` grows it without bound — and every
/// echoed byte is also written to the session recording. Real readline-backed
/// shells have a line limit too, so truncating here costs no realism.
const MAX_COMMAND_LEN: usize = 8 * 1024;

/// Longest terminal escape sequence tracked before resynchronising.
///
/// `escape_seq` was previously cleared only by an ASCII letter, so a client
/// that sent ESC followed only by digits or punctuation latched it forever and
/// every subsequent byte was silently discarded. Real CSI sequences are short.
const MAX_ESCAPE_SEQ_LEN: usize = 16;

/// Cap on harvested username/password fields.
///
/// These arrive as arbitrary SSH protocol strings — unlike interactive shell
/// input they are never filtered to printable ASCII, and nothing in the
/// protocol bounds them usefully. They are persisted to `attacks.json` forever
/// and keyed into the dashboard's in-memory counters, so an unbounded value is
/// a memory-growth primitive at both ends of the pipeline.
const MAX_CREDENTIAL_LEN: usize = 256;

/// Idle timeout for an authenticated session.
///
/// The previous hour let an attacker park on a session slot at zero cost;
/// with `max_sessions` slots that is a cheap way to exhaust the pool. Long
/// enough that a slow interactive attacker is not cut off mid-recon.
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(900);

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

/// Addresses the payload fetcher must never connect to.
///
/// Deliberately broader than "private": the fetcher runs in the gateway
/// process, on the host's network, so anything it can reach is reachable by an
/// attacker who types a URL. Link-local covers the cloud metadata service
/// (169.254.169.254), which is the highest-value target on most deployments.
fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || o[0] == 0                                    // 0.0.0.0/8
                || (o[0] == 100 && (64..128).contains(&o[1]))    // CGNAT 100.64/10
                || (o[0] == 192 && o[1] == 0 && o[2] == 2)       // TEST-NET-1
                || (o[0] == 198 && (18..20).contains(&o[1]))     // benchmarking
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)    // TEST-NET-2
                || (o[0] == 203 && o[1] == 0 && o[2] == 113)     // TEST-NET-3
                || o[0] >= 240                                   // reserved 240/4
        }
        IpAddr::V6(v6) => {
            // Normalise the IPv4-mapped form (::ffff:127.0.0.1) first, or every
            // v4 rule below would be trivially sidestepped by spelling the
            // address as IPv6.
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_blocked_ip(IpAddr::V4(mapped));
            }
            let seg0 = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (seg0 & 0xfe00) == 0xfc00 // unique-local fc00::/7
                || (seg0 & 0xffc0) == 0xfe80 // link-local  fe80::/10
        }
    }
}

/// Resolve `url`'s host and return the single vetted address the fetch is
/// allowed to connect to, or the reason it was refused.
///
/// Returning a concrete `SocketAddr` — which the caller pins onto the HTTP
/// client via `ClientBuilder::resolve` — is what closes the TOCTOU: the old
/// guard resolved the name, checked only the *first* answer, then let `reqwest`
/// resolve again independently, so a hostile resolver could return a public
/// address to the check and a private one to the connection. Here the address
/// that was checked is the address that gets dialled.
///
/// Fails **closed**: anything that cannot be parsed, resolved, or confidently
/// classified is refused. The old guard returned `false` (allow) on every
/// parse failure, which is what made `http://127.0.0.1:8080/` and
/// `http://evil.com@127.0.0.1/` reachable — both produced a host string that
/// `format!("{host}:80")` could not parse.
fn vet_target(url: &reqwest::Url) -> Result<SocketAddr, String> {
    use std::net::ToSocketAddrs;

    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!("scheme {:?} not allowed", url.scheme()));
    }
    let host = url.host_str().ok_or_else(|| "URL has no host".to_owned())?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "URL has no port".to_owned())?;

    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("resolve {host}: {e}"))?
        .collect();

    let Some(first) = addrs.first().copied() else {
        return Err(format!("{host} resolved to no addresses"));
    };
    // Refuse if *any* answer is blocked, not just the one we would pick. A name
    // that resolves to both a public and a private address is a rebinding
    // attempt, not a legitimate target.
    if let Some(bad) = addrs.iter().find(|a| is_blocked_ip(a.ip())) {
        return Err(format!("{host} resolves to blocked address {}", bad.ip()));
    }
    Ok(first)
}

/// Last path segment of `url`, reduced to something safe to use as a filename.
///
/// The payload is written into the session mount root, so this must never be
/// able to name a parent directory or a nested path.
fn safe_filename(url: &reqwest::Url) -> String {
    let candidate = url
        .path_segments()
        .and_then(std::iter::Iterator::last)
        .unwrap_or("");
    if candidate.is_empty()
        || candidate == "."
        || candidate == ".."
        || candidate.contains('/')
        || candidate.contains('\\')
        || candidate.starts_with('.')
    {
        return "index.html".to_owned();
    }
    candidate.chars().take(128).collect()
}

/// Truncate an attacker-supplied credential field on a char boundary.
fn truncate_credential(s: &str) -> String {
    match s.char_indices().nth(MAX_CREDENTIAL_LEN) {
        Some((idx, _)) => format!("{}…", &s[..idx]),
        None => s.to_owned(),
    }
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

/// Rolling window for the per-prefix connect-rate limit.
const RATE_WINDOW: Duration = Duration::from_secs(60);

/// Upper bound on distinct source prefixes tracked at once.
///
/// Reached only under a rotating-source flood; the sweep below normally keeps
/// the map far smaller. Once full, previously-unseen prefixes are refused
/// rather than allowed, so the limiter degrades closed.
const MAX_TRACKED_PREFIXES: usize = 65_536;

/// Bucket a source address to the prefix its operator is actually allocated.
///
/// Keying on the exact `IpAddr` made the per-IP limits meaningless over IPv6:
/// a routed /64 — standard from most VPS providers and many consumer ISPs —
/// gives an attacker 2^64 source addresses and therefore a fresh
/// `max_sessions_per_ip` / `max_connects_per_min_per_ip` budget for every
/// single connection. IPv4 keeps full-address granularity; IPv6 collapses to
/// the /64.
fn admission_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[8..].fill(0);
            IpAddr::V6(std::net::Ipv6Addr::from(octets))
        }
    }
}

struct IpEntry {
    active: u32,
    recent_connects: VecDeque<Instant>,
}

impl IpEntry {
    /// An entry is reclaimable once nothing is using it and its rate-limit
    /// window has fully drained — at that point it carries no information.
    fn is_stale(&self, now: Instant) -> bool {
        self.active == 0
            && !self
                .recent_connects
                .iter()
                .any(|t| now.duration_since(*t) <= RATE_WINDOW)
    }
}

/// Tracks concurrent sessions and connection rate per source IP so a single
/// botnet host can't monopolize the global session pool or hammer the
/// listener with reconnects. Cheap, lock-guarded, non-blocking — never held
/// across an `.await`.
struct GuardState {
    entries: HashMap<IpAddr, IpEntry>,
    /// When the stale-entry sweep last ran, so it stays amortized rather than
    /// running on every admission once the table is large.
    last_sweep: Instant,
}

pub struct IpConnectionGuard {
    max_per_ip: u32,
    max_per_minute: u32,
    state: StdMutex<GuardState>,
}

impl IpConnectionGuard {
    pub fn new(max_per_ip: u32, max_per_minute: u32) -> Self {
        Self {
            max_per_ip,
            max_per_minute,
            state: StdMutex::new(GuardState {
                entries: HashMap::new(),
                last_sweep: Instant::now(),
            }),
        }
    }

    /// Attempt to admit a new connection from `ip`. On success the caller
    /// takes ownership of one admitted "slot" and must call `release(ip)`
    /// exactly once when the connection ends (or admission is abandoned).
    fn try_admit(&self, ip: IpAddr) -> bool {
        let key = admission_key(ip);
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();

        // Reclaim stale entries. `release` can only drop an entry whose window
        // has already drained, and the window was only ever pruned inside this
        // function for the *one* key being admitted — so an entry for a source
        // that never returns was retained forever, and connection churn from a
        // rotating source became unbounded memory growth.
        //
        // The sweep is O(n), so it runs at most once per rate window and only
        // once the table is large enough to be worth walking. Running it on
        // every admission would make a full table cost O(n) per connection,
        // which is its own denial of service.
        if st.entries.len() >= MAX_TRACKED_PREFIXES / 2
            && now.duration_since(st.last_sweep) >= RATE_WINDOW
        {
            st.entries.retain(|_, e| !e.is_stale(now));
            st.last_sweep = now;
        }
        if st.entries.len() >= MAX_TRACKED_PREFIXES && !st.entries.contains_key(&key) {
            warn!("Admission table full ({MAX_TRACKED_PREFIXES} prefixes); refusing new source {key}");
            return false;
        }

        let entry = st.entries.entry(key).or_insert_with(|| IpEntry {
            active: 0,
            recent_connects: VecDeque::new(),
        });

        while matches!(entry.recent_connects.front(), Some(t) if now.duration_since(*t) > RATE_WINDOW)
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
        let key = admission_key(ip);
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = st.entries.get_mut(&key) {
            entry.active = entry.active.saturating_sub(1);
            if entry.active == 0 && entry.recent_connects.is_empty() {
                st.entries.remove(&key);
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
    /// Bytes consumed by the in-progress escape sequence, so a malformed one
    /// can't latch `escape_seq` on forever (see `MAX_ESCAPE_SEQ_LEN`).
    escape_len: usize,
    last_byte: u8,
    /// Payload fetches already performed for this session, against
    /// `forensics.max_fetches_per_session`.
    fetch_count: u32,
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

        // A session that never reached a clean `exit` or `channel_close` —
        // dropped TCP connection, idle timeout, client killed mid-handshake —
        // still owns a sandbox holding a mount and a session directory.
        // `OverlayMount::drop` releases the mount, but the *directory* and the
        // artifacts inside it are the honeypot's actual product, so they need
        // the same forensics pass the clean path gets rather than being left
        // for the next startup to reconcile.
        //
        // `Drop` cannot be async, so the work is handed to the runtime. If
        // there is no runtime (dropped during shutdown), the sandbox still
        // unmounts via its own `Drop` and the directory is reclaimed by
        // `reclaim_orphaned_sessions` on the next start.
        if self.is_ended {
            return;
        }
        let Some(sandbox) = self.sandbox.take() else {
            return;
        };
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let forensics = self.forensics.clone();
        let meta = self.meta.clone();
        handle.spawn(async move {
            if let Ok(Some(upper_dir)) = sandbox.teardown().await {
                let _ = forensics.analyze_upperdir(&upper_dir, &meta).await;
                if let Some(session_dir) = upper_dir.parent() {
                    let _ = tokio::fs::remove_dir_all(session_dir).await;
                }
            }
        });
    }
}

impl ActiveSession {
    /// Write to the channel and mirror it into the session recording.
    ///
    /// `Session::data` returns a `Result` as of russh 0.63 (it used to be
    /// infallible), so a failed write now propagates instead of being dropped
    /// on the floor — if the peer is gone there is no point continuing to
    /// render a shell at it.
    async fn send_output(
        &mut self,
        channel: ChannelId,
        data: &str,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        session.data(channel, data.as_bytes().to_vec())?;
        let _ = self.recorder.record_output(data).await;
        Ok(())
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

impl Handler for ActiveSession {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        self.event_tx.send(TelemetryEvent::CredentialHarvest(CredentialHarvestEvent {
            timestamp: Utc::now(),
            session_id: self.meta.session_id.clone(),
            ip: self.meta.client_ip,
            username: truncate_credential(user),
            password: Some(truncate_credential(password)),
            auth_method: AuthMethod::Password,
        })).await;
        Ok(Auth::Accept)
    }

    async fn auth_publickey(&mut self, user: &str, public_key: &PublicKey) -> Result<Auth, Self::Error> {
        self.event_tx.send(TelemetryEvent::CredentialHarvest(CredentialHarvestEvent {
            timestamp: Utc::now(),
            session_id: self.meta.session_id.clone(),
            ip: self.meta.client_ip,
            username: truncate_credential(user),
            // Record the key fingerprint, not just the algorithm name: it is
            // the one credential-harvest field that correlates a single actor
            // across source IPs, which is exactly what a honeypot wants.
            password: Some(truncate_credential(&format!(
                "pubkey:{} {}",
                public_key.algorithm().as_str(),
                public_key.fingerprint(HashAlg::Sha256)
            ))),
            auth_method: AuthMethod::PublicKey,
        })).await;
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // russh 0.63 replaced the `Ok(true)`/`Ok(false)` return with an
        // explicit handle; dropping it without answering auto-rejects.
        reply.accept().await;
        Ok(())
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
        self.send_output(channel, banner, session).await?;
        let prompt = self.get_prompt();
        self.send_output(channel, &prompt, session).await?;
        Ok(())
    }

    async fn data(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        for &byte in data {
            if byte == 0x1b {
                self.escape_seq = true;
                self.escape_len = 0;
                self.last_byte = byte;
                continue;
            }
            if self.escape_seq {
                self.escape_len += 1;
                // Terminate on a plausible final byte, or bail out once the
                // sequence has run longer than any real one would — otherwise
                // `\x1b` followed by digits forever swallows the whole session.
                if byte.is_ascii_alphabetic()
                    || byte == b'~'
                    || self.escape_len >= MAX_ESCAPE_SEQ_LEN
                {
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
                    session.data(channel, b"\r\n".to_vec())?;
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
                            self.send_output(channel, "logout\r\n", session).await?;
                            session.close(channel)?;
                            self.teardown_session().await;
                            return Ok(());
                        }

                        let response = if re_download().is_match(&cmd) {
                            let urls: Vec<&str> = re_url().find_iter(&cmd).map(|m| m.as_str()).collect();
                            if urls.is_empty() {
                                let tool = cmd.split_whitespace().next().unwrap_or("wget");
                                format!("{tool}: missing URL\r\n")
                            } else if !self.config.forensics.fetch_payloads
                                || self.fetch_count >= self.config.forensics.max_fetches_per_session
                            {
                                // Egress disabled, or this session has spent its
                                // fetch budget. Either way the attacker sees a
                                // normal download; we just never make the request.
                                fake_wget_progress(&urls[0].to_owned(), 64)
                            } else {
                                self.fetch_count += 1;
                                let url = urls[0].to_owned();
                                let meta = self.meta.clone();
                                let event_tx2 = self.event_tx.clone();
                                let qdir = self.config.forensics.quarantine_dir.clone();
                                let is_pipe = re_pipe_shell().is_match(&cmd);
                                let url2 = url.clone();
                                let mount_root = self.vfs.mount_root.clone();
                                let max_bytes = self.config.forensics.max_payload_bytes;

                                let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
                                tokio::task::spawn_blocking(move || {
                                    let result = fetch_payload_blocking(&url, &meta, &qdir, mount_root.as_deref(), max_bytes);
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

                        self.send_output(channel, &response, session).await?;
                    }
                    let prompt = self.get_prompt();
                    self.send_output(channel, &prompt, session).await?;
                }

                0x7f | 0x08 => {
                    self.last_byte = byte;
                    if !self.cmd_buffer.is_empty() {
                        self.cmd_buffer.pop();
                        session.data(channel, b"\x08 \x08".to_vec())?;
                        // Recorded as visual output (what the terminal actually showed),
                        // not input, so session replay renders the correction faithfully.
                        let _ = self.recorder.record_output("\x08 \x08").await;
                    }
                }

                0x03 => {
                    self.last_byte = byte;
                    self.cmd_buffer.clear();
                    self.send_output(channel, "^C\r\n", session).await?;
                    let prompt = self.get_prompt();
                    self.send_output(channel, &prompt, session).await?;
                }

                0x04 => {
                    self.last_byte = byte;
                    if self.cmd_buffer.is_empty() {
                        self.send_output(channel, "logout\r\n", session).await?;
                        session.close(channel)?;
                        self.teardown_session().await;
                    }
                }

                c if c.is_ascii_graphic() || c == b' ' => {
                    self.last_byte = byte;
                    if self.cmd_buffer.len() >= MAX_COMMAND_LEN {
                        // Drop the excess instead of echoing it: no buffer
                        // growth, no recording growth, and the (truncated)
                        // line still runs on the next newline, so the session
                        // stays believable rather than going silent.
                        continue;
                    }
                    let ch = char::from(byte);
                    self.cmd_buffer.push(ch);
                    session.data(channel, vec![byte])?;
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

impl Handler for SessionHandler {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        match self {
            Self::Active(s) => s.auth_password(user, password).await,
            Self::Rejected => Ok(Auth::reject()),
        }
    }

    async fn auth_publickey(&mut self, user: &str, public_key: &PublicKey) -> Result<Auth, Self::Error> {
        match self {
            Self::Active(s) => s.auth_publickey(user, public_key).await,
            Self::Rejected => Ok(Auth::reject()),
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        match self {
            Self::Active(s) => s.channel_open_session(channel, reply, session).await,
            Self::Rejected => {
                reply
                    .reject(ChannelOpenFailure::AdministrativelyProhibited)
                    .await;
                Ok(())
            }
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

/// Fetch an attacker-supplied URL, bounded in every dimension an attacker
/// controls: which address it may reach, how many bytes it may read, and how
/// much it may write.
///
/// The attacker always sees a plausible `wget` transcript regardless of what
/// actually happened — a refusal looks exactly like a success, so the guard
/// itself is not a fingerprinting oracle.
fn fetch_payload_blocking(
    url: &str,
    _meta: &SessionMeta,
    quarantine_dir: &str,
    mount_root: Option<&Path>,
    max_bytes: u64,
) -> (String, Option<(String, u64, String, IocFindings)>) {
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;

    let decoy = || fake_wget_progress(url, 64);

    let Ok(parsed) = reqwest::Url::parse(url) else {
        return (decoy(), None);
    };
    let target = match vet_target(&parsed) {
        Ok(t) => t,
        Err(reason) => {
            // Logged, not surfaced: the operator needs to know an SSRF attempt
            // happened, the attacker must not learn the fetch was blocked.
            warn!("Refusing payload fetch for {url}: {reason}");
            return (decoy(), None);
        }
    };
    let Some(host) = parsed.host_str() else {
        return (decoy(), None);
    };

    let client = match reqwest::blocking::Client::builder()
        .user_agent("Wget/1.21.2 (linux-gnu)")
        .timeout(Duration::from_secs(5))
        // Redirects were previously followed (up to 10 by default) with the
        // guard applied only to the original URL, so a 302 to 169.254.169.254
        // bypassed vetting entirely. Nothing legitimate here needs them.
        .redirect(reqwest::redirect::Policy::none())
        // Pin the connection to the address `vet_target` actually checked.
        .resolve(host, target)
        .build()
    {
        Ok(c) => c,
        Err(_) => return (decoy(), None),
    };

    let Ok(mut resp) = client.get(parsed.clone()).send() else {
        return (decoy(), None);
    };

    // Reject early on an advertised oversize body, but never trust the header
    // as the only check — the read loop below enforces the real limit.
    if resp.content_length().is_some_and(|len| len > max_bytes) {
        warn!("Refusing payload fetch for {url}: advertised length exceeds cap");
        return (decoy(), None);
    }

    // Stream with a hard cap. The previous `resp.bytes()` buffered the entire
    // response, so a multi-gigabyte body meant a multi-gigabyte allocation plus
    // two full-size disk writes — bounded only by a 5s timeout, which on a fast
    // link is not a bound at all.
    let cap = usize::try_from(max_bytes).unwrap_or(usize::MAX);
    let mut body: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        match resp.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                let remaining = cap.saturating_sub(body.len());
                if n >= remaining {
                    body.extend_from_slice(&chunk[..remaining]);
                    warn!("Truncated payload from {url} at {cap} byte cap");
                    break;
                }
                body.extend_from_slice(&chunk[..n]);
            }
            Err(_) => break,
        }
    }

    let size_bytes = body.len() as u64;
    let size_kb = usize::try_from(size_bytes / 1024).unwrap_or(usize::MAX);
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let sha256 = hex::encode(hasher.finalize());
    let qpath = format!("{quarantine_dir}/{sha256}");

    // 1. Quarantine copy with restricted permissions
    if std::fs::write(&qpath, &body).is_ok() {
        let _ = std::fs::set_permissions(&qpath, std::fs::Permissions::from_mode(0o600));
    }

    // 2. Also save to the session mount root for attacker inspection &
    //    OverlayFS capture. `safe_filename` keeps this inside `<mount>/root`.
    if let Some(mount) = mount_root {
        let target_path = mount.join("root").join(safe_filename(&parsed));
        let _ = std::fs::write(&target_path, &body);
    }

    let iocs = extract_iocs_from_bytes(&body);
    (fake_wget_progress(url, size_kb), Some((sha256, size_bytes, qpath, iocs)))
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

        // Initialize session recorder and OverlayFS sandbox.
        //
        // The recorder is opened *first* and its failure aborts admission, so a
        // sandbox is never provisioned (and leaked) for a session we are about
        // to refuse.
        let provisioned = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let rec = aegis_collector::SessionRecorder::open(cast_path, session_id.clone())
                    .await?;

                let lower_dir = Path::new(&self.config.vmm.rootfs_path);
                let overlay_base = Path::new(&self.config.vmm.overlay_base);
                let sb = aegis_vmm::spawn_sandbox(&meta, lower_dir, overlay_base)
                    .await
                    .ok();

                Ok::<_, aegis_common::AegisError>((rec, sb))
            })
        });

        let (recorder, sandbox) = match provisioned {
            Ok(pair) => pair,
            Err(e) => {
                // Opening the recorder fails when the disk is full, inodes are
                // exhausted, or we are out of file descriptors — every one of
                // which an attacker can drive. The previous `.expect` turned
                // that resource exhaustion into a panic on *every* subsequent
                // connection, so the honeypot appeared to run while collecting
                // nothing. Declining the session keeps it alive and observable.
                warn!("Rejecting connection from {ip}: cannot open session recorder: {e}");
                drop(permit);
                self.ip_guard.release(ip);
                return SessionHandler::Rejected;
            }
        };

        let mount_root = sandbox.as_ref().map(|s| s.root_dir.clone());
        let lower_root = Some(PathBuf::from(&self.config.vmm.rootfs_path));
        let vfs = VirtualFileSystem::with_roots(mount_root, lower_root);

        SessionHandler::Active(Box::new(ActiveSession {
            meta,
            session_start: Instant::now(),
            vfs,
            cmd_buffer: String::new(),
            escape_seq: false,
            escape_len: 0,
            last_byte: 0,
            fetch_count: 0,
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

pub fn build_russh_config(keypair: PrivateKey) -> russh::server::Config {
    russh::server::Config {
        // Without this, russh's `Default` advertises `SSH-2.0-russh_<version>`
        // — identifying the honeypot as a Rust SSH server in the first bytes of
        // every connection, before key exchange, to anyone running `nc` and to
        // Shodan/Censys on their routine scans. Matching a real Ubuntu 22.04
        // OpenSSH package string keeps the banner consistent with the
        // `uname` / `os-release` / `ps` output the fake shell emits.
        //
        // NOTE: this fixes the *banner* only. The `hasshServer` fingerprint —
        // an MD5 over the KEX/cipher/MAC/compression algorithm lists in
        // SSH_MSG_KEXINIT — still reflects russh's defaults, which match no
        // OpenSSH release. Aligning `Preferred` and offering an RSA host key
        // alongside Ed25519 is the remaining half of that fix.
        server_id: russh::SshId::Standard(
            std::borrow::Cow::Borrowed("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.4"),
        ),
        inactivity_timeout: Some(SESSION_IDLE_TIMEOUT),
        auth_rejection_time: std::time::Duration::from_millis(800),
        auth_rejection_time_initial: Some(std::time::Duration::from_millis(200)),
        keys: vec![keypair],
        ..Default::default()
    }
}

#[cfg(test)]
mod ssrf_tests {
    use super::{is_blocked_ip, safe_filename, truncate_credential, vet_target, MAX_CREDENTIAL_LEN};
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn blocks_loopback_private_and_metadata_addresses() {
        for addr in [
            "127.0.0.1", "127.1.2.3", "0.0.0.0", "10.0.0.1", "172.16.0.1",
            "192.168.1.1", "169.254.169.254", // cloud metadata — the big one
            "100.64.0.1",                      // CGNAT
            "255.255.255.255", "240.0.0.1", "224.0.0.1",
        ] {
            assert!(is_blocked_ip(ip(addr)), "{addr} must be blocked");
        }
    }

    #[test]
    fn blocks_ipv6_loopback_ula_and_link_local() {
        for addr in ["::1", "::", "fc00::1", "fd00::1", "fe80::1", "ff02::1"] {
            assert!(is_blocked_ip(ip(addr)), "{addr} must be blocked");
        }
    }

    /// Spelling a blocked v4 address as IPv4-mapped IPv6 must not evade the
    /// v4 rules.
    #[test]
    fn blocks_ipv4_mapped_ipv6_form() {
        assert!(is_blocked_ip(ip("::ffff:127.0.0.1")));
        assert!(is_blocked_ip(ip("::ffff:169.254.169.254")));
    }

    #[test]
    fn allows_ordinary_public_addresses() {
        for addr in ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700::1111"] {
            assert!(!is_blocked_ip(ip(addr)), "{addr} must be allowed");
        }
    }

    /// The old guard built `format!("{host}:80")` from a host string that
    /// still carried the port, so `127.0.0.1:8080` produced `127.0.0.1:8080:80`
    /// — unparseable — and the function fell through to "allow". Same for URL
    /// userinfo. Both must now be refused.
    #[test]
    fn refuses_explicit_port_and_userinfo_bypasses() {
        for raw in [
            "http://127.0.0.1:8080/",
            "http://127.0.0.1:1234/x",
            "http://evil.com@127.0.0.1/",
            "http://user:pass@127.0.0.1:9000/",
            "http://[::1]:8080/",
            "http://169.254.169.254/latest/meta-data/",
        ] {
            let url = reqwest::Url::parse(raw).expect("test URL parses");
            assert!(vet_target(&url).is_err(), "{raw} must be refused");
        }
    }

    /// Anything unparseable or non-HTTP fails closed, rather than the old
    /// behaviour of returning "not private" and proceeding.
    #[test]
    fn fails_closed_on_non_http_schemes() {
        for raw in ["file:///etc/passwd", "gopher://127.0.0.1/", "ftp://10.0.0.1/"] {
            let url = reqwest::Url::parse(raw).expect("test URL parses");
            assert!(vet_target(&url).is_err(), "{raw} must be refused");
        }
    }

    #[test]
    fn safe_filename_never_escapes_the_mount_root() {
        for (raw, expected) in [
            ("http://x.test/a/b/payload.bin", "payload.bin"),
            ("http://x.test/", "index.html"),
            ("http://x.test/a/", "index.html"),
            ("http://x.test/..", "index.html"),
            ("http://x.test/a/../..", "index.html"),
            ("http://x.test/.bashrc", "index.html"),
        ] {
            let url = reqwest::Url::parse(raw).unwrap();
            let got = safe_filename(&url);
            assert_eq!(got, expected, "{raw}");
            assert!(!got.contains('/') && got != ".." && got != ".");
        }
    }

    #[test]
    fn credentials_are_truncated_on_a_char_boundary() {
        let long = "é".repeat(MAX_CREDENTIAL_LEN * 2);
        let out = truncate_credential(&long);
        assert!(out.chars().count() <= MAX_CREDENTIAL_LEN + 1);
        assert_eq!(truncate_credential("short"), "short");
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

    fn ipv6(s: &str) -> std::net::IpAddr {
        s.parse().unwrap()
    }

    /// Keying on the exact address gave an attacker with a routed /64 a fresh
    /// budget per connection, which made the per-IP limits decorative.
    #[test]
    fn ipv6_addresses_in_one_slash_64_share_a_budget() {
        let guard = IpConnectionGuard::new(2, 0);
        assert!(guard.try_admit(ipv6("2001:db8:1:2::1")));
        assert!(guard.try_admit(ipv6("2001:db8:1:2::2")));
        assert!(
            !guard.try_admit(ipv6("2001:db8:1:2::dead:beef")),
            "a third address in the same /64 must be refused"
        );
        // A different /64 is a different operator, so it gets its own budget.
        assert!(guard.try_admit(ipv6("2001:db8:1:3::1")));
    }

    #[test]
    fn ipv6_rate_limit_also_applies_per_slash_64() {
        let guard = IpConnectionGuard::new(0, 3);
        for i in 0..3 {
            assert!(guard.try_admit(ipv6(&format!("2001:db8::{i}"))));
        }
        assert!(!guard.try_admit(ipv6("2001:db8::ffff")));
    }

    /// Entries were only reclaimable via `release`, and only when their window
    /// had already drained — which it never had, because the window was pruned
    /// only inside `try_admit` for the key being admitted. Churn from rotating
    /// sources therefore grew the map without bound.
    #[test]
    fn admission_table_does_not_grow_without_bound() {
        let guard = IpConnectionGuard::new(0, 0);
        // Comfortably past the cap; the point is that the table stops growing,
        // not how quickly it gets there.
        let limit = u32::try_from(super::MAX_TRACKED_PREFIXES).unwrap() + 5_000;
        for i in 0..limit {
            let a = (i >> 8) as u16;
            let b = (i & 0xff) as u16;
            let addr = ipv6(&format!("2001:db8:{a:x}:{b:x}::1"));
            guard.try_admit(addr);
            guard.release(addr);
        }
        let len = guard.state.lock().unwrap().entries.len();
        assert!(
            len <= super::MAX_TRACKED_PREFIXES,
            "admission table grew to {len} entries"
        );
    }
}
