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
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Instant;
use tracing::info;

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
        "--2026-08-27 18:25:00--  {url}\r\nResolving {host} ({host})... 1.2.3.4\r\nConnecting to {host}|1.2.3.4|:80... connected.\r\nHTTP request sent, awaiting response... 200 OK\r\nLength: {size_bytes} ({size_kb}K) [application/octet-stream]\r\nSaving to: '{filename}'\r\n\r\n{filename}   100%[===================>]  {size_kb}.00K  --.-KB/s    in 0.1s\r\n\r\n2026-08-27 18:25:01 (512 KB/s) - '{filename}' saved [{size_bytes}]\r\n"
    )
}

// Modules declared at crate root in main.rs
use crate::vfs::VirtualFileSystem;
use crate::shell::dispatch;

// ---------------------------------------------------------------------------
// Shared Server State
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AegisServer {
    pub config: Arc<AegisConfig>,
    pub event_tx: EventSender,
    pub forensics: Arc<ForensicsEngine>,
}

// ---------------------------------------------------------------------------
// Per-Connection Handler
// ---------------------------------------------------------------------------

pub struct SessionHandler {
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
}

impl SessionHandler {
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
impl Handler for SessionHandler {
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
        })).await;

        let banner = "\r\nLinux ubuntu-server-01 5.15.0-72-generic #79-Ubuntu SMP x86_64\r\nWelcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-72-generic x86_64)\r\n\r\n * Documentation:  https://help.ubuntu.com\r\n * Management:     https://landscape.canonical.com\r\n * Support:        https://ubuntu.com/advantage\r\n\r\nLast login: Mon Aug 26 22:14:07 2026 from 192.168.1.100\r\n\r\n";
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
                    }
                }

                0x03 => {
                    self.last_byte = byte;
                    self.cmd_buffer.clear();
                    session.data(channel, russh::CryptoVec::from(b"^C\r\n".to_vec()));
                    let prompt = self.get_prompt();
                    self.send_output(channel, &prompt, session).await;
                }

                0x04 => {
                    self.last_byte = byte;
                    if self.cmd_buffer.is_empty() {
                        session.data(channel, russh::CryptoVec::from(b"logout\r\n".to_vec()));
                        session.close(channel);
                        self.teardown_session().await;
                    }
                }

                c if c.is_ascii_graphic() || c == b' ' => {
                    self.last_byte = byte;
                    let ch = char::from(byte);
                    self.cmd_buffer.push(ch);
                    let _ = self.recorder.record_input(&ch.to_string()).await;
                    session.data(channel, russh::CryptoVec::from(vec![byte]));
                }

                _ => { self.last_byte = byte; }
            }
        }
        Ok(())
    }

    async fn channel_close(&mut self, _channel: ChannelId, _session: &mut Session) -> Result<(), Self::Error> {
        self.teardown_session().await;
        Ok(())
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
        let meta = SessionMeta::new(addr.ip(), addr.port());
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

        SessionHandler {
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
        }
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
