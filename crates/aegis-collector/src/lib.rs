//! aegis-collector -- Event pipeline: receives TelemetryEvents from all crates,
//! serializes them as JSON lines to attacks.json, and provides SessionRecorder
//! for Asciinema v2 cast files.

use aegis_common::{AegisResult, SessionId, TelemetryEvent};
use std::fmt::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

// ---------------------------------------------------------------------------
// Output limits
// ---------------------------------------------------------------------------

/// Rotate `attacks.json` once it passes this size.
///
/// The log is append-only and attacker-driven: every command, every auth
/// attempt, every payload adds a line, forever. Without rotation, filling the
/// disk is a matter of patience — and once writes start failing the gateway
/// loses its ability to open new session recordings too, so log growth
/// escalates into refused connections.
const MAX_LOG_BYTES: u64 = 256 * 1024 * 1024;

/// Rotated generations of `attacks.json` retained (`.1` … `.4`).
const LOG_GENERATIONS: usize = 4;

/// Cap on a single session recording.
///
/// Every echoed keystroke is written as its own `[t,"o","x"]` line, so one
/// attacker byte costs ~35 on disk. The gateway caps a single command line,
/// but nothing caps how many lines a session sends — this does.
const MAX_CAST_BYTES: u64 = 32 * 1024 * 1024;

/// Mode for files holding harvested credentials and full session transcripts.
/// These were previously created at the process umask (0644 — world-readable).
const SENSITIVE_MODE: u32 = 0o600;

/// Render attacker-controlled text safe to write to an operator's terminal.
///
/// Usernames and passwords arrive as arbitrary SSH protocol strings — unlike
/// interactive shell input they are never filtered to printable ASCII — and
/// `print_event` writes them straight to stderr wrapped in ANSI colour codes.
/// Raw control bytes there let an attacker clear the operator's screen, rewrite
/// the window title, drive an OSC 52 clipboard write, or reposition the cursor
/// to overwrite earlier log lines and forge or erase evidence of their own
/// session (CWE-150). The operator's console is a trusted surface being fed
/// untrusted bytes, and an attacker who knows a honeypot is watched can target
/// the watcher. The same text also lands in `attacks.json`, so anything left
/// unescaped here re-fires on every later `cat` of that file.
fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c == '\\' {
            out.push_str("\\\\");
        } else if c.is_control() {
            // Unicode `Cc` covers both C0 (0x00-0x1f, DEL) and C1 (0x80-0x9f).
            let mut buf = [0u8; 4];
            for b in c.encode_utf8(&mut buf).as_bytes() {
                let _ = write!(out, "\\x{b:02x}");
            }
        } else {
            out.push(c);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Event Sender (cloneable handle)
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct EventSender(pub mpsc::Sender<TelemetryEvent>);

impl EventSender {
    pub async fn send(&self, event: TelemetryEvent) {
        if self.0.send(event).await.is_err() {
            warn!("collector channel closed -- dropping event");
        }
    }
}

// ---------------------------------------------------------------------------
// Event Collector
// ---------------------------------------------------------------------------

pub struct EventCollector {
    receiver: mpsc::Receiver<TelemetryEvent>,
    log_path: PathBuf,
}

impl EventCollector {
    pub fn new(
        log_path: impl AsRef<Path>,
        sessions_dir: impl AsRef<Path>,
        channel_capacity: usize,
    ) -> (Self, EventSender) {
        let (tx, rx) = mpsc::channel(channel_capacity);
        // sessions_dir accepted for API compat; recorders owned by SessionHandler.
        let _ = sessions_dir;
        let collector = Self {
            receiver: rx,
            log_path: log_path.as_ref().to_path_buf(),
        };
        (collector, EventSender(tx))
    }

    pub async fn run(mut self) -> AegisResult<()> {
        if let Some(parent) = self.log_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let (mut writer, mut written) = open_log(&self.log_path).await?;

        info!("Event collector started -> {}", self.log_path.display());

        while let Some(event) = self.receiver.recv().await {
            Self::print_event(&event);
            match serde_json::to_string(&event) {
                Ok(line) => {
                    if let Err(e) = writer.write_all(line.as_bytes()).await {
                        error!("Failed to write event: {e}");
                    }
                    if let Err(e) = writer.write_all(b"\n").await {
                        error!("Failed to write newline: {e}");
                    }
                    let _ = writer.flush().await;
                    written += line.len() as u64 + 1;

                    if written >= MAX_LOG_BYTES {
                        // Flush and swap before the next write rather than
                        // after, so the rotated file is always complete.
                        let _ = writer.flush().await;
                        drop(writer);
                        if let Err(e) = rotate_log(&self.log_path).await {
                            error!("Log rotation failed: {e}");
                        }
                        let (w, n) = open_log(&self.log_path).await?;
                        writer = w;
                        written = n;
                    }
                }
                Err(e) => error!("Failed to serialize event: {e}"),
            }
        }

        writer.flush().await?;
        info!("Event collector shut down cleanly.");
        Ok(())
    }

    fn print_event(event: &TelemetryEvent) {
        match event {
            TelemetryEvent::CredentialHarvest(e) => {
                let pw = e.password.as_deref().unwrap_or("<none>");
                eprintln!(
                    "\x1b[93m[!] CRED: {} | {}:{}\x1b[0m",
                    e.ip,
                    sanitize(&e.username),
                    sanitize(pw)
                );
            }
            TelemetryEvent::CommandRun(e) => {
                eprintln!(
                    "\x1b[96m[CMD] [{}|{}]: {}\x1b[0m",
                    e.ip,
                    e.session_id,
                    sanitize(&e.command)
                );
            }
            TelemetryEvent::PayloadCaptured(e) => {
                // `sha256` is hex from a fixed-width digest, but slicing it
                // blind would panic on any malformed value; take defensively.
                let short: String = e.sha256.chars().take(16).collect();
                eprintln!(
                    "\x1b[91m[PAYLOAD] {} -> {} ({} bytes) -> {}\x1b[0m",
                    e.ip, short, e.size_bytes, sanitize(&e.quarantine_path)
                );
            }
            TelemetryEvent::SessionStart(e) => {
                eprintln!("\x1b[92m[SESSION START] {} -> {}\x1b[0m", e.ip, e.session_id);
            }
            TelemetryEvent::SessionEnd(e) => {
                eprintln!("\x1b[90m[SESSION END] {} ({:.1}s)\x1b[0m", e.session_id, e.duration_secs);
            }
            TelemetryEvent::SyscallExecve(e) => {
                eprintln!(
                    "\x1b[35m[EXECVE] pid={} {} {}\x1b[0m",
                    e.pid,
                    sanitize(&e.filename),
                    sanitize(&e.argv.join(" "))
                );
            }
            TelemetryEvent::SyscallConnect(e) => {
                eprintln!("\x1b[35m[CONNECT] pid={} -> {}:{}\x1b[0m", e.pid, e.dest_ip, e.dest_port);
            }
            TelemetryEvent::SyscallMemfdCreate(e) => {
                eprintln!(
                    "\x1b[31m[MEMFD] pid={} name='{}' -- fileless ELF!\x1b[0m",
                    e.pid,
                    sanitize(&e.name)
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Log file handling
// ---------------------------------------------------------------------------

/// Open `attacks.json` for append at mode 0600, returning the writer and the
/// file's current size (so rotation accounting survives a restart).
///
/// The mode matters: this file holds every harvested username and password,
/// and was previously created at the process umask — 0644, readable by any
/// local user.
async fn open_log(path: &Path) -> AegisResult<(BufWriter<File>, u64)> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(SENSITIVE_MODE)
        .open(path)
        .await?;
    // `.mode()` only applies at creation, so fix up an existing file too.
    let _ = tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(SENSITIVE_MODE)).await;
    let size = file.metadata().await.map_or(0, |m| m.len());
    Ok((BufWriter::new(file), size))
}

/// Shift `attacks.json` -> `.1` -> `.2` … dropping the oldest generation.
async fn rotate_log(path: &Path) -> AegisResult<()> {
    let gen_path = |n: usize| -> PathBuf {
        let mut p = path.as_os_str().to_owned();
        p.push(format!(".{n}"));
        PathBuf::from(p)
    };

    // Oldest first, so nothing is overwritten before it has been shifted.
    let _ = tokio::fs::remove_file(gen_path(LOG_GENERATIONS)).await;
    for n in (1..LOG_GENERATIONS).rev() {
        let from = gen_path(n);
        if from.exists() {
            let _ = tokio::fs::rename(&from, &gen_path(n + 1)).await;
        }
    }
    tokio::fs::rename(path, gen_path(1)).await?;
    info!("Rotated {} at {MAX_LOG_BYTES} bytes", path.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// Session Recorder (Asciinema v2 .cast)
// ---------------------------------------------------------------------------

pub struct SessionRecorder {
    session_id: SessionId,
    writer: BufWriter<File>,
    start_ts: std::time::Instant,
    /// Bytes written so far, against `MAX_CAST_BYTES`.
    written: u64,
    /// Set once the cap is hit, so the truncation marker is written exactly
    /// once and every later record is a cheap no-op.
    truncated: bool,
}

impl SessionRecorder {
    pub async fn open(path: PathBuf, session_id: SessionId) -> AegisResult<Self> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        // 0600: a `.cast` is a full transcript of an attacker session and was
        // previously created world-readable at the process umask.
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(SENSITIVE_MODE)
            .open(&path)
            .await?;
        let _ =
            tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(SENSITIVE_MODE))
                .await;
        let mut writer = BufWriter::new(file);

        let unix_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let header = serde_json::json!({
            "version": 2,
            "width": 220,
            "height": 50,
            "timestamp": unix_ts,
            "title": format!("aegis-honeypot session {}", session_id),
            "env": { "SHELL": "/bin/bash", "TERM": "xterm-256color" }
        });
        let mut header_str = header.to_string();
        header_str.push('\n');
        writer.write_all(header_str.as_bytes()).await?;
        writer.flush().await?;

        info!("Session recorder opened -> {}", path.display());
        Ok(Self {
            session_id,
            writer,
            start_ts: std::time::Instant::now(),
            written: header_str.len() as u64,
            truncated: false,
        })
    }

    /// Write one `.cast` record, enforcing the per-session size cap.
    ///
    /// Recording stops at the cap rather than the process running out of disk:
    /// an attacker controls how much they type, and every echoed byte costs
    /// ~35 on disk, so an uncapped recording is a disk-exhaustion primitive
    /// that escalates (a full disk makes new session recordings un-openable,
    /// which the gateway treats as a reason to refuse connections).
    async fn write_record(&mut self, kind: &str, data: &str) -> AegisResult<()> {
        if self.truncated {
            return Ok(());
        }
        let mut s = serde_json::json!([self.elapsed(), kind, data]).to_string();
        s.push('\n');

        if self.written + s.len() as u64 > MAX_CAST_BYTES {
            self.truncated = true;
            let marker = serde_json::json!([
                self.elapsed(),
                "o",
                format!("\r\n[aegis: recording truncated at {MAX_CAST_BYTES} bytes]\r\n")
            ])
            .to_string();
            self.writer.write_all(marker.as_bytes()).await?;
            self.writer.write_all(b"\n").await?;
            self.writer.flush().await?;
            warn!(
                "Session {} hit the {MAX_CAST_BYTES}-byte recording cap — further output not recorded",
                self.session_id
            );
            return Ok(());
        }

        self.writer.write_all(s.as_bytes()).await?;
        self.written += s.len() as u64;
        Ok(())
    }

    fn elapsed(&self) -> f64 {
        let d = self.start_ts.elapsed();
        d.as_secs() as f64 + d.subsec_micros() as f64 / 1_000_000.0
    }

    pub async fn record_output(&mut self, data: &str) -> AegisResult<()> {
        self.write_record("o", data).await
    }

    pub async fn record_input(&mut self, data: &str) -> AegisResult<()> {
        self.write_record("i", data).await
    }

    /// `tokio::io::BufWriter` — unlike `std`'s — does not flush on drop, so
    /// callers must flush explicitly for a session to be durable before it
    /// reaches a clean `close()`. The gateway calls this once per incoming
    /// network read rather than per character/write: flushing on every
    /// `record_output`/`record_input` call turned buffered I/O into a
    /// syscall per keystroke, which is real overhead under many concurrent
    /// sessions or bulk/automated attacker traffic. Flushing once per read
    /// bounds worst-case data loss (on a kill mid-read) to at most one
    /// network packet's worth of typing, instead of losing nothing — a
    /// deliberate, small trade of durability granularity for throughput.
    pub async fn flush(&mut self) -> AegisResult<()> {
        self.writer.flush().await?;
        Ok(())
    }

    pub async fn close(&mut self) -> AegisResult<()> {
        self.writer.flush().await?;
        info!("Session recorder flushed -> {}", self.session_id);
        Ok(())
    }
}
