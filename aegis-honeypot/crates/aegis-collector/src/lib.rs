//! aegis-collector -- Event pipeline: receives TelemetryEvents from all crates,
//! serializes them as JSON lines to attacks.json, and provides SessionRecorder
//! for Asciinema v2 cast files.

use aegis_common::{AegisResult, SessionId, TelemetryEvent};
use std::path::{Path, PathBuf};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

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

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .await?;
        let mut writer = BufWriter::new(file);

        info!("Event collector started -> {}", self.log_path.display());

        while let Some(event) = self.receiver.recv().await {
            self.print_event(&event);
            match serde_json::to_string(&event) {
                Ok(line) => {
                    if let Err(e) = writer.write_all(line.as_bytes()).await {
                        error!("Failed to write event: {e}");
                    }
                    if let Err(e) = writer.write_all(b"\n").await {
                        error!("Failed to write newline: {e}");
                    }
                    let _ = writer.flush().await;
                }
                Err(e) => error!("Failed to serialize event: {e}"),
            }
        }

        writer.flush().await?;
        info!("Event collector shut down cleanly.");
        Ok(())
    }

    fn print_event(&self, event: &TelemetryEvent) {
        match event {
            TelemetryEvent::CredentialHarvest(e) => {
                let pw = e.password.as_deref().unwrap_or("<none>");
                eprintln!("\x1b[93m[!] CRED: {} | {}:{}\x1b[0m", e.ip, e.username, pw);
            }
            TelemetryEvent::CommandRun(e) => {
                eprintln!("\x1b[96m[CMD] [{}|{}]: {}\x1b[0m", e.ip, e.session_id, e.command);
            }
            TelemetryEvent::PayloadCaptured(e) => {
                eprintln!("\x1b[91m[PAYLOAD] {} -> {} ({} bytes) -> {}\x1b[0m",
                    e.ip, &e.sha256[..16], e.size_bytes, e.quarantine_path);
            }
            TelemetryEvent::SessionStart(e) => {
                eprintln!("\x1b[92m[SESSION START] {} -> {}\x1b[0m", e.ip, e.session_id);
            }
            TelemetryEvent::SessionEnd(e) => {
                eprintln!("\x1b[90m[SESSION END] {} ({:.1}s)\x1b[0m", e.session_id, e.duration_secs);
            }
            TelemetryEvent::SyscallExecve(e) => {
                eprintln!("\x1b[35m[EXECVE] pid={} {} {}\x1b[0m", e.pid, e.filename, e.argv.join(" "));
            }
            TelemetryEvent::SyscallConnect(e) => {
                eprintln!("\x1b[35m[CONNECT] pid={} -> {}:{}\x1b[0m", e.pid, e.dest_ip, e.dest_port);
            }
            TelemetryEvent::SyscallMemfdCreate(e) => {
                eprintln!("\x1b[31m[MEMFD] pid={} name='{}' -- fileless ELF!\x1b[0m", e.pid, e.name);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Session Recorder (Asciinema v2 .cast)
// ---------------------------------------------------------------------------

pub struct SessionRecorder {
    session_id: SessionId,
    writer: BufWriter<File>,
    start_ts: std::time::Instant,
}

impl SessionRecorder {
    pub async fn open(path: PathBuf, session_id: SessionId) -> AegisResult<Self> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .await?;
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

        info!("Session recorder opened -> {}", path.display());
        Ok(Self { session_id, writer, start_ts: std::time::Instant::now() })
    }

    fn elapsed(&self) -> f64 {
        let d = self.start_ts.elapsed();
        d.as_secs() as f64 + d.subsec_micros() as f64 / 1_000_000.0
    }

    pub async fn record_output(&mut self, data: &str) -> AegisResult<()> {
        let mut s = serde_json::json!([self.elapsed(), "o", data]).to_string();
        s.push('\n');
        self.writer.write_all(s.as_bytes()).await?;
        Ok(())
    }

    pub async fn record_input(&mut self, data: &str) -> AegisResult<()> {
        let mut s = serde_json::json!([self.elapsed(), "i", data]).to_string();
        s.push('\n');
        self.writer.write_all(s.as_bytes()).await?;
        Ok(())
    }

    pub async fn close(&mut self) -> AegisResult<()> {
        self.writer.flush().await?;
        info!("Session recorder flushed -> {}", self.session_id);
        Ok(())
    }
}
