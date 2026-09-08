//! `aegis-dashboard` — a small, read-only web UI over the honeypot's telemetry.
//!
//! This is deliberately a *separate* binary from `aegis-gateway`: the gateway
//! is the internet-facing, attacker-touching process and should expose as
//! little surface as possible, while the dashboard only ever reads files the
//! gateway already writes (`attacks_log`, `sessions_dir`) and never touches
//! the sandbox, network sockets to attackers, or quarantined payloads'
//! contents. Run it on a different host/network namespace than the honeypot
//! if you want the same separation in production.
//!
//! It tails `attacks.json` as newline-delimited [`TelemetryEvent`]s, keeps an
//! in-memory rollup (`store::Store`), and serves that rollup, a live SSE
//! event stream, and per-session drill-down (timeline + `.cast` replay) over
//! a small JSON API consumed by the bundled single-page UI.

mod store;

use aegis_common::{AegisConfig, TelemetryEvent};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Json};
use axum::routing::get;
use axum::Router;
use futures_util::StreamExt;
use serde::Deserialize;
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use store::Store;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::{broadcast, RwLock};
use tokio_stream::wrappers::BroadcastStream;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

const INDEX_HTML: &str = include_str!("../static/index.html");
const POLL_INTERVAL: Duration = Duration::from_millis(1500);
/// Backlog for the live-event broadcast channel. A slow SSE client that falls
/// this far behind just misses the oldest events (BroadcastStream reports a
/// `Lagged` error, which the stream handler silently skips past) rather than
/// blocking the tailer — the stream is a live feed, not a delivery guarantee.
const BROADCAST_CAPACITY: usize = 1024;

#[derive(Clone)]
struct AppState {
    store: Arc<RwLock<Store>>,
    /// Fan-out of every ingested event to connected `/api/stream` clients.
    live: broadcast::Sender<TelemetryEvent>,
    sessions_dir: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let config = std::env::args()
        .find(|a| a.ends_with(".toml"))
        .and_then(|p| AegisConfig::from_file(&p).ok())
        .unwrap_or_default();

    let attacks_log = PathBuf::from(&config.forensics.attacks_log);
    let (live_tx, _) = broadcast::channel(BROADCAST_CAPACITY);
    let state = AppState {
        store: Arc::new(RwLock::new(Store::default())),
        live: live_tx,
        sessions_dir: PathBuf::from(&config.forensics.sessions_dir),
    };

    info!("Tailing {}", attacks_log.display());
    tokio::spawn(tail_attacks_log(attacks_log, state.store.clone(), state.live.clone()));

    let app = Router::new()
        .route("/", get(index))
        .route("/api/summary", get(summary))
        .route("/api/events", get(events))
        .route("/api/stream", get(stream))
        .route("/api/session/:id", get(session_timeline))
        .route("/api/session/:id/cast", get(session_cast))
        .with_state(state.clone());

    let bind_addr = format!("{}:{}", config.dashboard.bind_addr, config.dashboard.port);
    info!("aegis-dashboard listening on http://{bind_addr}");
    if config.dashboard.bind_addr != "127.0.0.1" && config.dashboard.bind_addr != "localhost" {
        warn!(
            "Dashboard is bound to {} — it has no authentication, so only expose it on a trusted network.",
            config.dashboard.bind_addr
        );
    }

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Poll `attacks.json` for newly appended lines, fold each parsed event into
/// `store`, and fan it out to live SSE subscribers. Tracks a byte offset
/// rather than re-reading the whole file each tick, and only advances past
/// complete (`\n`-terminated) lines so a line the gateway is still mid-write
/// on is picked up on the next poll instead of being parsed truncated.
/// Tolerant of the file not existing yet (fresh deployment) and of it
/// shrinking (rotation/truncation resets to 0).
async fn tail_attacks_log(path: PathBuf, store: Arc<RwLock<Store>>, live: broadcast::Sender<TelemetryEvent>) {
    let mut offset: u64 = 0;
    loop {
        match read_new_lines(&path, &mut offset).await {
            Ok(lines) => {
                if !lines.is_empty() {
                    let mut store = store.write().await;
                    for line in lines {
                        if line.trim().is_empty() {
                            continue;
                        }
                        match serde_json::from_str::<TelemetryEvent>(&line) {
                            Ok(event) => {
                                // No receivers connected is the common case, not an error.
                                let _ = live.send(event.clone());
                                store.ingest(event);
                            }
                            Err(e) => warn!("skipping malformed event line: {e}"),
                        }
                    }
                }
            }
            Err(e) => warn!("could not read {}: {e}", path.display()),
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

async fn read_new_lines(path: &PathBuf, offset: &mut u64) -> std::io::Result<Vec<String>> {
    let mut file = match tokio::fs::File::open(path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };

    let len = file.metadata().await?.len();
    if len < *offset {
        // File was truncated or rotated out from under us — start over.
        *offset = 0;
    }
    if len == *offset {
        return Ok(Vec::new());
    }

    file.seek(std::io::SeekFrom::Start(*offset)).await?;
    let mut buf = Vec::with_capacity((len - *offset) as usize);
    file.read_to_end(&mut buf).await?;

    let Some(last_newline) = buf.iter().rposition(|&b| b == b'\n') else {
        // No complete line yet; leave offset untouched and try again next tick.
        return Ok(Vec::new());
    };

    *offset += (last_newline + 1) as u64;
    let text = String::from_utf8_lossy(&buf[..=last_newline]);
    Ok(text.lines().map(str::to_owned).collect())
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn summary(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.store.read().await.summary())
}

#[derive(Deserialize)]
struct EventsQuery {
    limit: Option<usize>,
    #[serde(rename = "type")]
    kind: Option<String>,
    ip: Option<std::net::IpAddr>,
}

const MAX_EVENTS_LIMIT: usize = 500;

async fn events(State(state): State<AppState>, Query(q): Query<EventsQuery>) -> impl IntoResponse {
    let limit = q.limit.unwrap_or(50).min(MAX_EVENTS_LIMIT);
    let events: Vec<TelemetryEvent> = {
        let store = state.store.read().await;
        store
            .recent_events(limit, q.kind.as_deref(), q.ip)
            .into_iter()
            .cloned()
            .collect()
    };
    (StatusCode::OK, Json(events))
}

/// Live event stream: pushes every newly ingested event to the browser the
/// moment the tailer picks it up, instead of the client polling on an
/// interval. Falls back gracefully — a client that never opens this endpoint
/// just doesn't get push updates; nothing else depends on it.
async fn stream(State(state): State<AppState>) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let rx = state.live.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|msg| {
        std::future::ready(match msg {
            Ok(event) => match Event::default().event("telemetry").json_data(&event) {
                Ok(sse_event) => Some(Ok(sse_event)),
                Err(_) => None,
            },
            // Receiver fell behind the broadcast capacity; drop the gap and
            // keep streaming rather than erroring the connection out.
            Err(_lagged) => None,
        })
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// Session id as used in `SessionId::new()`: a 12-character lowercase-hex
/// UUID fragment. Validated before touching the filesystem so a path like
/// `../../etc/passwd` can never reach `sessions_dir.join(id)`.
fn is_valid_session_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_hexdigit())
}

/// Full event timeline for one session (drill-down view), oldest first.
async fn session_timeline(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    if !is_valid_session_id(&id) {
        return (StatusCode::BAD_REQUEST, Json(Vec::<TelemetryEvent>::new()));
    }
    let store = state.store.read().await;
    let events: Vec<TelemetryEvent> = store.session_events(&id).into_iter().cloned().collect();
    (StatusCode::OK, Json(events))
}

/// Raw Asciinema v2 `.cast` content for a session, for the bundled replay
/// player to parse client-side. Plain text, not JSON — it's already
/// newline-delimited JSON internally (the cast format).
async fn session_cast(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    if !is_valid_session_id(&id) {
        return (StatusCode::BAD_REQUEST, String::new());
    }
    let path = state.sessions_dir.join(format!("{id}.cast"));
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => (StatusCode::OK, content),
        Err(_) => (StatusCode::NOT_FOUND, String::new()),
    }
}
