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
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Json, Response};
use axum::routing::get;
use axum::Router;
use futures_util::StreamExt;
use serde::Deserialize;
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use store::Store;
use subtle::ConstantTimeEq;
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
    /// Bearer token every request must present (unless `require_auth` is
    /// off). `Arc` so cloning `AppState` per-request doesn't reallocate it.
    token: Arc<String>,
    require_auth: bool,
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

    let token = if config.dashboard.require_auth {
        load_or_create_token(&config.dashboard.token_path).await?
    } else {
        warn!("require_auth is disabled — the dashboard is wide open to anyone who can reach it. Local dev only.");
        String::new()
    };

    let state = AppState {
        store: Arc::new(RwLock::new(Store::default())),
        live: live_tx,
        sessions_dir: PathBuf::from(&config.forensics.sessions_dir),
        token: Arc::new(token),
        require_auth: config.dashboard.require_auth,
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
        // `.layer` (not `.route_layer`) so every path — including a 404
        // fallback — goes through auth; nothing is reachable unauthenticated.
        .layer(middleware::from_fn_with_state(state.clone(), require_auth))
        .with_state(state.clone());

    let bind_addr = format!("{}:{}", config.dashboard.bind_addr, config.dashboard.port);
    info!("aegis-dashboard listening on http://{bind_addr}");
    if config.dashboard.bind_addr != "127.0.0.1" && config.dashboard.bind_addr != "localhost" {
        warn!(
            "Dashboard is bound to {} — {}",
            config.dashboard.bind_addr,
            if state.require_auth {
                "bearer-token auth is on, but confirm you actually want this off loopback."
            } else {
                "and require_auth is OFF. Anyone who can reach this network sees everything."
            }
        );
    }

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Load the dashboard's bearer token from `path`, generating and persisting a
/// new one (32 random bytes, hex-encoded) on first run — same pattern as the
/// gateway's `load_or_create_host_key`. The token is logged once at startup
/// since there's no other way for an operator to retrieve it short of
/// reading the file directly; `path` is also mentioned so it's easy to find
/// again later (e.g. to rotate it — just delete the file and restart).
async fn load_or_create_token(path: &str) -> anyhow::Result<String> {
    let path_buf = std::path::Path::new(path);
    match tokio::fs::read_to_string(path_buf).await {
        Ok(token) => {
            info!("Loaded dashboard bearer token from {path}");
            Ok(token.trim().to_string())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let token = generate_token();
            if let Some(parent) = path_buf.parent() {
                if !parent.as_os_str().is_empty() {
                    tokio::fs::create_dir_all(parent).await?;
                }
            }
            tokio::fs::write(path_buf, &token).await?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                tokio::fs::set_permissions(path_buf, std::fs::Permissions::from_mode(0o600)).await?;
            }
            warn!("No dashboard token found at {path} — generated a new one (saved there, mode 0600).");
            warn!("Dashboard bearer token: {token}");
            warn!("Pass it as `Authorization: Bearer <token>`, or open the dashboard once as `?token=<token>` (the page remembers it after that). Delete {path} and restart to rotate it.");
            Ok(token)
        }
        Err(e) => Err(anyhow::anyhow!("failed to read dashboard token at {path}: {e}")),
    }
}

/// 32 random bytes (256 bits) as lowercase hex, built from two v4 UUIDs
/// rather than pulling in a `rand` dependency just for this — `uuid` and
/// `hex` are already in the tree, and `Uuid::new_v4` draws from the OS CSPRNG.
fn generate_token() -> String {
    let mut bytes = Vec::with_capacity(32);
    bytes.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
    bytes.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
    hex::encode(bytes)
}

/// Bearer-token auth, checked via `Authorization: Bearer <token>` or a
/// `?token=` query param (needed for `/api/stream`, since browsers'
/// `EventSource` can't set custom headers). Applied to every route via
/// `.layer(...)`, not per-route, so nothing is reachable unauthenticated —
/// including the page itself, which is why the frontend's very first load
/// has to come in via `?token=` before it can persist the token client-side.
async fn require_auth(State(state): State<AppState>, request: Request, next: Next) -> Result<Response, StatusCode> {
    if !state.require_auth {
        return Ok(next.run(request).await);
    }

    let header_token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let provided = header_token.map(str::to_owned).or_else(|| query_token(request.uri()));

    match provided {
        Some(token) if constant_time_eq(&token, &state.token) => Ok(next.run(request).await),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

/// Our tokens are plain lowercase hex — no `=`, `&`, or `%` in them — so a
/// bare split is enough here without pulling in a query-string/URL crate
/// just for this one key.
fn query_token(uri: &axum::http::Uri) -> Option<String> {
    uri.query()?.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == "token").then(|| v.to_string())
    })
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    a.len() == b.len() && bool::from(a.ct_eq(b))
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

#[cfg(test)]
mod auth_tests {
    use super::*;

    #[test]
    fn generate_token_is_64_hex_chars_and_actually_random() {
        let a = generate_token();
        let b = generate_token();
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b, "two generated tokens collided — RNG is broken");
    }

    #[test]
    fn constant_time_eq_matches_and_rejects() {
        assert!(constant_time_eq("abc123", "abc123"));
        assert!(!constant_time_eq("abc123", "abc124"));
        assert!(!constant_time_eq("abc123", "abc12"), "different lengths must never match");
        assert!(!constant_time_eq("", "abc123"));
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn query_token_extracts_from_query_string() {
        let uri: axum::http::Uri = "/api/stream?token=deadbeef&limit=5".parse().unwrap();
        assert_eq!(query_token(&uri), Some("deadbeef".to_string()));

        let uri: axum::http::Uri = "/api/stream?limit=5".parse().unwrap();
        assert_eq!(query_token(&uri), None);

        let uri: axum::http::Uri = "/api/stream".parse().unwrap();
        assert_eq!(query_token(&uri), None);

        // token as the first param, with others after
        let uri: axum::http::Uri = "/api/stream?token=abc&type=COMMAND_RUN".parse().unwrap();
        assert_eq!(query_token(&uri), Some("abc".to_string()));
    }
}
