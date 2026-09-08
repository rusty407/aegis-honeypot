//! `aegis-dashboard` — a small, read-only web UI over the honeypot's telemetry.
//!
//! This is deliberately a *separate* binary from `aegis-gateway`: the gateway
//! is the internet-facing, attacker-touching process and should expose as
//! little surface as possible, while the dashboard only ever reads files the
//! gateway already writes (`attacks_log`) and never touches the sandbox,
//! network sockets to attackers, or quarantined payloads' contents. Run it on
//! a different host/network namespace than the honeypot if you want the same
//! separation in production.
//!
//! It tails `attacks.json` as newline-delimited [`TelemetryEvent`]s, keeps an
//! in-memory rollup (`store::Store`), and serves that rollup plus a live feed
//! over a tiny JSON API consumed by the bundled single-page UI.

mod store;

use aegis_common::{AegisConfig, TelemetryEvent};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Json};
use axum::routing::get;
use axum::Router;
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use store::Store;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::RwLock;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

type SharedStore = Arc<RwLock<Store>>;

const INDEX_HTML: &str = include_str!("../static/index.html");
const POLL_INTERVAL: Duration = Duration::from_millis(1500);

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
    let store: SharedStore = Arc::new(RwLock::new(Store::default()));

    info!("Tailing {}", attacks_log.display());
    tokio::spawn(tail_attacks_log(attacks_log, store.clone()));

    let app = Router::new()
        .route("/", get(index))
        .route("/api/summary", get(summary))
        .route("/api/events", get(events))
        .with_state(store);

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

/// Poll `attacks.json` for newly appended lines and fold each parsed event
/// into `store`. Tracks a byte offset rather than re-reading the whole file
/// each tick, and only advances past complete (`\n`-terminated) lines so a
/// line the gateway is still mid-write on is picked up on the next poll
/// instead of being parsed truncated. Tolerant of the file not existing yet
/// (fresh deployment) and of it shrinking (rotation/truncation resets to 0).
async fn tail_attacks_log(path: PathBuf, store: SharedStore) {
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
                            Ok(event) => store.ingest(event),
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

async fn summary(State(store): State<SharedStore>) -> impl IntoResponse {
    Json(store.read().await.summary())
}

#[derive(Deserialize)]
struct EventsQuery {
    limit: Option<usize>,
    #[serde(rename = "type")]
    kind: Option<String>,
}

const MAX_EVENTS_LIMIT: usize = 500;

async fn events(State(store): State<SharedStore>, Query(q): Query<EventsQuery>) -> impl IntoResponse {
    let limit = q.limit.unwrap_or(50).min(MAX_EVENTS_LIMIT);
    let events: Vec<TelemetryEvent> = {
        let store = store.read().await;
        store
            .recent_events(limit, q.kind.as_deref())
            .into_iter()
            .cloned()
            .collect()
    };
    (StatusCode::OK, Json(events))
}
