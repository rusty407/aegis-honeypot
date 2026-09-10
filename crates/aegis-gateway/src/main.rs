//! `aegis-gateway` binary entrypoint.
//!
//! Starts the tokio runtime, provisions the golden rootfs, initializes all subsystems
//! (collector, forensics engine, eBPF probes), and begins accepting SSH connections.

mod geoip;
mod handler;
mod shell;
mod vfs;

use aegis_common::AegisConfig;
use aegis_collector::EventCollector;
use aegis_forensics::ForensicsEngine;
use handler::{AegisServer, build_russh_config, IpConnectionGuard};
use russh::server::Server;
use russh_keys::key::KeyPair;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

/// Load a persistent Ed25519 host key from `path`, generating and saving one
/// on first run if it doesn't exist yet. Passing `None` falls back to a
/// throwaway key regenerated every restart — fine for a quick local test,
/// but a bad idea for a real deployment: a host key that changes across
/// reconnects is an easy honeypot fingerprint for a returning attacker.
async fn load_or_create_host_key(path: Option<&str>) -> anyhow::Result<KeyPair> {
    let Some(path) = path else {
        warn!("No host_key_path configured — generating an ephemeral Ed25519 key for this run only");
        return Ok(KeyPair::generate_ed25519());
    };
    let path_buf = std::path::Path::new(path);

    match tokio::fs::read_to_string(path_buf).await {
        Ok(pem) => {
            info!("Loaded persistent SSH host key from {path}");
            Ok(russh_keys::decode_secret_key(&pem, None)?)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            info!("No host key found at {path} — generating and persisting a new Ed25519 key");
            let keypair = KeyPair::generate_ed25519();

            if let Some(parent) = path_buf.parent() {
                if !parent.as_os_str().is_empty() {
                    tokio::fs::create_dir_all(parent).await?;
                }
            }
            let mut pem_bytes = Vec::new();
            russh_keys::encode_pkcs8_pem(&keypair, &mut pem_bytes)?;
            tokio::fs::write(path_buf, &pem_bytes).await?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                tokio::fs::set_permissions(path_buf, std::fs::Permissions::from_mode(0o600)).await?;
            }
            Ok(keypair)
        }
        Err(e) => Err(anyhow::anyhow!("failed to read host key at {path}: {e}")),
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    // Logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,russh=warn,aya=warn")),
        )
        .init();

    // Config — load from file or defaults
    let config = std::env::args()
        .find(|a| a.ends_with(".toml"))
        .and_then(|p| AegisConfig::from_file(&p).ok())
        .unwrap_or_default();
    let config = Arc::new(config);

    info!("aegis-honeypot starting on {}:{}", config.gateway.bind_addr, config.gateway.port);

    // Ensure output directories exist
    for dir in [
        &config.forensics.quarantine_dir,
        &config.forensics.sessions_dir,
        &config.vmm.overlay_base,
    ] {
        tokio::fs::create_dir_all(dir).await?;
    }

    // Provision Golden Rootfs for OverlayFS lowerdir
    if let Err(e) = aegis_vmm::rootfs::ensure_golden_rootfs(&config.vmm.rootfs_path).await {
        warn!("Failed to provision golden rootfs at {}: {e}", config.vmm.rootfs_path);
    }

    // Collector — spawn event pipeline
    let (collector, event_tx) = EventCollector::new(
        &config.forensics.attacks_log,
        &config.forensics.sessions_dir,
        4096,
    );
    tokio::spawn(async move {
        if let Err(e) = collector.run().await {
            error!("Event collector error: {e}");
        }
    });

    // Forensics engine
    let forensics = Arc::new(ForensicsEngine::new(
        &config.forensics.quarantine_dir,
        config.forensics.string_min_len,
        event_tx.0.clone(),
    ));

    // eBPF probes (requires CAP_BPF / root)
    let session_map = std::sync::Arc::new(
        tokio::sync::Mutex::new(
            std::collections::HashMap::<u32, aegis_common::SessionId>::new()
        )
    );

    match aegis_ebpf::EbpfProbeSet::load(event_tx.0.clone(), session_map.clone()).await {
        Ok(Some(probes)) => {
            info!("eBPF probes loaded — kernel telemetry active");
            tokio::spawn(async move {
                if let Err(e) = probes.run().await {
                    error!("eBPF probe error: {e}");
                }
            });
        }
        Ok(None) => {
            info!("eBPF probes not compiled — kernel telemetry disabled (run with --ebpf to enable)");
        }
        Err(e) => {
            error!("eBPF probe load failed (running without kernel telemetry): {e}");
        }
    }

    // GeoIP — optional, never blocks startup either way (see geoip.rs)
    let geoip = Arc::new(
        geoip::GeoIpLookup::load(config.geoip.geoip_db_path.as_deref(), config.geoip.asn_db_path.as_deref()).await,
    );

    // Host key — load or generate & persist
    let keypair = load_or_create_host_key(config.gateway.host_key_path.as_deref()).await?;

    let russh_config = Arc::new(build_russh_config(keypair));

    // Start server
    let bind_addr = format!("{}:{}", config.gateway.bind_addr, config.gateway.port);
    info!("Listening on {bind_addr}");
    info!(
        "Admission control: max {} concurrent sessions, {} per IP, {} connects/min per IP",
        config.gateway.max_sessions, config.gateway.max_sessions_per_ip, config.gateway.max_connects_per_min_per_ip
    );

    let mut server = AegisServer {
        session_semaphore: Arc::new(Semaphore::new(config.gateway.max_sessions.max(1))),
        ip_guard: Arc::new(IpConnectionGuard::new(
            config.gateway.max_sessions_per_ip,
            config.gateway.max_connects_per_min_per_ip,
        )),
        config,
        event_tx,
        forensics,
        geoip,
    };
    server
        .run_on_address(russh_config, &bind_addr)
        .await
        .map_err(|e| anyhow::anyhow!("SSH server error: {e}"))?;

    Ok(())
}
