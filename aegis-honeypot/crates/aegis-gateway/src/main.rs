//! `aegis-gateway` binary entrypoint.
//!
//! Starts the tokio runtime, provisions the golden rootfs, initializes all subsystems
//! (collector, forensics engine, eBPF probes), and begins accepting SSH connections.

mod handler;
mod shell;
mod vfs;

use aegis_common::AegisConfig;
use aegis_collector::EventCollector;
use aegis_forensics::ForensicsEngine;
use handler::{AegisServer, build_russh_config};
use russh::server::Server;
use russh_keys::key::KeyPair;
use std::sync::Arc;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

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

    // Host key — load or generate
    let keypair = if let Some(path) = &config.gateway.host_key_path {
        let pem = tokio::fs::read_to_string(path).await?;
        russh_keys::decode_secret_key(&pem, None)?
    } else {
        info!("Generating ephemeral Ed25519 host key (set host_key_path to persist)");
        KeyPair::generate_ed25519()
    };

    let russh_config = Arc::new(build_russh_config(keypair));

    // Start server
    let bind_addr = format!("{}:{}", config.gateway.bind_addr, config.gateway.port);
    info!("Listening on {bind_addr}");

    let mut server = AegisServer {
        config,
        event_tx,
        forensics,
    };
    server
        .run_on_address(russh_config, &bind_addr)
        .await
        .map_err(|e| anyhow::anyhow!("SSH server error: {e}"))?;

    Ok(())
}
