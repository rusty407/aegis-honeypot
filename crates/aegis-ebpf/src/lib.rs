//! `aegis-ebpf` — Userspace eBPF loader and RingBuffer consumer.
//!
//! Loads compiled eBPF programs into the kernel, attaches tracepoints for:
//!   - `syscalls/sys_enter_execve`    — binary execution tracking
//!   - `syscalls/sys_enter_connect`   — outbound C2 socket interception
//!   - `syscalls/sys_enter_memfd_create` — fileless ELF detection
//!
//! Streams `KernelEvent`s from the RingBuf to `aegis-collector` via mpsc.
//!
//! NOTE: Loading eBPF programs requires `CAP_BPF` (Linux 5.8+) or `CAP_SYS_ADMIN`.
//! The binary should be run with the appropriate capability or as root.

use aegis_common::{
    AegisError, AegisResult, KernelEvent, KernelEventType, SessionId, SyscallConnectEvent,
    SyscallExecveEvent, SyscallMemfdCreateEvent, TelemetryEvent,
};
use aya::maps::RingBuf;
use aya::programs::TracePoint;
use aya::Ebpf;
use chrono::Utc;
use std::net::{IpAddr, Ipv4Addr};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

// Macro that expands to an embedded byte array or empty slice if file missing.
// Must be defined before EBPF_BYTES static uses it.
macro_rules! include_bytes_or_empty {
    () => {{
        // In CI / first build before eBPF programs are compiled, return empty.
        // Replace with:
        //   include_bytes_aligned!(concat!(env!("OUT_DIR"), "/aegis_probes.o"))
        &[]
    }};
}

/// Compiled eBPF object bytes embedded at build time.
/// Replace with `include_bytes_aligned!` pointing to the compiled `.o` file
/// once the eBPF kernel-side programs are built with `cargo xtask build-ebpf`.
///
/// For development without the kernel programs compiled, the loader degrades
/// gracefully and returns without attaching any probes.
static EBPF_BYTES: &[u8] = include_bytes_or_empty!();

// ---------------------------------------------------------------------------
// Probe Loader
// ---------------------------------------------------------------------------

pub struct EbpfProbeSet {
    bpf: Ebpf,
    event_tx: mpsc::Sender<TelemetryEvent>,
    /// Mapping from kernel namespace PID → session_id (populated by gateway)
    session_map: std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<u32, SessionId>>>,
}

impl EbpfProbeSet {
    /// Load and attach all tracepoint probes.
    ///
    /// Returns `Ok(None)` if no eBPF bytecode is available (development mode).
    pub async fn load(
        event_tx: mpsc::Sender<TelemetryEvent>,
        session_map: std::sync::Arc<
            tokio::sync::Mutex<std::collections::HashMap<u32, SessionId>>,
        >,
    ) -> AegisResult<Option<Self>> {
        if EBPF_BYTES.is_empty() {
            warn!("eBPF bytecode not compiled — kernel telemetry disabled.");
            warn!("Run `cargo xtask build-ebpf` to compile kernel probes.");
            return Ok(None);
        }

        let mut bpf = Ebpf::load(EBPF_BYTES)
            .map_err(|e| AegisError::Ebpf(format!("load eBPF object: {e}")))?;

        // Attach execve tracepoint
        attach_tracepoint(&mut bpf, "handle_execve", "syscalls", "sys_enter_execve")?;
        // Attach connect tracepoint
        attach_tracepoint(&mut bpf, "handle_connect", "syscalls", "sys_enter_connect")?;
        // Attach memfd_create tracepoint
        attach_tracepoint(
            &mut bpf,
            "handle_memfd_create",
            "syscalls",
            "sys_enter_memfd_create",
        )?;

        info!("eBPF probes attached: execve, connect, memfd_create");

        Ok(Some(Self {
            bpf,
            event_tx,
            session_map,
        }))
    }

    /// Consume the RingBuf and stream events to the collector channel.
    /// Call this in a dedicated tokio task: `tokio::spawn(probes.run())`.
    pub async fn run(mut self) -> AegisResult<()> {
        // Extract shared handles before mutably borrowing self.bpf for the ring buffer.
        let event_tx = self.event_tx.clone();
        let session_map = self.session_map.clone();

        let mut ring: RingBuf<_> = self
            .bpf
            .map_mut("KERNEL_EVENTS")
            .ok_or_else(|| AegisError::Ebpf("map 'KERNEL_EVENTS' not found in eBPF object".into()))?
            .try_into()
            .map_err(|e| AegisError::Ebpf(format!("RingBuf cast: {e}")))?;

        info!("eBPF RingBuf consumer running…");

        loop {
            // Poll the ring buffer for new events
            while let Some(item) = ring.next() {
                let bytes: &[u8] = item.as_ref();
                if bytes.len() < std::mem::size_of::<KernelEvent>() {
                    warn!("Short kernel event ({} bytes)", bytes.len());
                    continue;
                }

                // SAFETY: kernel-side program writes exactly `KernelEvent` sized structs
                let ke: KernelEvent = unsafe {
                    std::ptr::read_unaligned(bytes.as_ptr() as *const KernelEvent)
                };

                if let Err(e) = dispatch_kernel_event(&ke, &event_tx, &session_map).await {
                    error!("dispatch_kernel_event: {e}");
                }
            }

            // Yield to other tasks between polls
            tokio::task::yield_now().await;
        }
    }
}

async fn dispatch_kernel_event(
    ke: &KernelEvent,
    event_tx: &mpsc::Sender<TelemetryEvent>,
    session_map: &std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<u32, SessionId>>>,
) -> AegisResult<()> {
    let map = session_map.lock().await;
    let session_id = map
        .get(&ke.ns_pid)
        .cloned()
        .unwrap_or_else(|| SessionId("unknown".into()));
    drop(map);

    let event_type = ke.event_type;
    let now = Utc::now();

    let telemetry = match event_type {
        t if t == KernelEventType::Execve as u32 => {
            let argv: Vec<String> = ke
                .argv_str()
                .split(' ')
                .map(|s| s.to_owned())
                .filter(|s| !s.is_empty())
                .collect();

            TelemetryEvent::SyscallExecve(SyscallExecveEvent {
                timestamp: now,
                session_id,
                ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                pid: ke.pid,
                filename: ke.filename_str().to_owned(),
                argv,
            })
        }
        t if t == KernelEventType::Connect as u32 => {
            TelemetryEvent::SyscallConnect(SyscallConnectEvent {
                timestamp: now,
                session_id,
                ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                pid: ke.pid,
                dest_ip: IpAddr::V4(ke.dest_ip_addr()),
                dest_port: u16::from_be(ke.dest_port),
            })
        }
        t if t == KernelEventType::MemfdCreate as u32 => {
            TelemetryEvent::SyscallMemfdCreate(SyscallMemfdCreateEvent {
                timestamp: now,
                session_id,
                ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                pid: ke.pid,
                name: ke.filename_str().to_owned(),
            })
        }
        _ => {
            warn!("Unknown kernel event type: {event_type}");
            return Ok(());
        }
    };

    event_tx
        .send(telemetry)
        .await
        .map_err(|_| AegisError::ChannelClosed)?;

    Ok(())
}


fn attach_tracepoint(
    bpf: &mut Ebpf,
    prog_name: &str,
    category: &str,
    name: &str,
) -> AegisResult<()> {
    let prog: &mut TracePoint = bpf
        .program_mut(prog_name)
        .ok_or_else(|| AegisError::Ebpf(format!("program '{prog_name}' not found")))?
        .try_into()
        .map_err(|e| AegisError::Ebpf(format!("cast '{prog_name}': {e}")))?;

    prog.load()
        .map_err(|e| AegisError::Ebpf(format!("load '{prog_name}': {e}")))?;

    prog.attach(category, name)
        .map_err(|e| AegisError::Ebpf(format!("attach '{prog_name}' to {category}/{name}: {e}")))?;

    info!("Attached tracepoint: {category}/{name} → {prog_name}");
    Ok(())
}
