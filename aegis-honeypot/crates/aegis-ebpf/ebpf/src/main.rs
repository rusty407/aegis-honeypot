//! `aegis-ebpf` kernel-side programs (no_std, bpf target).
//!
//! Three tracepoint programs compiled to BPF bytecode.
//! Each fills a `KernelEvent` struct and submits it to the shared `KERNEL_EVENTS` RingBuf.
//!
//! Build with:
//!   cargo +nightly build -p aegis-ebpf-programs --target bpfel-unknown-none -Z build-std=core

#![no_std]
#![no_main]

use aya_ebpf::macros::{map, tracepoint};
use aya_ebpf::maps::RingBuf;
use aya_ebpf::programs::TracePointContext;
use aya_ebpf::{helpers, EbpfContext};

// Wire-format struct matching `aegis_common::KernelEvent`
#[repr(C)]
struct KernelEvent {
    event_type: u32,
    pid: u32,
    ppid: u32,
    uid: u32,
    ns_pid: u32,
    dest_ip: u32,
    dest_port: u16,
    _pad: u16,
    filename: [u8; 128],
    argv: [u8; 256],
}

const EVENT_EXECVE: u32 = 1;
const EVENT_CONNECT: u32 = 2;
const EVENT_MEMFD: u32 = 3;

// Shared RingBuf map — 4 MB
#[map]
static KERNEL_EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

// ---------------------------------------------------------------------------
// sys_enter_execve — binary execution tracking
// ---------------------------------------------------------------------------
// Tracepoint args layout for sys_enter_execve:
//   +0  u64 syscall_nr
//   +8  const char* filename
//   +16 const char* const* argv
//   +24 const char* const* envp

#[tracepoint]
pub fn handle_execve(ctx: TracePointContext) -> u32 {
    unsafe { try_execve(&ctx).unwrap_or(0) }
}

unsafe fn try_execve(ctx: &TracePointContext) -> Option<u32> {
    let mut event = KernelEvent {
        event_type: EVENT_EXECVE,
        pid: helpers::bpf_get_current_pid_tgid() as u32,
        ppid: 0,
        uid: helpers::bpf_get_current_uid_gid() as u32,
        ns_pid: 0,
        dest_ip: 0,
        dest_port: 0,
        _pad: 0,
        filename: [0u8; 128],
        argv: [0u8; 256],
    };

    // Read filename pointer from tracepoint args at offset 8
    let filename_ptr: u64 = ctx.read_at(8).ok()?;
    let _ = helpers::bpf_probe_read_user_str_bytes(
        filename_ptr as *const u8,
        &mut event.filename,
    );

    // Read first argv[0] from args at offset 16
    let argv_ptr: u64 = ctx.read_at(16).ok()?;
    let arg0_ptr: u64 = helpers::bpf_probe_read_user(&(argv_ptr as *const u64)).ok()?;
    if arg0_ptr != 0 {
        let _ = helpers::bpf_probe_read_user_str_bytes(arg0_ptr as *const u8, &mut event.argv);
    }

    let size = core::mem::size_of::<KernelEvent>();
    if let Some(buf) = KERNEL_EVENTS.reserve::<KernelEvent>(0) {
        core::ptr::write_unaligned(buf.as_mut_ptr(), event);
        buf.submit(0);
    }

    Some(0)
}

// ---------------------------------------------------------------------------
// sys_enter_connect — outbound socket connection tracking (C2 detection)
// ---------------------------------------------------------------------------
// Tracepoint args for sys_enter_connect:
//   +0  u64 syscall_nr
//   +8  int fd
//   +16 struct sockaddr* uservaddr
//   +24 int addrlen

#[repr(C)]
struct SockaddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    _pad: [u8; 8],
}

#[tracepoint]
pub fn handle_connect(ctx: TracePointContext) -> u32 {
    unsafe { try_connect(&ctx).unwrap_or(0) }
}

unsafe fn try_connect(ctx: &TracePointContext) -> Option<u32> {
    let sockaddr_ptr: u64 = ctx.read_at(16).ok()?;

    let mut sa = SockaddrIn {
        sin_family: 0,
        sin_port: 0,
        sin_addr: 0,
        _pad: [0u8; 8],
    };

    helpers::bpf_probe_read_user(
        &mut sa as *mut SockaddrIn,
    ).ok()?;

    // AF_INET = 2 — only track IPv4 outbound
    if sa.sin_family != 2 {
        return Some(0);
    }

    let event = KernelEvent {
        event_type: EVENT_CONNECT,
        pid: helpers::bpf_get_current_pid_tgid() as u32,
        ppid: 0,
        uid: helpers::bpf_get_current_uid_gid() as u32,
        ns_pid: 0,
        dest_ip: sa.sin_addr,
        dest_port: sa.sin_port,
        _pad: 0,
        filename: [0u8; 128],
        argv: [0u8; 256],
    };

    if let Some(buf) = KERNEL_EVENTS.reserve::<KernelEvent>(0) {
        core::ptr::write_unaligned(buf.as_mut_ptr(), event);
        buf.submit(0);
    }

    Some(0)
}

// ---------------------------------------------------------------------------
// sys_enter_memfd_create — fileless ELF detection
// ---------------------------------------------------------------------------
// Tracepoint args for sys_enter_memfd_create:
//   +0  u64 syscall_nr
//   +8  const char* uname
//   +16 unsigned int flags

#[tracepoint]
pub fn handle_memfd_create(ctx: TracePointContext) -> u32 {
    unsafe { try_memfd(&ctx).unwrap_or(0) }
}

unsafe fn try_memfd(ctx: &TracePointContext) -> Option<u32> {
    let name_ptr: u64 = ctx.read_at(8).ok()?;

    let mut event = KernelEvent {
        event_type: EVENT_MEMFD,
        pid: helpers::bpf_get_current_pid_tgid() as u32,
        ppid: 0,
        uid: helpers::bpf_get_current_uid_gid() as u32,
        ns_pid: 0,
        dest_ip: 0,
        dest_port: 0,
        _pad: 0,
        filename: [0u8; 128],
        argv: [0u8; 256],
    };

    let _ = helpers::bpf_probe_read_user_str_bytes(name_ptr as *const u8, &mut event.filename);

    if let Some(buf) = KERNEL_EVENTS.reserve::<KernelEvent>(0) {
        core::ptr::write_unaligned(buf.as_mut_ptr(), event);
        buf.submit(0);
    }

    Some(0)
}

// Panic handler required for no_std
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
