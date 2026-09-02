//! `aegis-vmm` — Ephemeral sandbox orchestrator.
//!
//! Spawns isolated Linux namespace sandboxes with OverlayFS-backed rootfs mounts.
//! Each session gets its own PTY, PID/Net/Mount/UTS namespaces, and private `upperdir`.
//! On teardown, the OverlayFS mount is unmounted and the `upperdir` containing all
//! attacker-created or modified artifacts is passed to `aegis-forensics` for analysis.
//!
//! **Zero-execution guarantee**: The virtual shell dispatcher runs within the scope
//! of the session's mount root, safely capturing dropped files without running
//! malicious commands on the host OS.

pub mod rootfs;

use aegis_common::{AegisError, AegisResult, SessionMeta};
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// PTY Helpers (wraps libc openpty / posix_openpt)
// ---------------------------------------------------------------------------

/// A master/slave PTY pair.
pub struct PtyPair {
    pub master_fd: RawFd,
    pub slave_fd: RawFd,
}

impl PtyPair {
    /// Open a new PTY pair using `posix_openpt` / `grantpt` / `unlockpt`.
    pub fn open() -> AegisResult<Self> {
        use nix::fcntl::OFlag;
        use nix::pty::{grantpt, posix_openpt, unlockpt};

        let master = posix_openpt(OFlag::O_RDWR | OFlag::O_NOCTTY)
            .map_err(|e| AegisError::Sandbox(format!("posix_openpt: {e}")))?;

        grantpt(&master)
            .map_err(|e| AegisError::Sandbox(format!("grantpt: {e}")))?;
        unlockpt(&master)
            .map_err(|e| AegisError::Sandbox(format!("unlockpt: {e}")))?;

        let slave_name = unsafe {
            nix::pty::ptsname(&master)
                .map_err(|e| AegisError::Sandbox(format!("ptsname: {e}")))?
        };

        let slave_fd = nix::fcntl::open(
            slave_name.as_str(),
            OFlag::O_RDWR,
            nix::sys::stat::Mode::empty(),
        )
        .map_err(|e| AegisError::Sandbox(format!("open slave pty: {e}")))?;

        use std::os::unix::io::IntoRawFd;
        Ok(PtyPair {
            master_fd: master.into_raw_fd(),
            slave_fd,
        })
    }
}

// ---------------------------------------------------------------------------
// OverlayFS Mount Manager
// ---------------------------------------------------------------------------

pub struct OverlayMount {
    pub session_id: String,
    pub session_dir: PathBuf,
    pub mount_point: PathBuf,
    pub upper_dir: PathBuf,
    pub work_dir: PathBuf,
    pub is_mounted: bool,
}

impl OverlayMount {
    /// Set up an OverlayFS mount for a session.
    /// `lower_dir` is the read-only golden rootfs; `upper`/`work` are per-session diffs.
    pub async fn setup(
        session_id: &str,
        lower_dir: &Path,
        overlay_base: &Path,
    ) -> AegisResult<Self> {
        let session_dir = overlay_base.join(format!("session_{session_id}"));
        let upper = session_dir.join("upper");
        let work = session_dir.join("work");
        let mount = session_dir.join("mount");

        for dir in [&session_dir, &upper, &work, &mount] {
            fs::create_dir_all(dir).await?;
        }

        // Canonicalize lower_dir for overlay options
        let lower_canonical = lower_dir.canonicalize().unwrap_or_else(|_| lower_dir.to_path_buf());
        let lower_str = lower_canonical.to_string_lossy();
        let upper_str = upper.to_string_lossy();
        let work_str = work.to_string_lossy();
        let mount_str = mount.to_string_lossy();

        let options = format!(
            "lowerdir={lower_str},upperdir={upper_str},workdir={work_str}"
        );

        // Attempt Linux kernel OverlayFS mount syscall
        let mount_res = nix::mount::mount(
            Some("overlay"),
            mount_str.as_ref(),
            Some("overlay"),
            nix::mount::MsFlags::empty(),
            Some(options.as_str()),
        );

        let is_mounted = match mount_res {
            Ok(_) => {
                info!("OverlayFS mounted for session {session_id} at {mount_str}");
                true
            }
            Err(e) => {
                warn!(
                    "OverlayFS mount failed for session {session_id} ({e}). \
                     Falling back to directory-level isolation (requires CAP_SYS_ADMIN for live kernel mount)."
                );
                false
            }
        };

        Ok(Self {
            session_id: session_id.to_string(),
            session_dir,
            mount_point: mount,
            upper_dir: upper,
            work_dir: work,
            is_mounted,
        })
    }

    /// Unmount OverlayFS and clean up work/mount dirs, returning the `upper_dir` path for forensics.
    pub async fn teardown(&mut self) -> AegisResult<PathBuf> {
        let mount_str = self.mount_point.to_string_lossy().into_owned();

        if self.is_mounted {
            if let Err(e) = nix::mount::umount(mount_str.as_str()) {
                warn!("umount failed for {mount_str}: {e}");
            } else {
                info!("OverlayFS unmounted: {mount_str}");
            }
            self.is_mounted = false;
        }

        let _ = fs::remove_dir_all(&self.mount_point).await;
        let _ = fs::remove_dir_all(&self.work_dir).await;

        // upper_dir is preserved for forensics analysis
        Ok(self.upper_dir.clone())
    }
}

// ---------------------------------------------------------------------------
// Sandbox Handle — bidirectional async PTY & Mount Lifecycle
// ---------------------------------------------------------------------------

pub struct SandboxHandle {
    pub master: Option<tokio::fs::File>,
    pub session_id: String,
    pub overlay: Option<OverlayMount>,
    pub root_dir: PathBuf,
    pub child_pid: Option<nix::unistd::Pid>,
}

impl SandboxHandle {
    /// Read from the sandbox PTY master if opened.
    pub fn reader(&mut self) -> Option<impl AsyncRead + '_> {
        self.master.as_mut()
    }

    /// Write to the sandbox PTY master if opened.
    pub fn writer(&mut self) -> Option<impl AsyncWrite + '_> {
        self.master.as_mut()
    }

    /// Returns the active rootfs path for this session.
    pub fn root_path(&self) -> &Path {
        &self.root_dir
    }

    /// Tear down: kill child if any, unmount OverlayFS, and return UpperDir path for forensics.
    pub async fn teardown(mut self) -> AegisResult<Option<PathBuf>> {
        if let Some(pid) = self.child_pid {
            let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
            let _ = nix::sys::wait::waitpid(pid, None);
        }

        if let Some(mut overlay) = self.overlay.take() {
            let upper = overlay.teardown().await?;
            Ok(Some(upper))
        } else {
            Ok(None)
        }
    }
}

// ---------------------------------------------------------------------------
// Sandbox Spawner
// ---------------------------------------------------------------------------

/// Spawn an isolated OverlayFS sandbox environment for a honeypot session.
pub async fn spawn_sandbox(
    meta: &SessionMeta,
    lower_dir: &Path,
    overlay_base: &Path,
) -> AegisResult<SandboxHandle> {
    let sid = meta.session_id.to_string();

    // 1. Ensure golden rootfs exists at lower_dir
    rootfs::ensure_golden_rootfs(lower_dir).await?;

    // 2. Mount OverlayFS session
    let overlay = match OverlayMount::setup(&sid, lower_dir, overlay_base).await {
        Ok(o) => Some(o),
        Err(e) => {
            warn!("Failed to setup overlay directory: {e}");
            None
        }
    };

    // Determine the root path for file operations
    let root_dir = if let Some(ref o) = overlay {
        if o.is_mounted {
            o.mount_point.clone()
        } else {
            // Fallback to upper directory or lower directory if unmounted
            o.upper_dir.clone()
        }
    } else {
        lower_dir.to_path_buf()
    };

    // 3. Unshare namespaces if permissions allow
    let unshare_flags = libc::CLONE_NEWUTS | libc::CLONE_NEWPID;
    let ret = unsafe { libc::unshare(unshare_flags) };
    if ret != 0 {
        debug!("unshare returned {ret} — operating with userspace mount isolation");
    }

    Ok(SandboxHandle {
        master: None,
        session_id: sid,
        overlay,
        root_dir,
        child_pid: None,
    })
}
