//! `aegis-vmm` — Ephemeral per-session sandbox orchestrator.
//!
//! Each session gets a private OverlayFS layer over the read-only golden
//! rootfs: its own `upperdir` and `workdir`, mounted `nodev,nosuid,noexec`.
//! On teardown the mount is released and the `upperdir` — everything the
//! attacker created or modified — is handed to `aegis-forensics`.
//!
//! **What this does and does not isolate.** The containment property here is
//! *zero execution*, not namespaces: the virtual shell is a pure dispatcher
//! that never runs attacker input, so there is no process to confine. No PTY
//! is allocated, no child is forked, and no namespace is unshared — earlier
//! revisions claimed all three and delivered none of them, which is worse than
//! not claiming them, because it invites code to rely on a boundary that does
//! not exist. If real command execution is ever introduced, that isolation has
//! to be built here first.

pub mod rootfs;

use aegis_common::{AegisResult, SessionMeta};
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{info, warn};

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

        // `redirect_dir`/`metacopy` off: both are copy-up optimisations that
        // complicate what the upperdir actually contains, and forensics reads
        // the upperdir directly after teardown. Straightforward copy-up keeps
        // captured artifacts whole.
        let options = format!(
            "lowerdir={lower_str},upperdir={upper_str},workdir={work_str},redirect_dir=off,metacopy=off"
        );

        // Attempt Linux kernel OverlayFS mount syscall.
        //
        // nodev/nosuid/noexec are defense in depth: nothing in the current
        // zero-execution design ever executes from this mount, but the mount is
        // performed by a CAP_SYS_ADMIN process over a lowerdir that lives on
        // the host filesystem, and attacker-downloaded payloads get written
        // into it. These flags cost nothing and remove the setuid/device/exec
        // primitives entirely if that ever changes.
        let flags = nix::mount::MsFlags::MS_NODEV
            | nix::mount::MsFlags::MS_NOSUID
            | nix::mount::MsFlags::MS_NOEXEC;
        let mount_res = nix::mount::mount(
            Some("overlay"),
            mount_str.as_ref(),
            Some("overlay"),
            flags,
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

impl Drop for OverlayMount {
    /// Last-resort unmount.
    ///
    /// `teardown()` is only reached on a clean channel close or an explicit
    /// `exit`. Any session that ends abruptly — TCP reset, idle timeout, a
    /// panic in the handler — previously dropped this struct with the mount
    /// still live and the session directory still on disk, leaking both
    /// permanently. (34 orphaned session directories were found on the audited
    /// host, against a single cleanly-closed session.)
    ///
    /// A blocking `umount` in `Drop` is the right trade here: it is one fast
    /// syscall, and the alternative is leaking a kernel mount. `teardown()`
    /// clears `is_mounted`, so this is a no-op on the clean path.
    fn drop(&mut self) {
        if !self.is_mounted {
            return;
        }
        let mount_str = self.mount_point.to_string_lossy().into_owned();
        match nix::mount::umount(mount_str.as_str()) {
            Ok(()) => info!("OverlayFS unmounted on drop: {mount_str}"),
            Err(e) => warn!("umount on drop failed for {mount_str}: {e}"),
        }
        self.is_mounted = false;
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
// Startup Reconciliation
// ---------------------------------------------------------------------------

/// Reclaim session directories left behind by a previous run.
///
/// Even with `Drop` handling the in-process case, a `SIGKILL` or a host reboot
/// leaves `session_*` directories — and possibly live mounts — behind. Returns
/// `(session_id, upper_dir)` for each orphan so the caller can run forensics
/// over artifacts that would otherwise be silently discarded, which is the more
/// important half: those upperdirs are the honeypot's actual product.
///
/// Unmounting is best-effort; `umount` on a path that is not a mount point
/// simply fails, which is the expected case for a directory-only fallback.
pub async fn reclaim_orphaned_sessions(overlay_base: &Path) -> Vec<(String, PathBuf)> {
    let mut orphans = Vec::new();

    let Ok(mut entries) = fs::read_dir(overlay_base).await else {
        return orphans;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(session_id) = name.strip_prefix("session_") else {
            continue;
        };
        if !entry.file_type().await.is_ok_and(|t| t.is_dir()) {
            continue;
        }

        let mount_point = path.join("mount");
        if mount_point.is_dir() {
            let mount_str = mount_point.to_string_lossy().into_owned();
            if nix::mount::umount(mount_str.as_str()).is_ok() {
                info!("Unmounted orphaned OverlayFS mount: {mount_str}");
            }
        }

        let upper = path.join("upper");
        if upper.is_dir() {
            orphans.push((session_id.to_owned(), upper));
        } else {
            // Nothing recoverable — drop the whole directory.
            let _ = fs::remove_dir_all(&path).await;
        }
    }

    if !orphans.is_empty() {
        warn!(
            "Found {} orphaned session director{} from a previous run — running forensics before cleanup",
            orphans.len(),
            if orphans.len() == 1 { "y" } else { "ies" }
        );
    }
    orphans
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

    // NOTE: there is deliberately no `unshare()` here any more.
    //
    // The previous code called `unshare(CLONE_NEWUTS | CLONE_NEWPID)` once per
    // session and achieved nothing while doing real harm. `CLONE_NEWPID` does
    // not move the caller into a new PID namespace — it only affects future
    // children, and this function forks none. `CLONE_NEWUTS` applies to the
    // *calling thread*, which is whichever tokio worker happened to run the
    // connection, so unrelated sessions sharing that worker inherited divergent
    // namespace state for the rest of the process lifetime.
    //
    // The isolation this design actually provides is: a per-session directory,
    // plus the fact that nothing is ever executed. That is a defensible
    // architecture; it just isn't namespace isolation, and pretending otherwise
    // invited future code to rely on a boundary that was never there. If real
    // command execution is ever added, the unshare must happen in a forked
    // child before `exec` — never on a shared runtime thread.

    Ok(SandboxHandle {
        master: None,
        session_id: sid,
        overlay,
        root_dir,
        child_pid: None,
    })
}
