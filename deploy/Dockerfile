# ─── Stage 1: Builder ────────────────────────────────────────────────────────
FROM rust:1.79-slim AS builder

RUN apt-get update && apt-get install -y \
    pkg-config libssl-dev libclang-dev clang llvm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

# Build all workspace crates.
# `--locked` is required, not optional: without it a fresh build can silently
# resolve dependency versions other than the audited ones in Cargo.lock, which
# for an internet-facing SSH daemon defeats the point of auditing them.
RUN cargo build --release --locked -p aegis-gateway

# ─── Stage 2: Minimal Runtime ─────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libssl3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user but grant required capabilities via cap_add in compose
RUN useradd -m -s /bin/bash aegis

WORKDIR /opt/aegis
RUN mkdir -p quarantine sessions overlay && \
    chown -R aegis:aegis /opt/aegis

COPY --from=builder /build/target/release/aegis-gateway /usr/local/bin/
COPY deploy/config.toml ./config.toml

# ─── Capability Notes ─────────────────────────────────────────────────────────
# Requires at runtime:
#   cap_sys_admin    — OverlayFS mounts (see the caveat below)
#   net_bind_service — bind port 22 (if port < 1024)
#
# cap_bpf / cap_net_admin are NOT requested: the eBPF probes are not compiled
# into the binary (aegis-ebpf ships an empty bytecode blob), so granting them
# buys nothing and widens the process's privilege for no benefit.
#
# CAVEAT on CAP_SYS_ADMIN: it is close to root-equivalent, and this container
# runs as the unprivileged `aegis` user — container capabilities are not
# inherited into a non-root user's permitted set without file capabilities or
# ambient caps, so the OverlayFS mount will most likely fail and fall back to
# directory-only isolation. That fallback is a perfectly reasonable way to run
# this (nothing is ever executed from the mount either way); it is listed here
# so the choice is deliberate rather than an unnoticed silent failure. If you
# do not need real mounts, drop the capability entirely:
#
#   docker run --security-opt no-new-privileges --read-only \
#              -v aegis-data:/opt/aegis -p 22:2222 aegis-honeypot

EXPOSE 2222

USER aegis

ENTRYPOINT ["/usr/local/bin/aegis-gateway", "config.toml"]
