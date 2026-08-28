# ─── Stage 1: Builder ────────────────────────────────────────────────────────
FROM rust:1.79-slim AS builder

RUN apt-get update && apt-get install -y \
    pkg-config libssl-dev libclang-dev clang llvm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

# Build all workspace crates
RUN cargo build --release -p aegis-gateway

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
#   cap_bpf          — load eBPF programs
#   cap_net_admin    — attach TC filters / XDP
#   cap_sys_admin    — OverlayFS namespace mounts
#   net_bind_service — bind port 22 (if port < 1024)
#
# docker run --cap-add=CAP_BPF --cap-add=CAP_NET_ADMIN \
#            --cap-add=CAP_SYS_ADMIN -p 22:2222 aegis-honeypot

EXPOSE 2222

USER aegis

ENTRYPOINT ["/usr/local/bin/aegis-gateway", "config.toml"]
