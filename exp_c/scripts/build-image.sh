#!/usr/bin/env bash
set -euo pipefail

EXP_C="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

CILIUM_VULN="$EXP_C/cilium-vuln"
CILIUM_PATCHED="$EXP_C/cilium-patched"
UPSTREAM_IMAGE="quay.io/cilium/cilium:v1.18.5"
IMAGE="cilium-exp_c:v1.18.5-clean"

say() { printf '\033[34m[build-image]\033[0m %s\n' "$*"; }
die() { printf '\033[31m[build-image ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

if ! command -v docker >/dev/null; then
    die "docker not installed"
fi
if ! docker info >/dev/null; then
    die "docker daemon not accessible"
fi
if [[ ! -d "$CILIUM_VULN" ]]; then
    die "missing $CILIUM_VULN"
fi
if [[ ! -d "$CILIUM_PATCHED" ]]; then
    die "missing $CILIUM_PATCHED"
fi

say "building vulnerable cilium-agent"
make -C "$CILIUM_VULN/daemon"
AGENT_VULN="$CILIUM_VULN/daemon/cilium-agent"
if [[ ! -x "$AGENT_VULN" ]]; then
    die "missing $AGENT_VULN"
fi

say "building patched cilium-agent"
make -C "$CILIUM_PATCHED/daemon"
AGENT_PATCHED="$CILIUM_PATCHED/daemon/cilium-agent"
if [[ ! -x "$AGENT_PATCHED" ]]; then
    die "missing $AGENT_PATCHED"
fi

if [[ ! -d "$CILIUM_VULN/bpf" ]]; then
    die "missing $CILIUM_VULN/bpf"
fi
if [[ ! -d "$CILIUM_PATCHED/bpf" ]]; then
    die "missing $CILIUM_PATCHED/bpf"
fi

say "pulling $UPSTREAM_IMAGE"
docker pull "$UPSTREAM_IMAGE"

BUILD_CONTEXT="$(mktemp -d)"
trap 'rm -rf "$BUILD_CONTEXT"' EXIT

cp "$AGENT_VULN" "$BUILD_CONTEXT/cilium-agent.vuln"
cp "$AGENT_PATCHED" "$BUILD_CONTEXT/cilium-agent.patched"
cp -a "$CILIUM_VULN/bpf" "$BUILD_CONTEXT/bpf-pre-fix"
cp -a "$CILIUM_PATCHED/bpf" "$BUILD_CONTEXT/bpf-post-fix"

cat > "$BUILD_CONTEXT/Dockerfile" <<EOF
FROM $UPSTREAM_IMAGE

COPY cilium-agent.vuln /usr/bin/cilium-agent
COPY cilium-agent.patched /usr/bin/cilium-agent.patched
RUN chmod +x /usr/bin/cilium-agent /usr/bin/cilium-agent.patched

RUN rm -rf /var/lib/cilium/bpf
COPY bpf-pre-fix /var/lib/cilium/bpf-pre-fix
COPY bpf-post-fix /var/lib/cilium/bpf-post-fix
RUN ln -s bpf-pre-fix /var/lib/cilium/bpf
EOF

say "building $IMAGE"
docker build -t "$IMAGE" "$BUILD_CONTEXT"

say "sanity-checking image"
docker run --rm "$IMAGE" cilium-agent --version
say "done: $IMAGE"
