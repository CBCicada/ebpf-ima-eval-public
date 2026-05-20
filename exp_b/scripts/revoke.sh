#!/usr/bin/env bash
set -euo pipefail

EXP_B="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEY_DIR="$EXP_B/keys"

NS="$(cat /tmp/exp_b.demo_namespace 2>/dev/null || echo expb-cve)"
SERVER="$(cat /tmp/exp_b.demo_pod_label 2>/dev/null || echo cve-b-server)"
CLIENT="cve-b-client"
MEAS_LOG="/sys/kernel/security/ima/ascii_runtime_measurements"
REAPPRAISE="/sys/kernel/security/ima/reappraise_ebpf"

say() { printf '\033[34m[revoke]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[revoke WARN]\033[0m %s\n' "$*"; }
die() { printf '\033[31m[revoke ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

if [[ $EUID -ne 0 ]]; then
    die "run with sudo -E"
fi
if [[ -z "${KUBECONFIG:-}" && -n "${SUDO_USER:-}" ]]; then
    sudo_home="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
    export KUBECONFIG="$sudo_home/.kube/config"
fi

if ! command -v kubectl >/dev/null; then
    die "kubectl not installed"
fi
if ! command -v jq >/dev/null; then
    die "jq not installed"
fi
if ! command -v openssl >/dev/null; then
    die "openssl not installed"
fi
if ! command -v keyctl >/dev/null; then
    die "keyctl not installed"
fi
if [[ ! -f "$KEY_DIR/signing_cert.pem" || ! -f "$KEY_DIR/signing_key.pem" ]]; then
    die "missing vulnerable signing key material in $KEY_DIR"
fi

kubectl config use-context kind-exp-b >/dev/null
agent_pod="$(kubectl -n kube-system get pod -l k8s-app=cilium -o name | head -1)"
ep_id="$(cat /tmp/exp_b.endpoint_id 2>/dev/null || true)"
if [[ -z "$ep_id" ]]; then
    die "missing /tmp/exp_b.endpoint_id; run exp_b/scripts/run_vuln.sh first"
fi

link_path="/sys/fs/bpf/cilium/endpoints/$ep_id/links/cil_from_container"
prog_id="$(kubectl -n kube-system exec "$agent_pod" -- bpftool link show pinned "$link_path" -j 2>/dev/null | \
    jq -r '.prog_id // empty' || true)"
if [[ ! "$prog_id" =~ ^[0-9]+$ ]]; then
    die "could not resolve prog_id from $link_path"
fi

tag="$(kubectl -n kube-system exec "$agent_pod" -- bpftool prog show id "$prog_id" -j 2>/dev/null | \
    jq -r '.tag // empty' || true)"
if [[ "${#tag}" -ne 16 ]]; then
    die "could not resolve tag for prog $prog_id"
fi

vuln_hash="$(grep "sha256:${tag}" "$MEAS_LOG" | head -1 | awk '{print $4}' | sed 's/^sha256://')"
if [[ -z "$vuln_hash" || "${#vuln_hash}" -ne 64 ]]; then
    die "tag $tag not found in IMA measurement log"
fi
say "vulnerable hash: sha256:$vuln_hash"
printf '%s\n' "$vuln_hash" > /tmp/exp_b.vuln_hash

blacklist_id="$(keyctl show %:.blacklist 2>/dev/null | awk '/keyring: \.blacklist/ { print $1; exit }')"
if [[ -z "$blacklist_id" ]]; then
    die ".blacklist keyring not found"
fi

if keyctl list "$blacklist_id" | grep -qi "$vuln_hash"; then
    say "hash already in .blacklist"
else
    desc="bin:$vuln_hash"
    printf '%s' "$desc" \
        | openssl cms -sign -binary -nosmimecap -noattr -md sha256 \
            -signer "$KEY_DIR/signing_cert.pem" \
            -inkey "$KEY_DIR/signing_key.pem" \
            -outform DER \
        | keyctl padd blacklist "$desc" "$blacklist_id" >/dev/null
    say "added $desc to .blacklist"
fi

say "triggering eBPF reappraise"
reappraise_start_ns="$(date +%s%N)"
echo 1 > "$REAPPRAISE"
sleep 2

agent_pod="$(kubectl -n kube-system get pod -l k8s-app=cilium -o name | head -1)"
say "recent reload log lines"
kubectl -n kube-system logs "$agent_pod" --tail 2000 | \
    grep -iE "SIGUSR1|RegenerateAll|IMA-driven reload|Staged fix|alignment check" | tail -20 || \
    warn "no reload-path lines found"

restarts="$(kubectl -n kube-system get pod -l k8s-app=cilium -o jsonpath='{.items[0].status.containerStatuses[0].restartCount}')"
if [[ "$restarts" -ne 0 ]]; then
    die "agent restarted by kubelet ($restarts); expected unix.Exec in-place"
fi

live_agent="$(kubectl -n kube-system exec "$agent_pod" -- readlink /usr/bin/cilium-agent 2>/dev/null || true)"
if [[ "$live_agent" != "cilium-agent.patched" ]]; then
    die "live agent is $live_agent, expected cilium-agent.patched"
fi

if kubectl -n kube-system exec "$agent_pod" -- test -e /usr/bin/cilium-agent.next 2>/dev/null; then
    die "/usr/bin/cilium-agent.next still exists"
fi
if kubectl -n kube-system exec "$agent_pod" -- test -e /var/lib/cilium/bpf.next 2>/dev/null; then
    die "/var/lib/cilium/bpf.next still exists"
fi

prog_id=""
tag=""
patched_hash=""
for _ in {1..30}; do
    prog_id="$(kubectl -n kube-system exec "$agent_pod" -- bpftool link show pinned "$link_path" -j 2>/dev/null | \
        jq -r '.prog_id // empty' || true)"
    if [[ "$prog_id" =~ ^[0-9]+$ ]]; then
        tag="$(kubectl -n kube-system exec "$agent_pod" -- bpftool prog show id "$prog_id" -j 2>/dev/null | \
            jq -r '.tag // empty' || true)"
        if [[ "${#tag}" -eq 16 ]]; then
            patched_hash="$(grep "sha256:${tag}" "$MEAS_LOG" | tail -1 | awk '{print $4}' | sed 's/^sha256://')"
            [[ -n "$patched_hash" && "${#patched_hash}" -eq 64 ]] && break
        fi
    fi
    sleep 1
done
if [[ ! "$prog_id" =~ ^[0-9]+$ ]]; then
    die "could not resolve current prog_id"
fi
if [[ "${#tag}" -ne 16 ]]; then
    die "could not resolve current tag"
fi
if [[ -z "$patched_hash" || "${#patched_hash}" -ne 64 ]]; then
    die "current tag $tag not found in measurement log"
fi
if [[ "$patched_hash" == "$vuln_hash" ]]; then
    die "current endpoint program is still the blacklisted hash"
fi
reappraise_end_ns="$(date +%s%N)"
reappraise_ms="$(((reappraise_end_ns - reappraise_start_ns) / 1000000))"
say "current hash differs from blacklisted hash"
say "reappraise-to-patched endpoint time: ${reappraise_ms} ms"

curl_probe() {
    local path="$1"
    local response code server_header
    response="$(kubectl -n "$NS" exec "$CLIENT" -- \
        curl --http1.1 -H 'Connection: close' --max-time 5 -i -sS "http://$SERVER$path" 2>/dev/null || true)"
    code="$(awk '/^HTTP\// {code=$2} END {print code}' <<< "$response")"
    server_header="$(awk 'tolower($0) ~ /^server:/ {sub(/\r$/, ""); sub(/^[^:]*:[[:space:]]*/, ""); print; exit}' <<< "$response")"
    printf '%s\t%s\n' "$code" "$server_header"
}

IFS=$'\t' read -r public_code public_server < <(curl_probe /public)
IFS=$'\t' read -r private_code private_server < <(curl_probe /private)

say "GET /public  -> HTTP ${public_code:-failed}"
say "GET /private -> HTTP ${private_code:-failed}"
say "GET /private server header: ${private_server:-none}"

mkdir -p /tmp/exp_b_cve_behavior
cat > /tmp/exp_b_cve_behavior/post.txt <<EOF
mode=post
public=$public_code
public_server=$public_server
private=$private_code
private_server=$private_server
vuln_hash=$vuln_hash
patched_hash=$patched_hash
reappraise_ms=$reappraise_ms
EOF

if [[ "$public_code" != "200" ]]; then
    die "/public should be allowed, got ${public_code:-failed}"
fi
if [[ "${private_server,,}" != "envoy" ]]; then
    die "expected /private to pass through Envoy after reload"
fi

say "done"
