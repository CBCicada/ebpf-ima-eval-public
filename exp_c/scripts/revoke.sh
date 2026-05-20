#!/usr/bin/env bash
set -euo pipefail

EXP_C="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEY_DIR="$EXP_C/keys"

NS="expc-cve"
CLIENT="cve-c-client"
CLUSTER="exp-c"
ALLOW_PORT="80"
DENY_PORT="8080"
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

for cmd in kubectl jq openssl keyctl; do
    if ! command -v "$cmd" >/dev/null; then
        die "$cmd not installed"
    fi
done
if [[ ! -f "$KEY_DIR/signing_cert.pem" || ! -f "$KEY_DIR/signing_key.pem" ]]; then
    die "missing vulnerable signing key material in $KEY_DIR"
fi

kubectl config use-context "kind-$CLUSTER" >/dev/null
TARGET_NODE="$(cat /tmp/exp_c.target_node 2>/dev/null || echo "${CLUSTER}-worker2")"
TARGET_IP="$(cat /tmp/exp_c.target_ip 2>/dev/null || true)"
if [[ -z "$TARGET_IP" ]]; then
    TARGET_IP="$(kubectl get node "$TARGET_NODE" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')"
fi
if [[ -z "$TARGET_IP" ]]; then
    die "could not resolve $TARGET_NODE InternalIP"
fi

link_path="$(cat /tmp/exp_c.wg_link 2>/dev/null || echo /sys/fs/bpf/cilium/devices/cilium_wg0/links/cil_from_wireguard)"
agent_pod="$(kubectl -n kube-system get pod -l k8s-app=cilium --field-selector spec.nodeName="$TARGET_NODE" -o name | head -1)"
if [[ -z "$agent_pod" ]]; then
    die "no Cilium agent pod on $TARGET_NODE"
fi

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
printf '%s\n' "$vuln_hash" > /tmp/exp_c.vuln_hash

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

pod_names_before="$(kubectl -n kube-system get pod -l k8s-app=cilium -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | sort)"
restart_total_before="$(kubectl -n kube-system get pod -l k8s-app=cilium -o jsonpath='{range .items[*]}{.status.containerStatuses[0].restartCount}{"\n"}{end}' | awk '{sum += $1} END {print sum+0}')"

say "swapping BPF source tree to post-fix on all agents"
for agent in $(kubectl -n kube-system get pod -l k8s-app=cilium -o name); do
    if ! kubectl -n kube-system exec "$agent" -- sh -c 'test -d /var/lib/cilium/bpf-post-fix && ln -sfn bpf-post-fix /var/lib/cilium/bpf'; then
        die "source swap failed on $agent"
    fi
done

say "triggering eBPF reappraise"
reappraise_start_ns="$(date +%s%N)"
echo 1 > "$REAPPRAISE"
sleep 2

say "recent reload log lines"
for agent in $(kubectl -n kube-system get pod -l k8s-app=cilium -o name); do
    printf '%s\n' "--- $agent ---"
    kubectl -n kube-system logs "$agent" --tail 2000 | \
        grep -iE "SIGUSR1|RegenerateAll|IMA-driven reload|ReinitializeForce|reinitialize" | tail -10 || \
        warn "no reload-path lines found on $agent"
done

pod_names_after="$(kubectl -n kube-system get pod -l k8s-app=cilium -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | sort)"
restart_total_after="$(kubectl -n kube-system get pod -l k8s-app=cilium -o jsonpath='{range .items[*]}{.status.containerStatuses[0].restartCount}{"\n"}{end}' | awk '{sum += $1} END {print sum+0}')"
if [[ "$pod_names_after" != "$pod_names_before" ]]; then
    die "Cilium agent pod set changed during bytecode-only reload"
fi
if [[ "$restart_total_after" -ne "$restart_total_before" ]]; then
    die "Cilium agent restart count changed during bytecode-only reload"
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
            if [[ -n "$patched_hash" && "${#patched_hash}" -eq 64 && "$patched_hash" != "$vuln_hash" ]]; then
                break
            fi
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
    die "current wireguard program is still the blacklisted hash"
fi
if keyctl list "$blacklist_id" | grep -qi "$patched_hash"; then
    die "patched hash is also blacklisted"
fi
reappraise_end_ns="$(date +%s%N)"
reappraise_ms="$(((reappraise_end_ns - reappraise_start_ns) / 1000000))"
say "current hash differs from blacklisted hash"
say "reappraise-to-patched wireguard time: ${reappraise_ms} ms"

curl_code() {
    local port="$1"
    kubectl -n "$NS" exec "$CLIENT" -- \
        curl --max-time 5 -sS -o /tmp/cve-c.out -w '%{http_code}' "http://$TARGET_IP:$port" 2>/dev/null || true
}

allow_code="$(curl_code "$ALLOW_PORT")"
deny_code="$(curl_code "$DENY_PORT")"

say "remote pod -> allowed host $TARGET_IP:$ALLOW_PORT -> HTTP ${allow_code:-failed}"
say "remote pod -> denied  host $TARGET_IP:$DENY_PORT -> HTTP ${deny_code:-failed}"

mkdir -p /tmp/exp_c_cve_behavior
cat > /tmp/exp_c_cve_behavior/post.txt <<EOF
mode=post
target=$TARGET_IP
allowed_port=$ALLOW_PORT
denied_port=$DENY_PORT
allowed_http=$allow_code
denied_http=$deny_code
vuln_hash=$vuln_hash
patched_hash=$patched_hash
reappraise_ms=$reappraise_ms
EOF

if [[ "$allow_code" != "200" ]]; then
    die "allowed host port $ALLOW_PORT should remain reachable, got ${allow_code:-failed}"
fi
if [[ "$deny_code" == "200" ]]; then
    die "expected patched host firewall enforcement after reload, got HTTP 200"
fi

say "done"
