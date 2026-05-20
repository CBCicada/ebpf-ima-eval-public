#!/usr/bin/env bash
set -euo pipefail

NS="expc-cve"
CLIENT="cve-c-client"
SERVER="cve-c-host-server"
CLUSTER="exp-c"
SOURCE_NODE="${CLUSTER}-worker"
TARGET_NODE="${CLUSTER}-worker2"
ALLOW_PORT="80"
DENY_PORT="8080"
POLICY_SYS="/sys/kernel/security/ima/policy"
MEAS_LOG="/sys/kernel/security/ima/ascii_runtime_measurements"
WG_LINK="/sys/fs/bpf/cilium/devices/cilium_wg0/links/cil_from_wireguard"

say() { printf '\033[34m[run_vuln]\033[0m %s\n' "$*"; }
die() { printf '\033[31m[run_vuln ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

if [[ $EUID -ne 0 ]]; then
    die "run with sudo -E"
fi
if [[ -z "${KUBECONFIG:-}" && -n "${SUDO_USER:-}" ]]; then
    sudo_home="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
    export KUBECONFIG="$sudo_home/.kube/config"
fi

for cmd in kubectl jq; do
    if ! command -v "$cmd" >/dev/null; then
        die "$cmd not installed"
    fi
done
if [[ ! -e /sys/kernel/security/ima/reappraise_ebpf ]]; then
    die "missing IMA eBPF reappraise interface"
fi
kubectl config use-context "kind-$CLUSTER" >/dev/null

before_count="$(wc -l < "$MEAS_LOG" || echo 0)"
say "measurement log before policy: $before_count entries"

if grep -q "appraise func=BPF_CHECK ebpf_prog_type=BPF_PROG_TYPE_SCHED_CLS" "$POLICY_SYS"; then
    say "BPF SCHED_CLS appraisal policy already active"
else
    say "loading IMA BPF policy"
    {
        printf 'measure func=BPF_CHECK\n'
        printf 'appraise func=BPF_CHECK ebpf_prog_type=BPF_PROG_TYPE_SCHED_CLS\n'
    } > "$POLICY_SYS"
fi
if ! grep -E "func=BPF_CHECK" "$POLICY_SYS" >/dev/null; then
    die "BPF_CHECK policy missing"
fi

say "restarting signer-enabled Cilium under active policy"
kubectl -n kube-system delete pod -l k8s-app=cilium --wait=true >/dev/null
kubectl -n kube-system rollout status ds/cilium --timeout=5m

for agent_pod in $(kubectl -n kube-system get pod -l k8s-app=cilium -o name); do
    logs="$(kubectl -n kube-system logs "$agent_pod" --tail 1000 2>/dev/null || true)"
    if ! grep -q "IMA-driven reload signal watcher installed" <<< "$logs"; then
        die "restarted agent did not log reload watcher: $agent_pod"
    fi
    if ! kubectl -n kube-system exec "$agent_pod" -- test -e "$WG_LINK"; then
        die "$WG_LINK missing in $agent_pod"
    fi
done

cp "$MEAS_LOG" /tmp/exp_c.meas_baseline
printf '%s\n' "$WG_LINK" > /tmp/exp_c.wg_link
printf '%s\n' "$SOURCE_NODE" > /tmp/exp_c.source_node
printf '%s\n' "$TARGET_NODE" > /tmp/exp_c.target_node

TARGET_IP="$(kubectl get node "$TARGET_NODE" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')"
if [[ -z "$TARGET_IP" ]]; then
    die "could not resolve $TARGET_NODE InternalIP"
fi
printf '%s\n' "$TARGET_IP" > /tmp/exp_c.target_ip

say "creating CVE workload"
kubectl delete ciliumclusterwidenetworkpolicy expc-cve-hostfw --ignore-not-found >/dev/null
kubectl delete namespace "$NS" --ignore-not-found --wait=true --timeout=2m >/dev/null
kubectl label node "$TARGET_NODE" status=lockdown --overwrite >/dev/null
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NS" apply -f - >/dev/null <<YAML
apiVersion: apps/v1
kind: Deployment
metadata:
  name: $SERVER
spec:
  replicas: 1
  selector:
    matchLabels:
      app: $SERVER
  template:
    metadata:
      labels:
        app: $SERVER
        test: hostfw
        zgroup: testServerHost
    spec:
      hostNetwork: true
      nodeSelector:
        kubernetes.io/hostname: $TARGET_NODE
      tolerations:
      - operator: Exists
      containers:
      - name: server
        image: python:3.12-alpine
        command:
        - python3
        - -u
        - -c
        - |
          from http.server import BaseHTTPRequestHandler, HTTPServer
          import threading
          class H(BaseHTTPRequestHandler):
              def do_GET(self):
                  self.send_response(200)
                  self.end_headers()
                  self.wfile.write(b"host-ok\n")
              def log_message(self, *args):
                  pass
          for port in ($ALLOW_PORT, $DENY_PORT):
              threading.Thread(target=HTTPServer(("0.0.0.0", port), H).serve_forever, daemon=True).start()
          threading.Event().wait()
---
apiVersion: v1
kind: Pod
metadata:
  name: $CLIENT
  labels:
    app: $CLIENT
    test: hostfw
    zgroup: testClient
spec:
  restartPolicy: Never
  nodeSelector:
    kubernetes.io/hostname: $SOURCE_NODE
  containers:
  - name: curl
    image: curlimages/curl:8.10.1
    command: ["sh", "-c", "sleep 1d"]
YAML

kubectl -n "$NS" rollout status deploy "$SERVER" --timeout=3m >/dev/null
kubectl -n "$NS" wait --for=condition=Ready pod "$CLIENT" --timeout=3m >/dev/null

kubectl apply -f - >/dev/null <<YAML
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: expc-cve-hostfw
specs:
- description: Allow only test client traffic to TCP/$ALLOW_PORT on the target host.
  nodeSelector:
    matchLabels:
      status: lockdown
  ingress:
  - fromEndpoints:
    - matchLabels:
        zgroup: testClient
    toPorts:
    - ports:
      - port: "$ALLOW_PORT"
        protocol: TCP
  - fromEndpoints:
    - matchExpressions:
      - key: test
        operator: NotIn
        values:
        - hostfw
  egress:
  - toEndpoints:
    - matchLabels:
        zgroup: testClient
  - toEndpoints:
    - matchExpressions:
      - key: test
        operator: NotIn
        values:
        - hostfw
- description: Open node plumbing and the allowed host test port between nodes.
  nodeSelector: {}
  ingress:
  - fromEntities:
    - remote-node
    toPorts:
    - ports:
      - port: "$ALLOW_PORT"
        protocol: TCP
      - port: "6443"
        protocol: TCP
      - port: "10250"
        protocol: TCP
      - port: "4240"
        protocol: TCP
      - port: "51871"
        protocol: UDP
  egress:
  - toEntities:
    - remote-node
    toPorts:
    - ports:
      - port: "$ALLOW_PORT"
        protocol: TCP
      - port: "6443"
        protocol: TCP
      - port: "10250"
        protocol: TCP
      - port: "4240"
        protocol: TCP
      - port: "51871"
        protocol: UDP
- description: Allow all to/from health and world.
  nodeSelector: {}
  ingress:
  - fromEntities:
    - health
    - world
  egress:
  - toEntities:
    - health
    - world
- description: Allow ICMP and ICMPv6 traffic on all nodes.
  nodeSelector: {}
  ingress:
  - icmps:
    - fields:
      - type: 8
        family: IPv4
      - type: 128
        family: IPv6
  egress:
  - icmps:
    - fields:
      - type: 8
        family: IPv4
      - type: 128
        family: IPv6
YAML

sleep 10

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
cat > /tmp/exp_c_cve_behavior/pre.txt <<EOF
mode=pre
target=$TARGET_IP
allowed_port=$ALLOW_PORT
denied_port=$DENY_PORT
allowed_http=$allow_code
denied_http=$deny_code
EOF

if [[ "$allow_code" != "200" ]]; then
    die "allowed host port $ALLOW_PORT should be reachable, got ${allow_code:-failed}"
fi
if [[ "$deny_code" != "200" ]]; then
    die "expected vulnerable host-firewall bypass before reload, got ${deny_code:-failed}"
fi

say "pre-reload vulnerable behavior observed: remote pod reached denied host port"
