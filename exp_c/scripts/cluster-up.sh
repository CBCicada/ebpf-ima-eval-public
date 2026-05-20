#!/usr/bin/env bash
set -euo pipefail

EXP_C="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEY_DIR="$EXP_C/keys"

CLUSTER="exp-c"
IMAGE="cilium-exp_c:v1.18.5-clean"
KEYS_IN_NODE="/exp_c/keys"
SIGN_SCRIPT="$KEYS_IN_NODE/sign-bpf.sh"

say() { printf '\033[34m[cluster-up]\033[0m %s\n' "$*"; }
die() { printf '\033[31m[cluster-up ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

TMP_FILES=()
cleanup() {
    if ((${#TMP_FILES[@]})); then
        rm -f "${TMP_FILES[@]}"
    fi
}
trap cleanup EXIT

for cmd in docker kind kubectl helm openssl keyctl; do
    if ! command -v "$cmd" >/dev/null; then
        die "$cmd not installed"
    fi
done
if ! docker info >/dev/null; then
    die "docker daemon not accessible"
fi
if ! docker image inspect "$IMAGE" >/dev/null; then
    die "$IMAGE not found; run exp_c/scripts/build-image.sh first"
fi

if [[ ! -f "$KEY_DIR/signing_key.pem" || ! -f "$KEY_DIR/signing_cert.der" || ! -f "$KEY_DIR/signing_key_patched.pem" || ! -f "$KEY_DIR/signing_cert_patched.der" ]]; then
    say "generating local signing keys"
    "$KEY_DIR/generate-keys.sh"
fi
if [[ ! -x "$KEY_DIR/sign-bpf.sh" ]]; then
    die "missing executable $KEY_DIR/sign-bpf.sh"
fi

say "registering signer certs in .ima"
IMA_KEYRING_ID="$(sudo keyctl show %:.ima 2>/dev/null | awk '/keyring: \.ima/ { print $1; exit }')"
if [[ -z "$IMA_KEYRING_ID" ]]; then
    die ".ima keyring not found"
fi

for der in "$KEY_DIR/signing_cert.der" "$KEY_DIR/signing_cert_patched.der"; do
    cn="$(openssl x509 -inform DER -in "$der" -noout -subject | sed -n 's/.*CN *= *\([^,]*\).*/\1/p')"
    if sudo keyctl list "$IMA_KEYRING_ID" | grep -qF "$cn"; then
        say "$cn already in .ima"
    else
        sudo keyctl padd asymmetric "" "$IMA_KEYRING_ID" < "$der" >/dev/null
        say "$cn added to .ima"
    fi
done
printf '%s\n' "$IMA_KEYRING_ID" > /tmp/exp_c.ima_keyring_id

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
    say "kind cluster $CLUSTER already exists"
else
    kind_config="$(mktemp --suffix=.yaml)"
    TMP_FILES+=("$kind_config")
    cat > "$kind_config" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: $CLUSTER
networking:
  disableDefaultCNI: true
  kubeProxyMode: none
nodes:
- role: control-plane
  extraMounts:
  - hostPath: $KEY_DIR
    containerPath: $KEYS_IN_NODE
    readOnly: true
- role: worker
  extraMounts:
  - hostPath: $KEY_DIR
    containerPath: $KEYS_IN_NODE
    readOnly: true
- role: worker
  extraMounts:
  - hostPath: $KEY_DIR
    containerPath: $KEYS_IN_NODE
    readOnly: true
EOF
    say "creating kind cluster $CLUSTER"
    kind create cluster --config "$kind_config" --wait 3m
fi

kubectl config use-context "kind-$CLUSTER" >/dev/null

for node in "${CLUSTER}-control-plane" "${CLUSTER}-worker" "${CLUSTER}-worker2"; do
    if ! docker container inspect "$node" >/dev/null 2>&1; then
        die "kind node container $node not found"
    fi
    if ! docker exec "$node" test -d "$KEYS_IN_NODE"; then
        say "copying keys into reused node $node"
        docker exec "$node" mkdir -p "$KEYS_IN_NODE"
        docker cp "$KEY_DIR/." "$node:$KEYS_IN_NODE/"
    fi
done

say "loading $IMAGE into kind"
kind load docker-image "$IMAGE" --name "$CLUSTER"

if ! helm repo list 2>/dev/null | grep -q '^cilium'; then
    helm repo add cilium https://helm.cilium.io/
fi
helm repo update cilium >/dev/null

NODE_IP="$(docker container inspect "${CLUSTER}-control-plane" --format '{{ .NetworkSettings.Networks.kind.IPAddress }}')"
values="$(mktemp --suffix=.yaml)"
TMP_FILES+=("$values")
cat > "$values" <<EOF
image:
  repository: cilium-exp_c
  tag: v1.18.5-clean
  useDigest: false
  pullPolicy: Never

operator:
  replicas: 1

kubeProxyReplacement: true
k8sServiceHost: $NODE_IP
k8sServicePort: 6443
rollOutCiliumPods: true

routingMode: native
ipv4NativeRoutingCIDR: 10.244.0.0/16
encryption:
  enabled: true
  type: wireguard
  nodeEncryption: true
hostFirewall:
  enabled: true

debug:
  enabled: false
hubble:
  enabled: false

extraEnv:
  - name: BPF_SIGN_SCRIPT
    value: $SIGN_SCRIPT
  - name: BPF_SIGN_KEYRING_ID
    value: "$IMA_KEYRING_ID"

extraHostPathMounts:
  - name: exp-c-keys
    hostPath: $KEYS_IN_NODE
    mountPath: $KEYS_IN_NODE
    hostPathType: Directory
    readOnly: true
EOF

if helm -n kube-system status cilium >/dev/null 2>&1; then
    say "upgrading Cilium"
    helm upgrade cilium cilium/cilium --version 1.18.5 --namespace kube-system --values "$values" --reuse-values
else
    say "installing Cilium"
    helm install cilium cilium/cilium --version 1.18.5 --namespace kube-system --values "$values"
fi

kubectl -n kube-system rollout status ds/cilium --timeout=5m
kubectl -n kube-system wait --for=condition=Ready pod -l io.cilium/app=operator --timeout=5m

for agent_pod in $(kubectl -n kube-system get pod -l k8s-app=cilium -o name); do
    if ! kubectl -n kube-system exec "$agent_pod" -- env | grep -E '^BPF_SIGN_' >/dev/null; then
        die "BPF_SIGN_* env missing in $agent_pod"
    fi
    if ! kubectl -n kube-system exec "$agent_pod" -- test -x "$SIGN_SCRIPT"; then
        die "$SIGN_SCRIPT missing in $agent_pod"
    fi
    logs="$(kubectl -n kube-system logs "$agent_pod" --tail 1000 2>/dev/null || true)"
    if ! grep -q "IMA-driven reload signal watcher installed" <<< "$logs"; then
        die "reload watcher log not found in $agent_pod"
    fi
done

say "done"
