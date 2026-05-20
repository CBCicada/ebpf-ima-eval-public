#!/usr/bin/env bash
set -euo pipefail

EXP_B="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEY_DIR="$EXP_B/keys"

CLUSTER="exp-b"
IMAGE="cilium-exp_b:v1.16.0-sigusr1"
KEYS_IN_NODE="/exp_b/keys"
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

if ! command -v docker >/dev/null; then
    die "docker not installed"
fi
if ! command -v kind >/dev/null; then
    die "kind not installed"
fi
if ! command -v kubectl >/dev/null; then
    die "kubectl not installed"
fi
if ! command -v helm >/dev/null; then
    die "helm not installed"
fi
if ! command -v openssl >/dev/null; then
    die "openssl not installed"
fi
if ! command -v keyctl >/dev/null; then
    die "keyctl not installed"
fi
if ! docker info >/dev/null; then
    die "docker daemon not accessible"
fi
if ! docker image inspect "$IMAGE" >/dev/null; then
    die "$IMAGE not found; run exp_b/scripts/build-image.sh first"
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
printf '%s\n' "$IMA_KEYRING_ID" > /tmp/exp_b.ima_keyring_id

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
EOF
    say "creating kind cluster $CLUSTER"
    kind create cluster --config "$kind_config" --wait 2m
fi

kubectl config use-context "kind-$CLUSTER" >/dev/null

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
  repository: cilium-exp_b
  tag: v1.16.0-sigusr1
  useDigest: false
  pullPolicy: Never

operator:
  replicas: 1

kubeProxyReplacement: true
k8sServiceHost: $NODE_IP
k8sServicePort: 6443
rollOutCiliumPods: true

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
  - name: exp-b-keys
    hostPath: $KEYS_IN_NODE
    mountPath: $KEYS_IN_NODE
    hostPathType: Directory
    readOnly: true
EOF

if helm -n kube-system status cilium >/dev/null 2>&1; then
    say "upgrading Cilium"
    helm upgrade cilium cilium/cilium --version 1.16.0 --namespace kube-system --values "$values" --reuse-values
else
    say "installing Cilium"
    helm install cilium cilium/cilium --version 1.16.0 --namespace kube-system --values "$values"
fi

kubectl -n kube-system rollout status ds/cilium --timeout=3m
kubectl -n kube-system wait --for=condition=Ready pod -l io.cilium/app=operator --timeout=3m

agent_pod="$(kubectl -n kube-system get pod -l k8s-app=cilium -o name | head -1)"
if ! kubectl -n kube-system exec "$agent_pod" -- env | grep -E '^BPF_SIGN_' >/dev/null; then
    die "BPF_SIGN_* env missing"
fi
if ! kubectl -n kube-system exec "$agent_pod" -- test -x "$SIGN_SCRIPT"; then
    die "$SIGN_SCRIPT missing in agent pod"
fi
for _ in {1..30}; do
    logs="$(kubectl -n kube-system logs "$agent_pod" --tail 1000 2>/dev/null || true)"
    if grep -q "IMA-driven reload signal watcher installed" <<< "$logs"; then
        break
    fi
    sleep 1
done
logs="$(kubectl -n kube-system logs "$agent_pod" --tail 1000 2>/dev/null || true)"
if ! grep -q "IMA-driven reload signal watcher installed" <<< "$logs"; then
    die "reload watcher log not found"
fi

say "done"
