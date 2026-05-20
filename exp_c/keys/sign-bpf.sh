#!/usr/bin/env bash
set -euo pipefail

KEY_DIR="${KEY_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"

SRC_LINK_TARGET="$(readlink /var/lib/cilium/bpf 2>/dev/null || true)"
case "$SRC_LINK_TARGET" in
    *v1.16.4*)
        cert="$KEY_DIR/signing_cert_patched.pem"
        key="$KEY_DIR/signing_key_patched.pem"
        ;;
    *)
        cert="$KEY_DIR/signing_cert.pem"
        key="$KEY_DIR/signing_key.pem"
        ;;
esac

cert="${BPF_SIGN_CERT:-$cert}"
key="${BPF_SIGN_KEY:-$key}"

[[ -f "$cert" ]] || { echo "missing signing cert: $cert" >&2; exit 1; }
[[ -f "$key" ]] || { echo "missing signing key: $key" >&2; exit 1; }

exec openssl cms -sign -binary -nosmimecap -noattr -md sha256 \
    -signer "$cert" \
    -inkey "$key" \
    -outform DER
