#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${OUT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
KERNEL_CA_KEY="${KERNEL_CA_KEY:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/ebpf-ima-linux/certs/signing_key.pem}"
KERNEL_CA_CERT="${KERNEL_CA_CERT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/ebpf-ima-linux/certs/signing_key.x509}"

[[ -f "$KERNEL_CA_KEY" ]] || { echo "missing kernel CA key: $KERNEL_CA_KEY" >&2; exit 1; }
[[ -f "$KERNEL_CA_CERT" ]] || { echo "missing kernel CA cert: $KERNEL_CA_CERT" >&2; exit 1; }

mkdir -p "$OUT_DIR"

gen_pair() {
    local tag="$1" cn="$2"
    local key="$OUT_DIR/signing_key${tag}.pem"
    local cert="$OUT_DIR/signing_cert${tag}.pem"
    local der="$OUT_DIR/signing_cert${tag}.der"
    local cfg csr

    if [[ -f "$key" || -f "$cert" || -f "$der" ]]; then
        [[ -f "$key" && -f "$cert" && -f "$der" ]] || {
            echo "partial key material exists for $cn in $OUT_DIR; delete it or complete it" >&2
            exit 1
        }
        echo "$cn already exists in $OUT_DIR"
        return 0
    fi

    cfg="$(mktemp)"
    csr="$(mktemp)"
    trap 'rm -f "$cfg" "$csr"' RETURN

    cat > "$cfg" <<EOF
[req]
default_bits = 4096
distinguished_name = dn
prompt = no
req_extensions = v3
[dn]
CN = $cn
O = eBPF-IMA Demo
[v3]
basicConstraints = critical,CA:FALSE
keyUsage = digitalSignature
subjectKeyIdentifier = hash
EOF

    openssl req -new -nodes -newkey rsa:4096 -keyout "$key" -out "$csr" \
        -config "$cfg" -batch 2>/dev/null

    openssl x509 -req -in "$csr" \
        -CA "$KERNEL_CA_CERT" -CAform DER \
        -CAkey "$KERNEL_CA_KEY" \
        -CAcreateserial \
        -days 36500 -sha256 \
        -extensions v3 -extfile "$cfg" \
        -out "$cert" 2>/dev/null

    openssl x509 -in "$cert" -out "$der" -outform DER
    chmod 600 "$key"
    chmod 644 "$cert" "$der"

    echo "generated $cn"
    openssl x509 -in "$cert" -noout -fingerprint -sha256
}

gen_pair "" "ebpf-ima-exp-d-signer"

echo "key material: $OUT_DIR"
