#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${OUT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

mkdir -p "$OUT_DIR"

gen_pair() {
    local tag="$1" cn="$2" ca_key="$3" ca_cert="$4"
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
    trap "rm -f '$cfg' '$csr'" RETURN

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
        -CA "$ca_cert" -CAform DER \
        -CAkey "$ca_key" \
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

gen_from_tree() {
    local tag="$1" tree="$2" cn="$3"
    local ca_key="$tree/certs/signing_key.pem"
    local ca_cert="$tree/certs/signing_key.x509"

    if [[ ! -f "$ca_key" || ! -f "$ca_cert" ]]; then
        echo "warning: missing kernel CA files under $tree/certs; skipping $tag" >&2
        return 0
    fi

    gen_pair ".$tag" "$cn" "$ca_key" "$ca_cert"
}

gen_from_tree "linux_6_19_rc4" "$ROOT/linux-6.19-rc4" "ebpf-ima-exp-d-signer-linux-6.19-rc4"
gen_from_tree "ebpf_ima_linux" "$ROOT/ebpf-ima-linux" "ebpf-ima-exp-d-signer-ebpf-ima-linux"

echo "key material: $OUT_DIR"
