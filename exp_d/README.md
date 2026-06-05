# exp_d: raw eBPF load performance

This experiment measures raw `BPF_PROG_LOAD` latency for a tiny socket-filter eBPF program.

Program attributes and signatures are prepared before timing. Each row times only the `bpf(BPF_PROG_LOAD)` syscall.

## Setup

Generate the signers once if the key files are missing:

```bash
cd ~/ebpf-ima-eval-public/exp_d
bash keys/generate-keys.sh
```

Load the cert for the running kernel after every reboot.

For `linux-6.19-rc4`:

```bash
sudo keyctl padd asymmetric "" %:.ima < keys/signing_cert.linux_6_19_rc4.der
```

For `ebpf-ima-linux`:

```bash
sudo keyctl padd asymmetric "" %:.ima < keys/signing_cert.ebpf_ima_linux.der
```

`make` chooses the signed-load key by `uname -r`: `rc4` uses `keys/signing_key.linux_6_19_rc4.pem`, and `rc1` uses `keys/signing_key.ebpf_ima_linux.pem`.

## Runs

### linux-6.19-rc4 baseline

Baseline has no policy rule to be added.

```bash
cd ~/ebpf-ima-eval-public/exp_d
make RUN_NAME=baseline_unsigned SIGNED=0 UNIQUE=0 ITERS=1000
make RUN_NAME=baseline_signed SIGNED=1 UNIQUE=0 ITERS=1000
```

### ebpf-ima-linux no rule

Do not add any `func=BPF_CHECK` IMA policy rule.

```bash
cd ~/ebpf-ima-eval-public/exp_d
make RUN_NAME=ima_no_rule_unsigned SIGNED=0 UNIQUE=0 ITERS=1000
make RUN_NAME=ima_no_rule_signed SIGNED=1 UNIQUE=0 ITERS=1000
```

### ebpf-ima-linux measure

Add measurement policy, then run:

```bash
echo "measure func=BPF_CHECK" | sudo tee /sys/kernel/security/ima/policy

cd ~/ebpf-ima-eval-public/exp_d
make RUN_NAME=ima_measure_identical_unsigned SIGNED=0 UNIQUE=0 ITERS=1000
make RUN_NAME=ima_measure_identical_signed SIGNED=1 UNIQUE=0 ITERS=1000
make RUN_NAME=ima_measure_unique_unsigned SIGNED=0 UNIQUE=1 ITERS=200
make RUN_NAME=ima_measure_unique_signed SIGNED=1 UNIQUE=1 ITERS=200
```

### ebpf-ima-linux appraise

For appraisal, start from a fresh boot and add only appraisal policy.

```bash
echo "appraise func=BPF_CHECK" | sudo tee /sys/kernel/security/ima/policy

cd ~/ebpf-ima-eval-public/exp_d
make RUN_NAME=ima_appraise_signed SIGNED=1 UNIQUE=0 ITERS=1000
```

## Data Files

Each `make` run creates one result directory:

```text
results/<timestamp>-<RUN_NAME>/
```

Files:

- `load.tsv`: raw per-load timing: `iteration<TAB>elapsed_ms<TAB>rc<TAB>errno`. The loader exits after the first load error.
- `meta.tsv`: run settings.

Analyze result directories after collecting runs:

```bash
python3 analyze.py results
```

`make clean` deletes the local benchmark binary and `results/`.
