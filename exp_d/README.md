# exp_d: eBPF IMA load overhead

This experiment measures repeated signed `bpftool prog load` latency for a socket-filter eBPF object with a configurable payload size.

`PAYLOAD_KB` is the requested payload size embedded in the object. The final `.o` is slightly larger because it also contains ELF metadata, BTF/debug info, the license section, and the tiny BPF program.

Default to 1000 iterations, can be changed through load_bench.c

Examples from local compile checks:

```text
PAYLOAD_KB=88    -> build/payload_88kb.bpf.o    ~99 KB
PAYLOAD_KB=256   -> build/payload_256kb.bpf.o   ~271 KB
PAYLOAD_KB=1024  -> build/payload_1024kb.bpf.o  ~1 MB
```

## Signing

Every run uses signed bpftool loading:

```bash
bpftool -L -S -k keys/signing_key.pem -i keys/signing_cert.pem prog load ...
```

`-L` is required because this custom bpftool signs programs through the generated-loader path.

This is intentional. The experiment compares IMA policy/enforcement overhead, not signed-vs-unsigned loading. Put the signing key and cert at:

```text
exp_d/keys/signing_key.pem
exp_d/keys/signing_cert.pem
```

For appraisal modes, make sure the signer certificate is also trusted by `.ima` before running.

## Run Modes

`make` defaults to running the benchmark. It builds the selected payload object and `load_bench`, then writes raw data under `results/`.

All runs use signed `bpftool` loads. Generate the exp_d signer once if the key files are missing:

```bash
cd ~/ebpf-ima-eval-public/exp_d
bash keys/generate-keys.sh
sudo keyctl padd asymmetric "" %:.ima < keys/signing_cert.der
```

Do the keyctl padd every reboot

IMA policy is append-only, so run modes in this order within one boot: `no_ima`, then `measure`, then `measure_appraise`. To get an `appraise`-only run, use a fresh boot and add only the appraisal rule.

### 1. no_ima

Do not add any `func=BPF_CHECK` IMA policy rule.

```bash
cd ~/ebpf-ima-eval-public/exp_d
make PAYLOAD_KB=88 RUN_NAME=no_ima
```

### 2. measure

Add measurement policy, then run:

```bash
echo "measure func=BPF_CHECK" | sudo tee /sys/kernel/security/ima/policy

cd ~/ebpf-ima-eval-public/exp_d
make PAYLOAD_KB=88 RUN_NAME=measure
```

### 3. appraise-only

For appraisal without measurement, start from a fresh boot, add only appraisal policy, then run.

```bash
echo "appraise func=BPF_CHECK" | sudo tee /sys/kernel/security/ima/policy

cd ~/ebpf-ima-eval-public/exp_d
make PAYLOAD_KB=88 RUN_NAME=appraise
```

### 4. measure_appraise

If you already ran `measure` in this boot, add appraisal and run again:

```bash
echo "appraise func=BPF_CHECK" | sudo tee /sys/kernel/security/ima/policy

cd ~/ebpf-ima-eval-public/exp_d
make PAYLOAD_KB=88 RUN_NAME=measure_appraise
```

If starting from a fresh boot, add both rules before the `measure_appraise` run.

Repeat the same mode with other payload sizes by changing `PAYLOAD_KB`, for example `PAYLOAD_KB=256` or `PAYLOAD_KB=1024`.

## Data Files

Each `make` run creates one result directory:

```text
results/<timestamp>-<RUN_NAME>-<PAYLOAD_KB>kb/
```

Files:

- `load.tsv`: raw per-load timing, one row per successful signed load: `iteration<TAB>elapsed_ms<TAB>0`. The loader exits immediately on the first load error.

The number of iterations is the line count of `load.tsv`.

Analyze result directories after collecting runs:

```bash
python3 analyze.py results
```

This prints a short text summary for each result directory.

`make clean` deletes generated build artifacts and local `results/`. Copy or move any result files you want to keep before cleaning.
