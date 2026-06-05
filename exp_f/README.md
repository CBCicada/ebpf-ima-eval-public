# exp_f: direct cgroup attachment purge coverage

Coverage test for the cgroup-specific purge path.

The runner checks that the revoked program ID disappears and that the temporary cgroup holding the direct attachment is removed. With `--populated`, it also moves a harmless `sleep` process into the cgroup so purge exercises the kill/drain path before cgroup removal.

## Setup

```bash
cd ~/ebpf-ima-eval-public/exp_f
bash keys/generate-keys.sh
sudo keyctl padd asymmetric "" %:.ima < keys/signing_cert.der
```

Load measure plus appraise policy for the cgroup-sock create hook before running this test:

```bash
echo "measure func=BPF_CHECK ebpf_prog_type=BPF_PROG_TYPE_CGROUP_SOCK ebpf_attach_type=BPF_CGROUP_INET_SOCK_CREATE" | sudo tee /sys/kernel/security/ima/policy
echo "appraise func=BPF_CHECK ebpf_prog_type=BPF_PROG_TYPE_CGROUP_SOCK ebpf_attach_type=BPF_CGROUP_INET_SOCK_CREATE" | sudo tee /sys/kernel/security/ima/policy
```

## Run

Run the full two-case batch:

```bash
cd ~/ebpf-ima-eval-public/exp_f
./run.sh
```

Run individual cases:

```bash
python3 run.py --timeout-ms 10000
python3 run.py --populated --timeout-ms 10000 --holder-seconds 45
```

## Data Files

Each run creates:

```text
results/<timestamp>-<case>-direct-cgroup/purge.tsv
```

`purge.tsv` has one data row with load time, blacklist time, reappraise time, residual program count, whether the cgroup still exists, and whether the sleeper is still alive.

Analyze result directories:

```bash
python3 analyze.py results
```

When all runs purge cleanly, the analyzer prints zero residual programs, zero remaining cgroups, and zero remaining sleeper processes.
