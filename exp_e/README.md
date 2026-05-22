# exp_e: eBPF IMA purge resources

Stress test purge

- `--progs N`: load `N` distinct signed target programs.
- `--prog-pins N`: create `N` bpffs program pins per target program.
- `--prog-fd-holders N`: spawn `N` sleeping processes that hold program fds.
- `--fds-per-holder N`: each program-fd holder opens each target program `N` times.
- `--pin-fd-holders N`: spawn `N` sleeping processes that hold fds opened from pinned programs.
- `--prog-array-entries N`: create a pinned prog-array map with `N` tail-call entries referencing target programs.
- `--link-count N`: create `N` unpinned perf-event BPF links per target program and hold their fds in one sleeping process.
- `--link-fd-holders N`: spawn `N` sleeping processes; each creates and holds one unpinned perf-event BPF link per target program.
- `--link-pins N`: create `N` pinned perf-event BPF links per target program.
- `--link-pin-fd-holders N`: spawn `N` sleeping processes that open fds to every pinned link.

Multiple links for the same target program are attached to distinct tracepoint events. If `--link-count + --link-fd-holders + --link-pins` exceeds the helper's built-in pool of 18 tracepoints, the runner fails before compiling or loading programs.

18 is just a hardcoded list of tracepoints for convenience.

The target program is loaded as a tracepoint program. Link modes attach it to one or more tracepoint perf events from the helper's built-in pool.

## Setup

`exp_e` has its own signer under `keys/`, matching the `exp_d` layout:

```bash
cd ~/ebpf-ima-eval-public/exp_e
bash keys/generate-keys.sh
sudo keyctl padd asymmetric "" %:.ima < keys/signing_cert.der
```

The runner generates missing `keys/signing_key.pem`, `keys/signing_cert.pem`, and `keys/signing_cert.der`, then adds the DER certificate to `%:.ima` before loading programs. Run the `keyctl padd` step again after each reboot if you are doing setup manually.

Load measure plus appraise policy for tracepoint BPF only before running purge tests:

```bash
echo "measure func=BPF_CHECK ebpf_prog_type=BPF_PROG_TYPE_TRACEPOINT" | sudo tee /sys/kernel/security/ima/policy
echo "appraise func=BPF_CHECK ebpf_prog_type=BPF_PROG_TYPE_TRACEPOINT" | sudo tee /sys/kernel/security/ima/policy
```

## Run Examples

One program, 100 program pins:

```bash
cd ~/ebpf-ima-eval-public/exp_e
python3 run.py --progs 1 --prog-pins 100
```

100 programs, one pin each:

```bash
python3 run.py --progs 100 --prog-pins 1
```

One program, 10 holder processes, each holding one program fd:

```bash
python3 run.py --progs 1 --prog-fd-holders 10 --fds-per-holder 1
```

One program with a pinned prog-array containing 100 tail-call entries:

```bash
python3 run.py --progs 1 --prog-array-entries 100
```

One program with 10 unpinned BPF links held by a sleeping process:

```bash
python3 run.py --progs 1 --link-count 10
```

One program with 10 pinned BPF links:

```bash
python3 run.py --progs 1 --link-pins 10
```

One program with pinned links plus 5 processes holding fds to those pinned links:

```bash
python3 run.py --progs 1 --link-pins 10 --link-pin-fd-holders 5
```

Mixed resources:

```bash
python3 run.py --progs 10 --prog-pins 2 --prog-fd-holders 4 --fds-per-holder 2 --prog-array-entries 100
```

## Data Files

Each run creates:

```text
results/<timestamp>-<resource-label>/purge.tsv
```

`purge.tsv` has one data row with resource counts, load time, blacklist time, reappraise time, and residual count.

Analyze result directories:

```bash
python3 analyze.py results
```

When all runs purge cleanly, the analyzer prints:

```text
0 residual revoked programs after timeout over X runs.
```

Remove local generated files with:

```bash
rm -rf build results
```
