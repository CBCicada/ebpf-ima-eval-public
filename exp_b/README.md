# Cilium CVE demo (CVE-2024-52529)

For this as the fix involves changing bpf program fields, this reloads cilium loader and ebpf programs entirely from v1.16.0 to v1.16.4. This is not an ebpf bytecode only change and that was demonstrated in exp_c.

Build both Cilium agents to verify patches compile:

```bash
cd ~/ebpf-ima-eval-public/exp_b/cilium-vuln
make -C daemon
./daemon/cilium-agent --version

cd ~/ebpf-ima-eval-public/exp_b/cilium-patched
make -C daemon
./daemon/cilium-agent --version
```

policy:
```bash
measure func=BPF_CHECK
appraise func=BPF_CHECK ebpf_prog_type=BPF_PROG_TYPE_SCHED_CLS
```

Use the kernel build keys to generate new certs
```bash
cd ~/ebpf-ima-eval-public/exp_b/keys/
./generate-keys.sh
```