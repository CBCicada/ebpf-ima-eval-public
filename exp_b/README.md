# Cilium CVE demo (CVE-2024-52529)

For this as the fix involves changing bpf program fields, this reloads cilium loader and ebpf programs entirely from v1.16.0 to v1.16.4. This is not an ebpf bytecode only change and that was demonstrated in exp_c.

