# Cilium CVE demo 2 (CVE-2026-26963)

Fix is one commit diff, only ebpf bytecode difference.

Build both Cilium agents to verify patches compile:

```bash
cd ~/ebpf-ima-eval-public/exp_c/cilium-vuln
make -C daemon
./daemon/cilium-agent --version

cd ~/ebpf-ima-eval-public/exp_c/cilium-patched
make -C daemon
./daemon/cilium-agent --version
```
Use the kernel build keys to generate new certs
```bash
cd ~/ebpf-ima-eval-public/exp_c/keys/
./generate-keys.sh
```


```bash
cd ~/ebpf-ima-eval-public/exp_c/scripts
./build-image.sh
./cluster-up.sh
sudo -E bash ./run_vuln.sh
sudo -E bash ./revoke.sh
```
