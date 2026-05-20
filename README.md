# assumptions / setup

install Fedora 42.

## host tools for exp B/C

Install these before compiling the kernel.

```bash
sudo dnf install -y \
  git curl ca-certificates jq \
  make gcc gcc-c++ clang llvm llvm-devel elfutils-libelf-devel \
  openssl keyutils bpftool golang \
  moby-engine docker-compose containerd dnf-plugins-core

sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"
newgrp docker

sudo curl -Lo /usr/local/bin/kind \
  https://kind.sigs.k8s.io/dl/v0.24.0/kind-linux-amd64
sudo chmod +x /usr/local/bin/kind

KUBECTL_VERSION="$(curl -sL https://dl.k8s.io/release/stable.txt)"
sudo curl -Lo /usr/local/bin/kubectl \
  "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl"
sudo chmod +x /usr/local/bin/kubectl

curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | sudo bash
```

Running clusters on fedora could run into default limit of fs.inotify.max_user_instances
So we need to raise it in sysctl
Create file `/etc/sysctl.d/90-k8s-inotify.conf` with content
```
fs.inotify.max_user_instances = 1024
```

## kernel

Kernel is compiled in `~/ebpf-ima-eval-public/ebpf-ima-linux` with the checked-in
`kernel.config` copied to `ebpf-ima-linux/.config`.

```bash
cp ../kernel.config .config
make -j$(nproc)
sudo make modules_install
sudo make install
sudo dracut --kver "6.19.0-rc1+" --force
sudo grub2-mkconfig -o /boot/grub2/grub.cfg
sudo grubby --info=ALL
sudo grubby --set-default-index=?
```

After kernel compilation, the build CA used by Exp B/C signer certs is at:

```text
~/ebpf-ima-eval-public/ebpf-ima-linux/certs/signing_key.pem
~/ebpf-ima-eval-public/ebpf-ima-linux/certs/signing_key.x509
```

Then compile the custom bpftool

```bash
cd ~/ebpf-ima-eval-public/ebpf-ima-linux/tools/bpf/bpftool
make -j$(nproc)
```

and symlink it
```bash
sudo ln -sf ~/ebpf-ima-eval-public/ebpf-ima-linux/tools/bpf/bpftool/bpftool /usr/local/bin/bpftool
```

check:

```bash
docker info
kind version
kubectl version --client
helm version --short
go version
sudo keyctl show %:.ima
sudo keyctl show %:.blacklist
ls /sys/kernel/security/ima/reappraise_ebpf
```

Every exp should be executed on a fresh boot.
