# assumptions / setup
kernel is compiled in tree in wherever/ebpf-ima-eval-public/ebpf-ima-linux with
the checked-in `kernel.config` copied to `ebpf-ima-linux/.config`.

```bash
cp ../kernel.config .config
make -j$(nproc)
sudo make modules_install
sudo make install
sudo dracut --kver "6.19.0-rc1+" --force
sudo grub2-mkconfig -o /boot/grub2/grub.cfg
some grubby nonsense
```

ON A Fedora 42

# Caracal prereqs / build

Caracal is under `exp_a/caracal` as a submodule. It is upstream v0.2 with Aya
dependencies pinned for reproducible source builds.

Prereqs used locally:

```bash
rustup default nightly
rustup component add rust-src
cargo install bpf-linker
```

Build order:

```bash
cd exp_a/caracal/caracal-ebpf
cargo build --release

cd ..
cargo build --release
```
