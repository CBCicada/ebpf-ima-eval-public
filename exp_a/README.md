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