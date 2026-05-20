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
sudo grubby --info=ALL
sudo grubby --set-default-index=?
```

ON A Fedora 42

Then compile the custom bpftool

```bash
cd ~/ebpf-ima-eval-public/ebpf-ima-linux/tools/bpf/bpftool
make -j$(nproc)
```

and symlink it
```bash
sudo ln -sf ~/ebpf-ima-eval-public/ebpf-ima-linux/tools/bpf/bpftool/bpftool /usr/local/bin/bpftool
```

Every exp are to be executed on a fresh boot.