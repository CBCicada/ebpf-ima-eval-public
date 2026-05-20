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

# 1, Measuring the ebpf program

```bash
root@fedora:/home/cbcicada# echo "measure func=BPF_CHECK" > /sys/kernel/security/ima/policy
root@fedora:/home/cbcicada# sudo cat /sys/kernel/security/ima/policy 
measure func=BPF_CHECK
```

Start a process to hide
```bash
cbcicada@fedora:~/ebpf-ima-eval-public/exp_a$ ./sleep.sh
... (keep this in the background)
cbcicada@fedora:~/ebpf-ima-eval-public$ ps aux | grep sleep
cbcicada   35633  0.0  0.0 231932  3712 pts/4    S+   23:26   0:00 /bin/bash ./sleep.sh
```

Note down the number of ebpf programs now and the current measurements
```bash
cbcicada@fedora:~/ebpf-ima-eval-public$ sudo bpftool prog list | wc -l
333
```

(note root bash)
```bash
root@fedora:/sys/kernel/security/ima# cat ascii_runtime_measurements
......
10 683bbaf59c68d09142fbdf85ef1a7647fdbb4183 ima-bpf sha256:feb355913a039a9c8721dce7e15de97e5887994202eb7cbec1a86ded04833bbf iter
```

And then start caracal rootkit in another shell
```bash
cbcicada@fedora:~/ebpf-ima-eval-public/exp_a/caracal/target/release$ sudo ./caracal --pid 35633 -v
[INFO  caracal] =========== eBPF RESSOURCES ===========
[INFO  caracal] bpf prog: 538 -> hide
[INFO  caracal] bpf prog: 539 -> hide
[INFO  caracal] bpf prog: 540 -> hide
...
```

We can see how that the bash sleep.sh is gone, and the ebpf program count stays the same
```bash
cbcicada@fedora:~/ebpf-ima-eval-public$ ps aux | grep sleep
cbcicada   40018  0.0  0.0 230340  2400 ?        S    23:33   0:00 sleep 180
cbcicada   40910  0.0  0.0 230344  2392 pts/4    S+   23:34   0:00 sleep 1
cbcicada   40914  0.0  0.0 230340  2396 ?        S    23:34   0:00 sleep 1
cbcicada   40937  0.0  0.0 231256  2660 pts/13   S+   23:34   0:00 grep --color=auto sleep
cbcicada@fedora:~/ebpf-ima-eval-public$ sudo bpftool prog show | wc -l
333
```

However, we can see that we have captured their programs in this hash list backed by TPM
```bash
root@fedora:/sys/kernel/security/ima# cat ascii_runtime_measurements
...
10 2db5279c16a2fa7fa91fe7b3cffa8ec8ed88b3e5 ima-bpf sha256:59f4a931744dcdc62944a018ed3990e666ec6444616418d3b09a82dc5c753d52 aya_name_check
10 d217aba26ac292d7bd5a22e26e29e95d20c9dbdd ima-bpf sha256:26bbb9e7623511d4ff39f4fa1f25c26c388b91513d43e3470ca2c7460fb0f29e 
10 59cde1829806e8b77d87a8fd5e3138858b0fa862 ima-bpf sha256:ccd15b8023c130f79030932aff8817f1270a1ae959047aff11f3e0b13d2c8441 bpf
10 c0a5c9faab5c04715d941c569cdec0a91a21038c ima-bpf sha256:d97ef48add8ef9c006156564e94c6f6530476fc2381f5e79c58a07078be08713 pid_enter
10 21e7d94bb5e42a4ddf28a83c00053bbfd67b1ec9 ima-bpf sha256:2aa42dd91b8b2e7e7b4b2ea160905c631ef28bde6e5d95f7dcc26b5d89e58967 pid_exit
10 936dafc9f6f6c47b2052e67bda2ba9666eaf5270 ima-bpf sha256:1ab4c3c03cb369f7aa02b9829802fadec65b29315ebf823c74ff3553c61e1af7 statx_enter
10 747c4cd36cbfffa163d7d4197bdf50071040f110 ima-bpf sha256:7d16d4134b9a322498093ede24dc02dacd7d82e4aa2cc976d1869ea9edcfbf0d newfstatat_ente
10 8dfbdc17b7c130d0dfe0ac60d141f2e14cd1ae7b ima-bpf sha256:e1b2dcb57dd33ddd9c4a0982f6ccf9ebca1b640f4f718e675f0ca9aa829ebec7 chdir_enter
10 06a0e7ea908ae575cbfa4d80171d664a76741546 ima-bpf sha256:950ca48a213756202ae200781d1d2030958bbe8f95ef56dd0933a51f9e5a6a83 openat_enter
10 df28699917a3fb46914c3359003ff739b4a1e3c7 ima-bpf sha256:dd66dc20fe7a9f83e2a61afe82dbe29ed2561acaa97bc36c574827e3210d654a x64_sys_kill_ex
10 8e4b4d9830b243fb80a90a096fb50bc51863fb8c ima-bpf sha256:bf32d9328418efb5b7548b20bbe5d4e2a260b8739f575948a89e581a2507bfd6 x64_sys_kill_en
10 c01d5cb57e8adb2dceb76c4dfb401e0221d7e79d ima-bpf sha256:9cc6cd97dae24df9c841aa1b3e0e6d48ff195714008c24ae03b5efb8d90feb88 x64_sys_getpgid
10 d40806780ea0477c321772be18a9d50922610832 ima-bpf sha256:dd66dc20fe7a9f83e2a61afe82dbe29ed2561acaa97bc36c574827e3210d654a x64_sys_getpgid
10 f77cec3098001720f94870a29095b0e8e4aa3d59 ima-bpf sha256:ad162f88c73d269a9e6c38e3b7ccf0f492b69d413c4ecb84b70902e6878707ee x64_sys_getsid_
10 6e2d30a2cefe8c649c1001f4da49270422cad778 ima-bpf sha256:dd66dc20fe7a9f83e2a61afe82dbe29ed2561acaa97bc36c574827e3210d654a x64_sys_getsid_
10 d812c47312b22955f507cde9cb5584815a0d909c ima-bpf sha256:cc84fdbd692f9db7176d12d7b11d813658581977a7b0706274c233ef07bdeb3d x64_sys_getprio
10 26a8d9e154c062e123d8bcf4f65083c4061e0c66 ima-bpf sha256:dd66dc20fe7a9f83e2a61afe82dbe29ed2561acaa97bc36c574827e3210d654a x64_sys_getprio
10 644aefafa98e12890a8591ac699b69f04095f4ee ima-bpf sha256:193493fdf906e0502682329f734632fc25b18561161f72d9257a7fc448d0f8bf x64_sys_sched_g
10 e2bd4fe968531de0a0c251c0edcd1be23f24371f ima-bpf sha256:dd66dc20fe7a9f83e2a61afe82dbe29ed2561acaa97bc36c574827e3210d654a x64_sys_sched_g
10 c42e80aeeaf3f54238e44cf8f448592843ef1960 ima-bpf sha256:74bd4c69f7eb884f80f5f47f6ddebdcd38828e11972e579f2f708e170d4787da x64_sys_sched_g
10 5dde811867f2b3e454573978b66fd7425cb49c41 ima-bpf sha256:dd66dc20fe7a9f83e2a61afe82dbe29ed2561acaa97bc36c574827e3210d654a x64_sys_sched_r
10 d53e4ac69523dd6097d964ffefae4256b9a2af91 ima-bpf sha256:be35128661b91dfe4c18fdb5c8fcc624b7b7829ab4f58870e6b0bb008b7649fe x64_sys_sched_r
10 117647bd1d78715a75be02b9bdebca0d1e05d8a2 ima-bpf sha256:f83dc4cfc1769a97e5de6414644f18d40bf185399e1b83c405e1293b3565cb69 x64_sys_sched_g
```

# 2, Appraise their ebpf programs out of the system

We know caracal runs kprobe ebpf programs to hide its ebpf programs and other processes.
Following the previous setup, we can add another rule to appraise these programs

```bash
root@fedora:/sys/kernel/security/ima# echo "appraise func=BPF_CHECK ebpf_prog_type=BPF_PROG_TYPE_KPROBE" > /sys/kernel/security/ima/policy
```

then trigger reappraisal
```bash
root@fedora:/sys/kernel/security/ima# time echo "signal=10 timeout=5000 force=1" > /sys/kern
el/security/ima/reappraise_ebpf

real    0m1.435s
user    0m0.005s
sys     0m0.011s
```

We can observe that caracal exitted following user defined signal 1
```
[INFO  caracal_ebpf::deunhide::stat] openat(/proc/pid/35633..) detected
[INFO  caracal_ebpf::deunhide::stat] newfstatat(/proc/pid/35633..) detected
User defined signal 1
```

The bash running sleep.sh can be listed again
```bash
cbcicada@fedora:~/ebpf-ima-eval-public$ ps aux | grep sleep
cbcicada   35633  0.0  0.0 231932  3712 pts/4    S+   23:26   0:00 /bin/bash ./sleep.sh
cbcicada   47443  0.0  0.0 230340  2392 ?        S    23:42   0:00 sleep 180
cbcicada   47582  0.0  0.0 230344  2392 pts/4    S+   23:43   0:00 sleep 1
cbcicada   47586  0.0  0.0 231256  2664 pts/13   S+   23:43   0:00 grep --color=auto sleep
```

And running `sudo dmesg` shows a successful appraisal
```bash
[ 3612.461724] bpf_prog_purge[id=558]: queued=1 wait_left_jiffies=4935
[ 3612.550386] bpf_prog_purge[id=559]: queued=1 wait_left_jiffies=4940
[ 3612.630533] bpf_prog_purge[id=560]: queued=1 wait_left_jiffies=4941
[ 3612.630608] ima: IMA policy reappraised on BPF programs
```

Running caracal again shows the program will be denied loading
```bash
cbcicada@fedora:~/ebpf-ima-eval-public/exp_a/caracal/target/release$ sudo ./caracal --pid 35633 -v
Error: the BPF_PROG_LOAD syscall failed. Verifier output: verification time 81 usec
stack depth 8
processed 22 insns (limit 1000000) max_states_per_insn 0 total_states 2 peak_states 2 mark_read 0


Caused by:
    Permission denied (os error 13)
```