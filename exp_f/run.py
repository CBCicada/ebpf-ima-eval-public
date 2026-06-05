#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parent
BUILD = ROOT / "build"
KEYS = ROOT / "keys"
MEASUREMENTS = "/sys/kernel/security/ima/ascii_runtime_measurements"
REAPPRAISE = "/sys/kernel/security/ima/reappraise_ebpf"
CGROUP_ROOT = Path("/sys/fs/cgroup")


def run(cmd, **kwargs):
    return subprocess.run(cmd, check=True, **kwargs)


def out(cmd):
    return subprocess.check_output(cmd, text=True)


def ensure_root():
    if os.geteuid() != 0:
        os.execvp("sudo", ["sudo", sys.executable, *sys.argv])


def resolve_path(path):
    p = Path(path)
    if not p.is_absolute():
        p = ROOT / p
    return str(p.resolve())


def ima_keyring_id():
    return int(out(["keyctl", "describe", "%:.ima"]).split(":", 1)[0])


def ensure_signing_material(sign_key, sign_cert, sign_cert_der):
    paths = [Path(sign_key), Path(sign_cert), Path(sign_cert_der)]
    if all(p.exists() for p in paths):
        return
    if any(p.exists() for p in paths):
        raise SystemExit("partial exp_f signing material exists; delete or complete keys/signing_*")
    run(["bash", str(KEYS / "generate-keys.sh")], cwd=ROOT)


def ensure_ima_trust(sign_cert_der):
    listing = out(["keyctl", "list", "%:.ima"])
    if "ebpf-ima-exp-f-signer" in listing:
        return
    cert = Path(sign_cert_der).read_bytes()
    run(["keyctl", "padd", "asymmetric", "", "%:.ima"], input=cert, stdout=subprocess.DEVNULL)


def do_not_nuke_existing_cgroup_progs():
    try:
        programs = json.loads(out(["bpftool", "prog", "show", "-j"]))
    except subprocess.CalledProcessError as err:
        raise SystemExit(f"bpftool preflight failed: {err}") from err

    matches = [prog for prog in programs if prog.get("type") == "cgroup_sock"]
    if matches:
        details = ", ".join(
            f"id={prog.get('id')} name={prog.get('name', '<unnamed>')}" for prog in matches
        )
        raise SystemExit(
            "refusing to run: pre-existing cgroup_sock programs are loaded. "
            "The appraise policy used by this experiment would reappraise matching "
            f"programs globally: {details}"
        )


def build_target(sign_key, sign_cert):
    BUILD.mkdir(exist_ok=True)
    salt = str(time.time_ns())
    src = BUILD / "cgroup_target.bpf.c"
    obj = BUILD / "cgroup_target.bpf.o"
    skel = BUILD / "cgroup_target.skel.h"
    loader = BUILD / "direct_cgroup_loader"
    template = (ROOT / "src" / "cgroup_target.bpf.c.in").read_text()
    src.write_text(template.replace("@SALT@", salt))
    run([
        "clang", "-O2", "-g", "-target", "bpf",
        "-I../ebpf-ima-linux/tools/lib",
        "-I../ebpf-ima-linux/tools/include/uapi",
        "-c", str(src), "-o", str(obj),
    ], cwd=ROOT)
    with skel.open("w") as f:
        run([
            "bpftool", "-S", "-k", sign_key, "-i", sign_cert,
            "gen", "skeleton", str(obj), "name", "cgroup_target",
        ], cwd=ROOT, stdout=f)
    run([
        "gcc", "-O2", "-Wall", "-Wextra",
        "-Ibuild",
        "-I../ebpf-ima-linux/tools/lib",
        "-I../ebpf-ima-linux/tools/include/uapi",
        "-o", str(loader), "src/direct_cgroup_loader.c",
    ], cwd=ROOT)
    return loader


def prog_info(pin):
    info = json.loads(out(["bpftool", "prog", "show", "pinned", str(pin), "-j"]))
    if isinstance(info, list):
        info = info[0]
    return int(info["id"]), info["tag"]


def ima_hash_for_tag(tag):
    text = Path(MEASUREMENTS).read_text()
    found = None
    needle = "sha256:" + tag
    for line in text.splitlines():
        if needle in line:
            found = line.split()[3].removeprefix("sha256:")
    if not found:
        raise RuntimeError(f"tag {tag} not found in IMA measurement log")
    return found


def blacklist(hash_value, sign_key, sign_cert):
    listing = out(["keyctl", "list", "%:.blacklist"])
    if hash_value.lower() in listing.lower():
        return
    desc = "bin:" + hash_value
    sig = subprocess.check_output([
        "openssl", "cms", "-sign", "-binary", "-nosmimecap", "-noattr", "-md", "sha256",
        "-signer", sign_cert, "-inkey", sign_key, "-outform", "DER",
    ], input=desc.encode())
    run(["keyctl", "padd", "blacklist", desc, "%:.blacklist"], input=sig, stdout=subprocess.DEVNULL)


def trigger_reappraise(timeout_ms):
    Path(REAPPRAISE).write_text(f"signal=10 timeout={timeout_ms} force=1\n")


def prog_exists(prog_id):
    return subprocess.run(["bpftool", "prog", "show", "id", str(prog_id)],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def residual_count(ids, deadline):
    while True:
        residual = sum(1 for prog_id in ids if prog_exists(prog_id))
        if residual == 0 or time.monotonic() >= deadline:
            return residual
        time.sleep(0.1)


def start_sleeper(cgroup, seconds):
    proc = subprocess.Popen(["sleep", str(seconds)])
    try:
        (cgroup / "cgroup.procs").write_text(str(proc.pid))
    except Exception:
        proc.terminate()
        proc.wait(timeout=2)
        raise
    return proc


def cleanup_cgroup(path, loader, pin, sleeper):
    if sleeper is not None and sleeper.poll() is None:
        sleeper.terminate()
        try:
            sleeper.wait(timeout=2)
        except subprocess.TimeoutExpired:
            sleeper.kill()
            sleeper.wait()
    if path.exists() and pin.exists():
        subprocess.run([str(loader), "detach", str(pin), str(path)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pin.unlink(missing_ok=True)
    if path.exists():
        try:
            path.rmdir()
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser(description="direct cgroup attachment purge coverage experiment")
    parser.add_argument("--populated", action="store_true", help="move a sleeper into the attached cgroup")
    parser.add_argument("--timeout-ms", type=int, default=10000)
    parser.add_argument("--holder-seconds", type=int, default=120)
    parser.add_argument("--sign-key", default="keys/signing_key.pem")
    parser.add_argument("--sign-cert", default="keys/signing_cert.pem")
    parser.add_argument("--sign-cert-der", default="keys/signing_cert.der")
    args = parser.parse_args()
    args.sign_key = resolve_path(args.sign_key)
    args.sign_cert = resolve_path(args.sign_cert)
    args.sign_cert_der = resolve_path(args.sign_cert_der)
    ensure_signing_material(args.sign_key, args.sign_cert, args.sign_cert_der)
    ensure_root()
    ensure_ima_trust(args.sign_cert_der)
    do_not_nuke_existing_cgroup_progs()
    keyring_id = ima_keyring_id()
    loader = build_target(args.sign_key, args.sign_cert)

    label = "populated" if args.populated else "empty"
    result = ROOT / "results" / f"{datetime.now():%Y%m%d-%H%M%S}-{label}-direct-cgroup"
    result.mkdir(parents=True, exist_ok=True)
    bpffs = Path(f"/sys/fs/bpf/ima_exp_f_{os.getpid()}_{int(time.time())}")
    bpffs.mkdir(parents=True, exist_ok=True)
    pin = bpffs / "cgroup_prog"
    cgroup = CGROUP_ROOT / f"ima_exp_f_{os.getpid()}_{int(time.time())}"
    cgroup.mkdir()

    sleeper = None
    ids = []
    load_ms = blacklist_ms = reappraise_ms = 0.0
    residual = 1
    cgroup_exists = 1
    sleeper_alive = 0

    try:
        if args.populated:
            sleeper = start_sleeper(cgroup, args.holder_seconds)

        load_start = time.monotonic()
        run([str(loader), "attach", str(pin), str(cgroup), str(keyring_id)], stdout=subprocess.DEVNULL)
        prog_id, tag = prog_info(pin)
        ids.append(prog_id)
        hash_value = ima_hash_for_tag(tag)
        load_ms = (time.monotonic() - load_start) * 1000

        blacklist_start = time.monotonic()
        blacklist(hash_value, args.sign_key, args.sign_cert)
        blacklist_ms = (time.monotonic() - blacklist_start) * 1000

        pin.unlink()
        reappraise_start = time.monotonic()
        trigger_reappraise(args.timeout_ms)
        reappraise_ms = (time.monotonic() - reappraise_start) * 1000

        residual = residual_count(ids, time.monotonic() + (args.timeout_ms / 1000) + 5.0)
        if sleeper is not None:
            try:
                sleeper.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        cgroup_exists = 1 if cgroup.exists() else 0
        sleeper_alive = 1 if sleeper is not None and sleeper.poll() is None else 0
    finally:
        cleanup_cgroup(cgroup, loader, pin, sleeper)
        try:
            bpffs.rmdir()
        except OSError:
            pass

    with (result / "purge.tsv").open("w") as f:
        f.write("populated\tload_ms\tblacklist_ms\treappraise_ms\tresidual\tcgroup_exists\tsleeper_alive\n")
        f.write(f"{int(args.populated)}\t{load_ms:.6f}\t{blacklist_ms:.6f}\t{reappraise_ms:.6f}\t{residual}\t{cgroup_exists}\t{sleeper_alive}\n")

    if residual == 0 and cgroup_exists == 0 and sleeper_alive == 0:
        print("0 residual revoked programs and 0 remaining cgroups after timeout over 1 runs.")
    else:
        raise SystemExit(
            f"residual={residual} cgroup_exists={cgroup_exists} sleeper_alive={sleeper_alive} after timeout"
        )
    print(result)


if __name__ == "__main__":
    main()
