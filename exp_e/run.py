#!/usr/bin/env python3
import argparse
import json
import os
import shutil
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
TRACEPOINT_SLOTS = 18


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
        raise SystemExit("partial exp_e signing material exists; delete or complete keys/signing_*")
    run(["bash", str(KEYS / "generate-keys.sh")], cwd=ROOT)


def ensure_ima_trust(sign_cert_der):
    listing = out(["keyctl", "list", "%:.ima"])
    if "ebpf-ima-exp-e-signer" in listing:
        return
    cert = Path(sign_cert_der).read_bytes()
    run(["keyctl", "padd", "asymmetric", "", "%:.ima"], input=cert, stdout=subprocess.DEVNULL)


def build_target(sign_key, sign_cert):
    BUILD.mkdir(exist_ok=True)
    salt = str(time.time_ns())
    src = BUILD / "purge_target.bpf.c"
    obj = BUILD / "purge_target.bpf.o"
    skel = BUILD / "purge_target.skel.h"
    loader = BUILD / "signed_loader"
    template = (ROOT / "src" / "purge_target.bpf.c.in").read_text()
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
            "gen", "skeleton", str(obj), "name", "purge_target",
        ], cwd=ROOT, stdout=f)
    run([
        "gcc", "-O2", "-Wall", "-Wextra",
        "-Ibuild",
        "-I../ebpf-ima-linux/tools/lib",
        "-I../ebpf-ima-linux/tools/include/uapi",
        "-o", str(loader), "src/signed_loader.c",
    ], cwd=ROOT)
    run(["gcc", "-O2", "-Wall", "-Wextra", "-o", str(BUILD / "ref_holder"), "src/ref_holder.c"], cwd=ROOT)
    return loader, BUILD / "ref_holder"


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


def start_logged_holder(cmd, log_path, ready_error):
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    with log_path.open("w") as f:
        while True:
            line = proc.stdout.readline()
            if not line:
                rest, _ = proc.communicate(timeout=2)
                f.write(rest)
                raise RuntimeError(ready_error)
            f.write(line)
            f.flush()
            if line.strip() == "ready":
                break
    return proc, log_path


def spawn_holder(holder, seconds, specs, log_path):
    cmd = [str(holder), "hold", str(seconds)]
    for path, copies in specs:
        cmd.extend([str(path), str(copies)])
    return start_logged_holder(cmd, log_path, "ref holder did not become ready")


def finish_holders(procs):
    for proc, log_path in procs:
        proc.terminate()
        try:
            output, _ = proc.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            output, _ = proc.communicate()
        with log_path.open("a") as f:
            f.write(output)


def link_pin_paths(link_dir, prog_count, per_prog):
    return [link_dir / f"link_{i}_{j}" for i in range(prog_count) for j in range(per_prog)]


def main():
    parser = argparse.ArgumentParser(description="merged purge scaling/stress resource experiment")
    parser.add_argument("--progs", type=int, required=True)
    parser.add_argument("--prog-pins", type=int, default=0)
    parser.add_argument("--prog-fd-holders", type=int, default=0)
    parser.add_argument("--fds-per-holder", type=int, default=1)
    parser.add_argument("--pin-fd-holders", type=int, default=0)
    parser.add_argument("--prog-array-entries", type=int, default=0)
    parser.add_argument("--link-count", type=int, default=0)
    parser.add_argument("--link-fd-holders", type=int, default=0)
    parser.add_argument("--link-pins", type=int, default=0)
    parser.add_argument("--link-pin-fd-holders", type=int, default=0)
    parser.add_argument("--timeout-ms", type=int, default=5000)
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
    keyring_id = ima_keyring_id()

    if args.progs <= 0:
        raise SystemExit("--progs must be positive")
    if not any([
        args.prog_pins,
        args.prog_fd_holders,
        args.pin_fd_holders,
        args.prog_array_entries,
        args.link_count,
        args.link_fd_holders,
        args.link_pins,
        args.link_pin_fd_holders,
    ]):
        raise SystemExit("request at least one implemented resource holder")
    if args.link_count + args.link_fd_holders + args.link_pins > TRACEPOINT_SLOTS:
        raise SystemExit(f"requested link slots exceed helper tracepoint pool of {TRACEPOINT_SLOTS}")
    loader, holder = build_target(args.sign_key, args.sign_cert)
    label = (
        f"{args.progs}progs-pins{args.prog_pins}"
        f"-fdh{args.prog_fd_holders}x{args.fds_per_holder}"
        f"-pfdh{args.pin_fd_holders}"
        f"-tail{args.prog_array_entries}"
        f"-links{args.link_count}"
        f"-lfdh{args.link_fd_holders}"
        f"-linkpins{args.link_pins}"
        f"-lph{args.link_pin_fd_holders}"
    )
    result = ROOT / "results" / f"{datetime.now():%Y%m%d-%H%M%S}-{label}"
    result.mkdir(parents=True, exist_ok=True)
    holder_logs = result / "holder_logs"
    holder_logs.mkdir()
    bpffs = Path(f"/sys/fs/bpf/ima_exp_e_{int(time.time())}")
    bpffs.mkdir(parents=True, exist_ok=True)

    procs = []
    ids = []
    hashes = set()
    base_pins = []
    extra_pins = []
    map_pin = bpffs / "tail_calls"
    link_dir = bpffs / "links"
    load_ms = blacklist_ms = reappraise_ms = 0.0

    try:
        load_start = time.monotonic()
        for i in range(args.progs):
            pin = bpffs / f"prog_{i}_base"
            run([str(loader), str(pin), str(keyring_id)], stdout=subprocess.DEVNULL)
            prog_id, tag = prog_info(pin)
            ids.append(prog_id)
            base_pins.append(pin)
            hashes.add(ima_hash_for_tag(tag))

            for j in range(args.prog_pins):
                extra = bpffs / f"prog_{i}_pin_{j}"
                run(["bpftool", "prog", "pin", "id", str(prog_id), str(extra)], stdout=subprocess.DEVNULL)
                extra_pins.append(extra)
        load_ms = (time.monotonic() - load_start) * 1000

        if args.prog_fd_holders:
            specs = [(pin, args.fds_per_holder) for pin in base_pins]
            for i in range(args.prog_fd_holders):
                procs.append(spawn_holder(holder, args.holder_seconds, specs, holder_logs / f"prog_fd_holder_{i}.log"))

        if args.pin_fd_holders:
            pins = extra_pins or base_pins
            specs = [(pin, 1) for pin in pins]
            for i in range(args.pin_fd_holders):
                procs.append(spawn_holder(holder, args.holder_seconds, specs, holder_logs / f"pin_fd_holder_{i}.log"))

        if args.prog_array_entries:
            run([str(holder), "prog_array", str(map_pin), str(args.prog_array_entries), *map(str, base_pins)])

        if args.link_count:
            procs.append(
                start_logged_holder(
                    [str(holder), "link_hold", str(args.holder_seconds), str(args.link_count), "0", *map(str, base_pins)],
                    holder_logs / "link_holder.log",
                    "link holder did not become ready",
                )
            )

        for i in range(args.link_fd_holders):
            start_index = args.link_count + i
            procs.append(
                start_logged_holder(
                    [str(holder), "link_hold", str(args.holder_seconds), "1", str(start_index), *map(str, base_pins)],
                    holder_logs / f"link_fd_holder_{i}.log",
                    "link fd holder did not become ready",
                )
            )

        if args.link_pins:
            link_dir.mkdir(parents=True, exist_ok=True)
            start_index = args.link_count + args.link_fd_holders
            run([str(holder), "link_pin", str(link_dir), str(args.link_pins), str(start_index), *map(str, base_pins)])

        if args.link_pin_fd_holders:
            if not args.link_pins:
                raise SystemExit("--link-pin-fd-holders requires --link-pins")
            specs = [(pin, 1) for pin in link_pin_paths(link_dir, args.progs, args.link_pins)]
            for i in range(args.link_pin_fd_holders):
                procs.append(spawn_holder(holder, args.holder_seconds, specs, holder_logs / f"link_pin_fd_holder_{i}.log"))

        for pin in base_pins:
            pin.unlink(missing_ok=True)

        blacklist_start = time.monotonic()
        for hash_value in hashes:
            blacklist(hash_value, args.sign_key, args.sign_cert)
        blacklist_ms = (time.monotonic() - blacklist_start) * 1000

        reappraise_start = time.monotonic()
        trigger_reappraise(args.timeout_ms)
        reappraise_ms = (time.monotonic() - reappraise_start) * 1000

        residual = residual_count(ids, time.monotonic() + (args.timeout_ms / 1000) + 5.0)
        time.sleep(2)
    finally:
        shutil.rmtree(bpffs, ignore_errors=True)
        finish_holders(procs)

    with (result / "purge.tsv").open("w") as f:
        f.write("progs\tprog_pins\tprog_fd_holders\tfds_per_holder\tpin_fd_holders\tprog_array_entries\tlink_count\tlink_fd_holders\tlink_pins\tlink_pin_fd_holders\tload_ms\tblacklist_ms\treappraise_ms\tresidual\n")
        f.write(f"{args.progs}\t{args.prog_pins}\t{args.prog_fd_holders}\t{args.fds_per_holder}\t{args.pin_fd_holders}\t{args.prog_array_entries}\t{args.link_count}\t{args.link_fd_holders}\t{args.link_pins}\t{args.link_pin_fd_holders}\t{load_ms:.6f}\t{blacklist_ms:.6f}\t{reappraise_ms:.6f}\t{residual}\n")

    if residual == 0:
        print("0 residual revoked programs after timeout over 1 runs.")
    else:
        raise SystemExit(f"{residual} residual revoked programs after timeout over 1 runs.")
    print(result)


if __name__ == "__main__":
    main()
