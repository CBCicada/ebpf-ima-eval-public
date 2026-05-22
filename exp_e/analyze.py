#!/usr/bin/env python3
import argparse
from pathlib import Path


def result_dirs(path):
    if (path / "purge.tsv").exists():
        return [path]
    return sorted(p for p in path.iterdir() if (p / "purge.tsv").exists())


def main():
    parser = argparse.ArgumentParser(description="Summarize exp_e purge.tsv files.")
    parser.add_argument("path")
    args = parser.parse_args()

    total = 0
    residual_total = 0
    for path in result_dirs(Path(args.path)):
        with (path / "purge.tsv").open() as f:
            header = next(f).split()
            values = next(f).split()
        row = dict(zip(header, values))
        total += 1
        residual_total += int(row["residual"])

        print(path.name)
        print(f"  progs: {row['progs']}")
        print(f"  prog_pins: {row['prog_pins']}")
        print(f"  prog_fd_holders: {row['prog_fd_holders']} x {row['fds_per_holder']}")
        print(f"  pin_fd_holders: {row['pin_fd_holders']}")
        print(f"  prog_array_entries: {row['prog_array_entries']}")
        print(f"  link_count: {row['link_count']}")
        print(f"  link_fd_holders: {row['link_fd_holders']}")
        print(f"  link_pins: {row['link_pins']}")
        print(f"  link_pin_fd_holders: {row['link_pin_fd_holders']}")
        print(f"  reappraise_ms: {float(row['reappraise_ms']):.6f}")
        print(f"  residual: {row['residual']}")

    if residual_total == 0:
        print(f"0 residual revoked programs after timeout over {total} runs.")
    else:
        print(f"{residual_total} residual revoked programs after timeout over {total} runs.")


if __name__ == "__main__":
    main()
