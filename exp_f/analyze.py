#!/usr/bin/env python3
import csv
import sys
from pathlib import Path


def main():
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("results")
    rows = []
    for path in sorted(root.glob("*/purge.tsv")):
        with path.open() as f:
            reader = csv.DictReader(f, delimiter="\t")
            for row in reader:
                row["path"] = str(path)
                rows.append(row)

    residual = sum(int(row["residual"]) for row in rows)
    cgroups = sum(int(row["cgroup_exists"]) for row in rows)
    sleepers = sum(int(row["sleeper_alive"]) for row in rows)
    print(f"{residual} residual revoked programs after timeout over {len(rows)} runs.")
    print(f"{cgroups} remaining cgroups after timeout over {len(rows)} runs.")
    print(f"{sleepers} remaining sleeper processes after timeout over {len(rows)} runs.")
    if residual or cgroups or sleepers:
        for row in rows:
            if int(row["residual"]) or int(row["cgroup_exists"]) or int(row["sleeper_alive"]):
                print(row["path"])
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
