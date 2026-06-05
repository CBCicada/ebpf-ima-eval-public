#!/usr/bin/env python3
import argparse
import statistics
from pathlib import Path


def percentile(values, pct):
    if not values:
        return 0.0
    return values[round((pct / 100) * (len(values) - 1))]


def result_dirs(path):
    if (path / "load.tsv").exists():
        return [path]
    return sorted(p for p in path.iterdir() if (p / "load.tsv").exists())


def summarize(path):
    values = []
    failures = 0

    with (path / "load.tsv").open() as f:
        for line in f:
            _, ms, rc, _ = line.split()
            if int(rc) == 0:
                values.append(float(ms))
            else:
                failures += 1

    values.sort()
    print(path.name)
    print(f"  runs: {len(values) + failures}")
    print(f"  failures: {failures}")
    print(f"  mean_ms: {statistics.mean(values) if values else 0:.6f}")
    print(f"  p50_ms: {percentile(values, 50):.6f}")
    print(f"  p90_ms: {percentile(values, 90):.6f}")
    print(f"  p99_ms: {percentile(values, 99):.6f}")


def main():
    parser = argparse.ArgumentParser(description="Summarize exp_load_perf load.tsv files.")
    parser.add_argument("path", help="a result directory or results/")
    args = parser.parse_args()

    for path in result_dirs(Path(args.path)):
        summarize(path)


if __name__ == "__main__":
    main()
