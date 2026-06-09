#!/usr/bin/env python3
import argparse
import statistics
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


def percentile(values, pct):
    if not values:
        return 0.0
    return values[round((pct / 100) * (len(values) - 1))]


def latest_result_dir(results, run_name):
    matches = sorted(p for p in results.iterdir() if p.is_dir() and p.name.endswith("-" + run_name))
    if not matches:
        raise FileNotFoundError(f"missing result directory for {run_name}")
    return matches[-1]


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
    if not values:
        raise ValueError(f"no successful loads in {path}")

    return {
        "runs": len(values) + failures,
        "failures": failures,
        "mean_ms": statistics.mean(values),
        "p50_ms": percentile(values, 50),
        "p90_ms": percentile(values, 90),
        "p99_ms": percentile(values, 99),
    }


def run_summary(results, run_name):
    return summarize(latest_result_dir(results, run_name))


def save_pdf(fig, out_dir, stem, pad_inches=0.02):
    path = out_dir / f"{stem}.pdf"
    fig.savefig(path, bbox_inches="tight", pad_inches=pad_inches)
    plt.close(fig)
    return path


def plot_policy_engine(results, out_dir):
    specs = [
        ("Control kernel\nunsigned", "baseline_unsigned", "#72B7B2"),
        ("Patched kernel\nno BPF_CHECK", "ima_no_rule_unsigned", "#4C78A8"),
        ("Measure identical\nunsigned", "ima_measure_identical_unsigned", "#F58518"),
    ]
    labels = [label for label, _, _ in specs]
    medians = [run_summary(results, run)["p50_ms"] for _, run, _ in specs]
    p99s = [run_summary(results, run)["p99_ms"] for _, run, _ in specs]
    colors = [color for _, _, color in specs]
    x = np.arange(len(specs))

    fig, ax = plt.subplots(figsize=(5.8, 2.1))
    ax.bar(x, medians, color=colors, width=0.62)
    ax.scatter(x, p99s, marker="_", s=120, color="black", linewidths=1.2, zorder=3)

    ax.set_ylabel("BPF_PROG_LOAD latency (ms)")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=9)
    ax.set_ylim(0, max(p99s) * 1.12)
    ax.grid(axis="y", linestyle=":", linewidth=0.7, alpha=0.7)
    return save_pdf(fig, out_dir, "policy_engine_overhead")


def plot_signed_delta(results, out_dir):
    pairs = [
        ("Control", "baseline_unsigned", "baseline_signed", "#72B7B2"),
        ("Bare metal\nno rule", "ima_no_rule_unsigned", "ima_no_rule_signed", "#4C78A8"),
        ("Bare metal\nmeasure identical", "ima_measure_identical_unsigned", "ima_measure_identical_signed", "#4C78A8"),
        ("VM\nno rule", "vm_ima_no_rule_unsigned", "vm_ima_no_rule_signed", "#F58518"),
        ("VM\nmeasure identical", "vm_ima_measure_identical_unsigned", "vm_ima_measure_identical_signed", "#F58518"),
    ]
    labels = [label for label, _, _, _ in pairs]
    deltas = []
    colors = []

    for _, unsigned_run, signed_run, color in pairs:
        unsigned = run_summary(results, unsigned_run)["p50_ms"]
        signed = run_summary(results, signed_run)["p50_ms"]
        deltas.append(signed - unsigned)
        colors.append(color)

    x = np.arange(len(pairs))
    fig, ax = plt.subplots(figsize=(7.0, 2.1))
    ax.bar(x, deltas, color=colors, width=0.62)

    ax.axhline(0.3, color="black", linestyle="--", linewidth=0.9, alpha=0.65)
    ax.set_ylabel("Signed minus unsigned p50 latency (ms)")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=8)
    ax.set_ylim(0, max(deltas) * 1.12)
    ax.grid(axis="y", linestyle=":", linewidth=0.7, alpha=0.7)
    return save_pdf(fig, out_dir, "signed_vs_unsigned_delta")


def plot_load_admission_combined(results, out_dir):
    policy_specs = [
        ("Control\nunsigned", "baseline_unsigned", "#72B7B2"),
        ("Patched\nno rule", "ima_no_rule_unsigned", "#4C78A8"),
        ("Measure\nidentical", "ima_measure_identical_unsigned", "#F58518"),
    ]
    signed_pairs = [
        ("Control", "baseline_unsigned", "baseline_signed", "#72B7B2"),
        ("Bare metal\nno rule", "ima_no_rule_unsigned", "ima_no_rule_signed", "#4C78A8"),
        ("Bare metal\nmeasure", "ima_measure_identical_unsigned", "ima_measure_identical_signed", "#4C78A8"),
        ("VM\nno rule", "vm_ima_no_rule_unsigned", "vm_ima_no_rule_signed", "#F58518"),
        ("VM\nmeasure", "vm_ima_measure_identical_unsigned", "vm_ima_measure_identical_signed", "#F58518"),
    ]

    fig, (ax_policy, ax_signed) = plt.subplots(
        1,
        2,
        figsize=(6.4, 2.0),
        constrained_layout=True,
        gridspec_kw={"width_ratios": [0.8, 1.35]},
    )

    labels = [label for label, _, _ in policy_specs]
    medians = [run_summary(results, run)["p50_ms"] for _, run, _ in policy_specs]
    p99s = [run_summary(results, run)["p99_ms"] for _, run, _ in policy_specs]
    colors = [color for _, _, color in policy_specs]
    x = np.arange(len(policy_specs))

    ax_policy.bar(x, medians, color=colors, width=0.62)
    ax_policy.scatter(x, p99s, marker="_", s=90, color="black", linewidths=1.1, zorder=3)
    ax_policy.set_title("(a) Policy path", fontsize=9, pad=2)
    ax_policy.set_ylabel("Latency (ms)", fontsize=8)
    ax_policy.set_xticks(x)
    ax_policy.set_xticklabels(labels, fontsize=7)
    ax_policy.set_ylim(0, max(p99s) * 1.12)
    ax_policy.tick_params(axis="y", labelsize=7)
    ax_policy.grid(axis="y", linestyle=":", linewidth=0.6, alpha=0.7)

    labels = [label for label, _, _, _ in signed_pairs]
    deltas = []
    colors = []
    for _, unsigned_run, signed_run, color in signed_pairs:
        unsigned = run_summary(results, unsigned_run)["p50_ms"]
        signed = run_summary(results, signed_run)["p50_ms"]
        deltas.append(signed - unsigned)
        colors.append(color)
    x = np.arange(len(signed_pairs))

    ax_signed.bar(x, deltas, color=colors, width=0.62)
    ax_signed.axhline(0.3, color="black", linestyle="--", linewidth=0.8, alpha=0.65)
    ax_signed.set_title("(b) Signed-load delta", fontsize=9, pad=2)
    ax_signed.set_ylabel("Delta p50 (ms)", fontsize=8)
    ax_signed.set_xticks(x)
    ax_signed.set_xticklabels(labels, fontsize=7)
    ax_signed.set_ylim(0, max(deltas) * 1.12)
    ax_signed.tick_params(axis="y", labelsize=7)
    ax_signed.grid(axis="y", linestyle=":", linewidth=0.6, alpha=0.7)

    return save_pdf(fig, out_dir, "load_admission_combined")


def write_measurement_table(results, out_dir):
    specs = [
        ("Bare metal", "identical unsigned", "ima_measure_identical_unsigned"),
        ("Bare metal", "unique unsigned", "ima_measure_unique_unsigned"),
        ("Bare metal", "identical signed", "ima_measure_identical_signed"),
        ("Bare metal", "unique signed", "ima_measure_unique_signed"),
        ("VM", "identical unsigned", "vm_ima_measure_identical_unsigned"),
        ("VM", "unique unsigned", "vm_ima_measure_unique_unsigned"),
        ("VM", "identical signed", "vm_ima_measure_identical_signed"),
        ("VM", "unique signed", "vm_ima_measure_unique_signed"),
    ]
    path = out_dir / "measurement_backend_table.tex"

    with path.open("w") as f:
        f.write("\\begin{tabular}{llrr}\n")
        f.write("\\toprule\n")
        f.write("Environment & Measured load & p50 (ms) & p99 (ms) \\\\\n")
        f.write("\\midrule\n")
        for environment, measured_load, run_name in specs:
            summary = run_summary(results, run_name)
            f.write(
                f"{environment} & {measured_load} & "
                f"{summary['p50_ms']:.3f} & {summary['p99_ms']:.3f} \\\\\n"
            )
        f.write("\\bottomrule\n")
        f.write("\\end{tabular}\n")

    return path


def main():
    parser = argparse.ArgumentParser(description="Generate selected exp_d load-admission figures.")
    parser.add_argument("results", nargs="?", default="results", help="results directory")
    parser.add_argument("--out", default="graphs", help="output directory")
    args = parser.parse_args()

    results = Path(args.results)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    outputs = [
        plot_policy_engine(results, out_dir),
        plot_signed_delta(results, out_dir),
        plot_load_admission_combined(results, out_dir),
        write_measurement_table(results, out_dir),
    ]
    for path in outputs:
        print(path)


if __name__ == "__main__":
    main()
