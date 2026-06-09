#!/usr/bin/env python3
import argparse
import csv
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


def result_dir(results, label):
    matches = sorted(p for p in results.iterdir() if p.is_dir() and p.name.endswith("-" + label))
    if not matches:
        raise FileNotFoundError(f"missing result directory for {label}")
    return matches[-1]


def read_purge(results, label):
    path = result_dir(results, label) / "purge.tsv"
    with path.open() as f:
        reader = csv.DictReader(f, delimiter="\t")
        row = next(reader)
    return {key: int(value) if key not in {"load_ms", "blacklist_ms", "reappraise_ms"} else float(value)
            for key, value in row.items()}


def save_pdf(fig, out_dir, stem):
    path = out_dir / f"{stem}.pdf"
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    return path


def plot_reference_fanout(results, out_dir):
    series = [
        ("bpffs pins", [
            (1, "1progs-pins1-fdh0x1-pfdh0-tail0-links0-lfdh0-linkpins0-lph0"),
            (10, "1progs-pins10-fdh0x1-pfdh0-tail0-links0-lfdh0-linkpins0-lph0"),
            (100, "1progs-pins100-fdh0x1-pfdh0-tail0-links0-lfdh0-linkpins0-lph0"),
            (1000, "1progs-pins1000-fdh0x1-pfdh0-tail0-links0-lfdh0-linkpins0-lph0"),
        ], "#4C78A8", "o"),
        ("program FDs", [
            (1, "1progs-pins0-fdh1x1-pfdh0-tail0-links0-lfdh0-linkpins0-lph0"),
            (10, "1progs-pins0-fdh1x10-pfdh0-tail0-links0-lfdh0-linkpins0-lph0"),
            (100, "1progs-pins0-fdh1x100-pfdh0-tail0-links0-lfdh0-linkpins0-lph0"),
            (1000, "1progs-pins0-fdh1x1000-pfdh0-tail0-links0-lfdh0-linkpins0-lph0"),
        ], "#F58518", "s"),
        ("tail-call entries", [
            (1, "1progs-pins0-fdh0x1-pfdh0-tail1-links0-lfdh0-linkpins0-lph0"),
            (10, "1progs-pins0-fdh0x1-pfdh0-tail10-links0-lfdh0-linkpins0-lph0"),
            (100, "1progs-pins0-fdh0x1-pfdh0-tail100-links0-lfdh0-linkpins0-lph0"),
            (1000, "1progs-pins0-fdh0x1-pfdh0-tail1000-links0-lfdh0-linkpins0-lph0"),
        ], "#54A24B", "^"),
    ]

    link_series = [
        ("unpinned links", [
            (1, "1progs-pins0-fdh0x1-pfdh0-tail0-links1-lfdh0-linkpins0-lph0"),
            (5, "1progs-pins0-fdh0x1-pfdh0-tail0-links5-lfdh0-linkpins0-lph0"),
            (10, "1progs-pins0-fdh0x1-pfdh0-tail0-links10-lfdh0-linkpins0-lph0"),
            (18, "1progs-pins0-fdh0x1-pfdh0-tail0-links18-lfdh0-linkpins0-lph0"),
        ], "#B279A2", "D"),
        ("pinned links", [
            (1, "1progs-pins0-fdh0x1-pfdh0-tail0-links0-lfdh0-linkpins1-lph0"),
            (5, "1progs-pins0-fdh0x1-pfdh0-tail0-links0-lfdh0-linkpins5-lph0"),
            (10, "1progs-pins0-fdh0x1-pfdh0-tail0-links0-lfdh0-linkpins10-lph0"),
            (18, "1progs-pins0-fdh0x1-pfdh0-tail0-links0-lfdh0-linkpins18-lph0"),
        ], "#E45756", "v"),
    ]

    fig, axes = plt.subplots(1, 2, figsize=(9.5, 3.6))
    x_labels = [1, 10, 100, 1000]
    x_positions = np.arange(len(x_labels))
    for name, points, color, marker in series:
        xs = np.arange(len(points))
        ys = [read_purge(results, label)["reappraise_ms"] for _, label in points]
        axes[0].plot(xs, ys, marker=marker, linewidth=1.8, markersize=5.5, color=color, label=name)
        for x, y in zip(xs, ys):
            axes[0].text(x, y + 0.9, f"{y:.1f}", ha="center", va="bottom", fontsize=7)

    axes[0].set_xticks(x_positions)
    axes[0].set_xticklabels([str(x) for x in x_labels])
    axes[0].set_xlabel("References to one revoked program")
    axes[0].set_ylabel("Reappraisal latency (ms)")
    axes[0].set_title("Passive reference fanout")
    axes[0].set_ylim(0, 30)
    axes[0].grid(axis="y", linestyle=":", linewidth=0.7, alpha=0.7)
    axes[0].legend(loc="upper center", bbox_to_anchor=(0.5, -0.22), ncol=3, frameon=False, fontsize=8)

    for name, points, color, marker in link_series:
        xs = [count for count, _ in points]
        ys = [read_purge(results, label)["reappraise_ms"] for _, label in points]
        axes[1].plot(xs, ys, marker=marker, linewidth=1.8, markersize=5.5, color=color, label=name)
        for x, y in zip(xs, ys):
            axes[1].text(x, y + 0.9, f"{y:.1f}", ha="center", va="bottom", fontsize=7)

    axes[1].set_xlabel("Links to one revoked program")
    axes[1].set_ylabel("Reappraisal latency (ms)")
    axes[1].set_title("Link fanout")
    axes[1].set_xticks([1, 5, 10, 18])
    axes[1].set_ylim(0, 32)
    axes[1].grid(axis="y", linestyle=":", linewidth=0.7, alpha=0.7)
    axes[1].legend(loc="upper center", bbox_to_anchor=(0.5, -0.22), ncol=2, frameon=False, fontsize=8)

    fig.subplots_adjust(wspace=0.34, bottom=0.28)
    return save_pdf(fig, out_dir, "purge_reference_fanout")


def plot_program_scaling(results, out_dir):
    program_points = [
        (1, "1progs-pins1-fdh0x1-pfdh0-tail0-links0-lfdh0-linkpins0-lph0"),
        (10, "10progs-pins1-fdh0x1-pfdh0-tail0-links0-lfdh0-linkpins0-lph0"),
        (50, "50progs-pins1-fdh0x1-pfdh0-tail0-links0-lfdh0-linkpins0-lph0"),
        (100, "100progs-pins1-fdh0x1-pfdh0-tail0-links0-lfdh0-linkpins0-lph0"),
    ]
    fig, ax = plt.subplots(figsize=(5.7, 3.6))

    xs = [count for count, _ in program_points]
    ys = [read_purge(results, label)["reappraise_ms"] for _, label in program_points]
    ax.plot(xs, ys, marker="o", linewidth=1.8, markersize=5.5, color="#4C78A8")
    for x, y in zip(xs, ys):
        label = f"{y / 1000:.3f} s" if y >= 1000 else f"{y:.0f} ms"
        ax.text(x, y + 45, label, ha="center", va="bottom", fontsize=8)

    ax.set_xlabel("Revoked programs")
    ax.set_ylabel("Reappraisal latency (ms)")
    ax.set_xticks(xs)
    ax.set_ylim(0, max(ys) * 1.22)
    ax.grid(axis="both", linestyle=":", linewidth=0.7, alpha=0.7)
    return save_pdf(fig, out_dir, "purge_program_scaling")


def plot_scaling_summary(results, out_dir):
    program_points = [
        (1, "1progs-pins1-fdh0x1-pfdh0-tail0-links0-lfdh0-linkpins0-lph0"),
        (10, "10progs-pins1-fdh0x1-pfdh0-tail0-links0-lfdh0-linkpins0-lph0"),
        (50, "50progs-pins1-fdh0x1-pfdh0-tail0-links0-lfdh0-linkpins0-lph0"),
        (100, "100progs-pins1-fdh0x1-pfdh0-tail0-links0-lfdh0-linkpins0-lph0"),
    ]
    fanout_series = [
        ("bpffs pins", [
            "1progs-pins1-fdh0x1-pfdh0-tail0-links0-lfdh0-linkpins0-lph0",
            "1progs-pins10-fdh0x1-pfdh0-tail0-links0-lfdh0-linkpins0-lph0",
            "1progs-pins100-fdh0x1-pfdh0-tail0-links0-lfdh0-linkpins0-lph0",
            "1progs-pins1000-fdh0x1-pfdh0-tail0-links0-lfdh0-linkpins0-lph0",
        ], "#4C78A8", "o"),
        ("program FDs", [
            "1progs-pins0-fdh1x1-pfdh0-tail0-links0-lfdh0-linkpins0-lph0",
            "1progs-pins0-fdh1x10-pfdh0-tail0-links0-lfdh0-linkpins0-lph0",
            "1progs-pins0-fdh1x100-pfdh0-tail0-links0-lfdh0-linkpins0-lph0",
            "1progs-pins0-fdh1x1000-pfdh0-tail0-links0-lfdh0-linkpins0-lph0",
        ], "#F58518", "s"),
        ("tail-call entries", [
            "1progs-pins0-fdh0x1-pfdh0-tail1-links0-lfdh0-linkpins0-lph0",
            "1progs-pins0-fdh0x1-pfdh0-tail10-links0-lfdh0-linkpins0-lph0",
            "1progs-pins0-fdh0x1-pfdh0-tail100-links0-lfdh0-linkpins0-lph0",
            "1progs-pins0-fdh0x1-pfdh0-tail1000-links0-lfdh0-linkpins0-lph0",
        ], "#54A24B", "^"),
        ("unpinned links", [
            "1progs-pins0-fdh0x1-pfdh0-tail0-links1-lfdh0-linkpins0-lph0",
            "1progs-pins0-fdh0x1-pfdh0-tail0-links5-lfdh0-linkpins0-lph0",
            "1progs-pins0-fdh0x1-pfdh0-tail0-links10-lfdh0-linkpins0-lph0",
            "1progs-pins0-fdh0x1-pfdh0-tail0-links18-lfdh0-linkpins0-lph0",
        ], "#B279A2", "D"),
        ("pinned links", [
            "1progs-pins0-fdh0x1-pfdh0-tail0-links0-lfdh0-linkpins1-lph0",
            "1progs-pins0-fdh0x1-pfdh0-tail0-links0-lfdh0-linkpins5-lph0",
            "1progs-pins0-fdh0x1-pfdh0-tail0-links0-lfdh0-linkpins10-lph0",
            "1progs-pins0-fdh0x1-pfdh0-tail0-links0-lfdh0-linkpins18-lph0",
        ], "#E45756", "v"),
    ]

    fig, axes = plt.subplots(1, 2, figsize=(9.8, 3.7), gridspec_kw={"width_ratios": [1.05, 1.35]})

    prog_xs = [count for count, _ in program_points]
    prog_ys = [read_purge(results, label)["reappraise_ms"] for _, label in program_points]
    axes[0].plot(prog_xs, prog_ys, marker="o", linewidth=1.8, markersize=5.5, color="#4C78A8")
    for x, y in zip(prog_xs, prog_ys):
        label = f"{y / 1000:.3f} s" if y >= 1000 else f"{y:.0f} ms"
        axes[0].text(x, y + 45, label, ha="center", va="bottom", fontsize=8)
    axes[0].set_xlabel("Revoked programs")
    axes[0].set_ylabel("Reappraisal latency (ms)")
    axes[0].set_title("Per-program purge cost")
    axes[0].set_xticks(prog_xs)
    axes[0].set_ylim(0, max(prog_ys) * 1.22)
    axes[0].grid(axis="both", linestyle=":", linewidth=0.7, alpha=0.7)

    fanout_xs = np.arange(4)
    for name, labels, color, marker in fanout_series:
        ys = [read_purge(results, label)["reappraise_ms"] for label in labels]
        axes[1].plot(fanout_xs, ys, marker=marker, linewidth=1.7, markersize=5.0, color=color, label=name)
    axes[1].set_xlabel("References to one revoked program")
    axes[1].set_ylabel("Reappraisal latency (ms)")
    axes[1].set_title("More references to one program")
    axes[1].set_xticks(fanout_xs)
    axes[1].set_xticklabels(["1", "10/5", "100/10", "1000/18"])
    axes[1].set_ylim(0, 36)
    axes[1].grid(axis="y", linestyle=":", linewidth=0.7, alpha=0.7)
    axes[1].legend(loc="upper center", bbox_to_anchor=(0.5, -0.22), ncol=3, frameon=False, fontsize=8)

    fig.subplots_adjust(wspace=0.36, bottom=0.30)
    return save_pdf(fig, out_dir, "purge_scaling_summary")


def main():
    parser = argparse.ArgumentParser(description="Generate exp_e purge latency figures.")
    parser.add_argument("results", nargs="?", default="results", help="results directory")
    parser.add_argument("--out", default="graphs", help="output directory")
    args = parser.parse_args()

    results = Path(args.results)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    outputs = [
        plot_reference_fanout(results, out_dir),
        plot_program_scaling(results, out_dir),
    ]
    for path in outputs:
        print(path)


if __name__ == "__main__":
    main()
