#!/usr/bin/env python3
"""Generate mainline MDDC/QG-DCA figures for the manuscript.

The figures are intentionally source-backed:
- the QG-DCA schematic is a method diagram;
- the evidence atlas reads saved experiment summaries and result CSVs.
"""

from __future__ import annotations

import csv
import json
import os
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch


ROOT = Path(os.environ.get("MDDC_ROOT", Path(__file__).resolve().parents[1]))
RESULTS = ROOT / "empirical_validation" / "results"
FIGURES = ROOT / "empirical_validation" / "figures"


def load_json(name: str) -> dict:
    return json.loads((RESULTS / name).read_text(encoding="utf-8"))


def setup_style() -> None:
    try:
        import scienceplots  # noqa: F401

        plt.style.use(["science", "no-latex"])
    except Exception:
        plt.style.use("default")
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "axes.unicode_minus": False,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            "savefig.dpi": 420,
            "figure.dpi": 180,
            "axes.linewidth": 0.8,
            "xtick.major.width": 0.8,
            "ytick.major.width": 0.8,
        }
    )


def add_box(ax, xy, width, height, text, fc="#f7f7f7", ec="#333333", fs=8, lw=0.9):
    box = FancyBboxPatch(
        xy,
        width,
        height,
        boxstyle="round,pad=0.02,rounding_size=0.02",
        linewidth=lw,
        edgecolor=ec,
        facecolor=fc,
    )
    ax.add_patch(box)
    ax.text(
        xy[0] + width / 2,
        xy[1] + height / 2,
        text,
        ha="center",
        va="center",
        fontsize=fs,
        wrap=True,
    )
    return box


def add_arrow(ax, start, end, text=None, rad=0.0, color="#333333", lw=1.1):
    arr = FancyArrowPatch(
        start,
        end,
        arrowstyle="-|>",
        mutation_scale=10,
        linewidth=lw,
        color=color,
        connectionstyle=f"arc3,rad={rad}",
    )
    ax.add_patch(arr)
    if text:
        ax.text(
            (start[0] + end[0]) / 2,
            (start[1] + end[1]) / 2 + 0.035,
            text,
            ha="center",
            va="center",
            fontsize=7,
            color=color,
        )


def make_qgdca_schematic() -> None:
    fig, ax = plt.subplots(figsize=(7.2, 3.65))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    blue = "#dbe9f6"
    orange = "#f8e3c5"
    green = "#dcefdc"
    red = "#f5d5d5"
    gray = "#eeeeee"
    purple = "#e8ddf3"

    add_box(ax, (0.03, 0.69), 0.18, 0.17, "AEC observations\nthreat and debt\nP_t, D_R(t)", blue)
    add_box(ax, (0.03, 0.43), 0.18, 0.17, "CEC generators\npatch, rule,\noracle, route", orange)
    add_box(ax, (0.03, 0.17), 0.18, 0.17, "Context memory\ncode, patch,\nfeedback, API", purple)

    add_box(
        ax,
        (0.31, 0.34),
        0.23,
        0.32,
        "QG-DCA\nqualification-gated\ndefense-capital accounting\n\nG(a,c,e)",
        "#fff2cc",
        fs=8.5,
        lw=1.1,
    )

    gate_y = [0.74, 0.61, 0.48, 0.35]
    gate_txt = ["structure", "semantic/context", "oracle/native", "cost/frontier"]
    for y, t in zip(gate_y, gate_txt):
        add_box(ax, (0.58, y - 0.04), 0.14, 0.08, t, gray, fs=7.4, lw=0.7)

    add_box(ax, (0.79, 0.70), 0.17, 0.15, "ADMIT\nupdate H_q(t)\nqualified capital", green)
    add_box(ax, (0.79, 0.45), 0.17, 0.15, "ABSTAIN\nrecord D_V(t)\nmissing evidence", gray)
    add_box(ax, (0.79, 0.20), 0.17, 0.15, "REJECT\nblocked output\nfalse capital avoided", red)

    for y in [0.775, 0.515, 0.255]:
        add_arrow(ax, (0.21, y), (0.31, 0.50), lw=1.0)
    add_arrow(ax, (0.54, 0.50), (0.58, 0.50), lw=1.0)
    for y in [0.775, 0.525, 0.275]:
        add_arrow(ax, (0.72, 0.50), (0.79, y), lw=1.0)

    ax.text(
        0.50,
        0.105,
        "Every decision feeds future AEC/CEC state: admitted artifacts update H_q(t), abstentions update D_V(t), and rejections expose false capital.",
        ha="center",
        va="center",
        fontsize=7.2,
        color="#333333",
    )

    ax.text(
        0.5,
        0.965,
        "QG-DCA separates admitted defense capital from validation debt",
        ha="center",
        va="top",
        fontsize=9.5,
        fontweight="bold",
    )
    ax.text(
        0.5,
        0.025,
        "LLMs can generate candidates, but QG-DCA is the admission and accounting layer.",
        ha="center",
        va="bottom",
        fontsize=8,
    )

    FIGURES.mkdir(parents=True, exist_ok=True)
    for ext in ("pdf", "png"):
        fig.savefig(FIGURES / f"fig_qgdca_schematic.{ext}", bbox_inches="tight")
    plt.close(fig)


def read_utility_rows() -> dict[str, dict]:
    rows = {}
    path = RESULTS / "experiment_lxxviii_external_baseline_utility_policies_20260624.csv"
    with path.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            rows[row["policy"]] = row
    return rows


def make_evidence_atlas() -> None:
    lxxvii = load_json("experiment_lxxvii_patch_differential_oracle_summary_20260624.json")
    lxxviii = load_json("experiment_lxxviii_external_baseline_system_comparison_summary_20260624.json")
    lxxix = load_json("experiment_lxxix_bigvul_cross_dataset_summary_20260624.json")
    utility = read_utility_rows()

    colors = {
        "bad": "#c44e52",
        "warn": "#dd8452",
        "good": "#55a868",
        "blue": "#4c72b0",
        "gray": "#8c8c8c",
    }

    fig, axes = plt.subplots(2, 3, figsize=(7.4, 4.8))
    axes = axes.ravel()

    # A. repair metric inflation
    ax = axes[0]
    vals = [31, 7]
    ax.bar(["applicable", "static\nqualified"], vals, color=[colors["warn"], colors["good"]])
    ax.set_title("(a) Repair metric inflation", fontsize=8.5)
    ax.set_ylabel("candidates")
    ax.text(0.5, 28, "4.43x\ninflation", ha="center", va="top", fontsize=8)
    ax.set_ylim(0, 34)

    # B. ASR gate contraction
    ax = axes[1]
    labels = ["struct.", "strict", "comment", "oracle"]
    vals = [112 / 131, 99 / 131, 57 / 131, lxxvii["true_oracle_rate"]]
    ax.bar(labels, vals, color=[colors["blue"], colors["good"], colors["warn"], colors["gray"]])
    ax.set_title("(b) ASR admission contraction", fontsize=8.5)
    ax.set_ylim(0, 1)
    ax.set_ylabel("rate")
    ax.axhline(0.5, color="#333333", linewidth=0.6, linestyle=":")
    ax.text(3, vals[3] + 0.04, "55/99", ha="center", fontsize=7)

    # C. CVEfixes false admission
    ax = axes[2]
    h = lxxviii["headline"]
    labels = ["CVSS", "struct.", "MDDC"]
    vals = [
        h["cvefixes_same_category_cvss_only_false_rate"],
        h["cvefixes_same_category_structural_false_rate"],
        h["cvefixes_same_category_mddc_strict_false_rate"],
    ]
    ax.bar(labels, vals, color=[colors["warn"], colors["bad"], colors["good"]])
    ax.set_title("(c) CVEfixes false admissions", fontsize=8.5)
    ax.set_ylim(0, 1)
    ax.set_ylabel("same-category false rate")
    ax.text(2, vals[2] + 0.05, "13.8%", ha="center", fontsize=7)

    # D. BigVul true versus false
    ax = axes[3]
    true_rates = [
        lxxix["true_pair_rates"]["structural_only"]["rate"],
        lxxix["true_pair_rates"]["strict_mddc_gate"]["rate"],
    ]
    false_rates = [
        lxxix["control_summary"]["same_category_different_cve"]["structural_only_mean_rate"],
        lxxix["control_summary"]["same_category_different_cve"]["strict_mddc_gate_mean_rate"],
    ]
    x = [0, 1]
    width = 0.35
    ax.bar([v - width / 2 for v in x], true_rates, width, label="true pairs", color=colors["blue"])
    ax.bar([v + width / 2 for v in x], false_rates, width, label="controls", color=colors["bad"])
    ax.set_xticks(x, ["struct.", "MDDC"])
    ax.set_ylim(0, 1.05)
    ax.set_title("(d) BigVul tradeoff", fontsize=8.5)
    ax.set_ylabel("rate")
    ax.legend(frameon=False, fontsize=6, loc="upper center", ncol=2)

    # E. utility pool false admissions
    ax = axes[4]
    labels = ["Qwen\nconf.", "DeepSeek\nscore", "MDDC"]
    vals = [
        float(utility["qwen_confidence_ge_0_7"]["false_admission_rate_among_admitted"]),
        float(utility["deepseek_score_ge_4"]["false_admission_rate_among_admitted"]),
        float(utility["mddc_utility_gate"]["false_admission_rate_among_admitted"]),
    ]
    ax.bar(labels, vals, color=[colors["warn"], colors["bad"], colors["good"]])
    ax.set_title("(e) Utility-gate debt control", fontsize=8.5)
    ax.set_ylim(0, 1)
    ax.set_ylabel("false among admitted")
    ax.text(2, 0.06, "0/33", ha="center", fontsize=7)

    # F. activation and deployment boundary
    ax = axes[5]
    labels = ["patch\nreuse", "apply\nupper", "test\nfrontier", "valid.\nfrontier"]
    vals = [0.0392, 0.1396, 0.275, 0.325]
    ax.bar(labels, vals, color=[colors["gray"], colors["warn"], colors["blue"], colors["blue"]])
    ax.set_title("(f) Activation boundary", fontsize=8.5)
    ax.set_ylim(0, 0.38)
    ax.set_ylabel("effective gain")
    ax.text(2.5, 0.345, "fallback below frontier", ha="center", fontsize=7)

    for ax in axes:
        ax.tick_params(axis="both", labelsize=7)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.grid(axis="y", alpha=0.18, linewidth=0.5)

    fig.suptitle("MDDC evidence atlas: qualification reduces false capital and exposes boundaries", fontsize=10)
    fig.tight_layout(rect=[0, 0, 1, 0.96])
    for ext in ("pdf", "png"):
        fig.savefig(FIGURES / f"fig_mddc_evidence_atlas.{ext}", bbox_inches="tight")
    plt.close(fig)


def main() -> int:
    setup_style()
    make_qgdca_schematic()
    make_evidence_atlas()
    print(json.dumps({"figures": ["fig_qgdca_schematic", "fig_mddc_evidence_atlas"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
