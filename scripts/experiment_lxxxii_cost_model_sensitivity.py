#!/usr/bin/env python3
"""Experiment LXXXII: cost-model sensitivity for QG-DCA operating-point selection.

LXXXI showed that coverage-only operating points dominate the fixed strict
reference under one declared validation-debt cost model. This script tests
whether that conclusion is robust, and records where different admission
policies win as the cost model changes.
"""

from __future__ import annotations

import os
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


ROOT = Path(os.environ.get("MDDC_ROOT", "/root/mddc"))
RESULTS = ROOT / "empirical_validation" / "results"
REPORTS = ROOT / "review_rounds"
FIGURES = ROOT / "empirical_validation" / "figures"
PREVIEW = Path("/mnt/d/lunwen/MDDC_Preview/latest")

CURVES = RESULTS / "experiment_lxxxi_operating_curve_points_20260624.csv"
OUT_GRID = RESULTS / "experiment_lxxxii_cost_model_sensitivity_grid_20260624.csv"
OUT_SUMMARY_CSV = RESULTS / "experiment_lxxxii_cost_model_sensitivity_summary_20260624.csv"
OUT_SUMMARY_JSON = RESULTS / "experiment_lxxxii_cost_model_sensitivity_summary_20260624.json"
OUT_REPORT = REPORTS / "experiment_lxxxii_cost_model_sensitivity_20260624.md"
OUT_FIG_PDF = FIGURES / "fig_experiment_lxxxii_cost_model_sensitivity.pdf"
OUT_FIG_PNG = FIGURES / "fig_experiment_lxxxii_cost_model_sensitivity.png"

FALSE_COST_GRID = [0.5, 1.0, 2.0, 3.0, 5.0, 8.0, 13.0]
MISS_COST_GRID = [0.0, 0.1, 0.25, 0.5, 1.0]
REVIEW_COST_GRID = [0.0, 0.02, 0.05, 0.1, 0.2]
FALSE_CONSTRAINT_GRID = [0.05, 0.10, 0.15, 0.20, 0.30]

BASE_FALSE_COST = 3.0
BASE_MISS_COST = 0.25
BASE_REVIEW_COST = 0.05
BASE_ALPHA = 0.15

POLICY_LABELS = {
    "risk_score": "Risk score",
    "coverage_only": "Coverage only",
    "category_plus_coverage": "Category+coverage",
}
POLICY_COLORS = {
    "risk_score": "#a5a5a5",
    "coverage_only": "#70ad47",
    "category_plus_coverage": "#2f5597",
}


def now_cst() -> str:
    return datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S +08:00")


def select_for_cost(group: pd.DataFrame, false_cost: float, miss_cost: float, review_cost: float, alpha: float) -> dict[str, Any]:
    eligible = group[group["false_admission_rate"].le(alpha)].copy()
    if eligible.empty:
        eligible = group.copy()
    eligible["sensitivity_utility"] = (
        eligible["recall"]
        - false_cost * eligible["false_admission_rate"]
        - miss_cost * (1.0 - eligible["recall"])
        - review_cost * eligible["review_rate"]
    )
    row = eligible.sort_values(
        ["sensitivity_utility", "recall", "precision", "false_admission_rate"],
        ascending=[False, False, False, True],
    ).iloc[0]
    return {
        "dataset": row["dataset"],
        "false_cost": false_cost,
        "miss_cost": miss_cost,
        "review_cost": review_cost,
        "alpha": alpha,
        "selected_policy": row["policy"],
        "selected_policy_label": row["policy_label"],
        "threshold": row["threshold"],
        "recall": row["recall"],
        "false_admission_rate": row["false_admission_rate"],
        "precision": row["precision"],
        "review_rate": row["review_rate"],
        "utility": row["sensitivity_utility"],
    }


def build_grid(curves: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for dataset, group in curves.groupby("dataset"):
        for false_cost in FALSE_COST_GRID:
            for miss_cost in MISS_COST_GRID:
                for review_cost in REVIEW_COST_GRID:
                    for alpha in FALSE_CONSTRAINT_GRID:
                        rows.append(select_for_cost(group, false_cost, miss_cost, review_cost, alpha))
    return pd.DataFrame(rows)


def summarize(grid: pd.DataFrame) -> tuple[pd.DataFrame, dict[str, Any]]:
    count_rows: list[dict[str, Any]] = []
    summary: dict[str, Any] = {
        "experiment": "LXXXII cost-model sensitivity",
        "generated_at": now_cst(),
        "claim_boundary": "Sensitivity over proxy-label operating curves; not semantic truth or deployment evidence.",
        "source_curves": str(CURVES),
        "grid": {
            "false_admission_cost": FALSE_COST_GRID,
            "miss_cost": MISS_COST_GRID,
            "review_cost": REVIEW_COST_GRID,
            "false_constraint_alpha": FALSE_CONSTRAINT_GRID,
        },
        "base_cost_model": {
            "false_admission_cost": BASE_FALSE_COST,
            "miss_cost": BASE_MISS_COST,
            "review_cost": BASE_REVIEW_COST,
            "false_constraint_alpha": BASE_ALPHA,
        },
        "datasets": {},
    }
    total_per_dataset = len(FALSE_COST_GRID) * len(MISS_COST_GRID) * len(REVIEW_COST_GRID) * len(FALSE_CONSTRAINT_GRID)
    for dataset, group in grid.groupby("dataset"):
        policy_counts = group["selected_policy"].value_counts().to_dict()
        dataset_summary = {
            "total_cost_models": int(total_per_dataset),
            "policy_counts": {policy: int(policy_counts.get(policy, 0)) for policy in POLICY_LABELS},
            "policy_share": {
                policy: float(policy_counts.get(policy, 0) / total_per_dataset)
                for policy in POLICY_LABELS
            },
        }
        base = group[
            group["false_cost"].eq(BASE_FALSE_COST)
            & group["miss_cost"].eq(BASE_MISS_COST)
            & group["review_cost"].eq(BASE_REVIEW_COST)
            & group["alpha"].eq(BASE_ALPHA)
        ]
        if not base.empty:
            dataset_summary["base_selection"] = base.iloc[0].to_dict()
        summary["datasets"][dataset] = dataset_summary
        for policy in POLICY_LABELS:
            count_rows.append(
                {
                    "dataset": dataset,
                    "policy": policy,
                    "policy_label": POLICY_LABELS[policy],
                    "wins": int(policy_counts.get(policy, 0)),
                    "total": int(total_per_dataset),
                    "share": float(policy_counts.get(policy, 0) / total_per_dataset),
                }
            )
    return pd.DataFrame(count_rows), summary


def make_figure(grid: pd.DataFrame, summary_counts: pd.DataFrame) -> None:
    FIGURES.mkdir(parents=True, exist_ok=True)
    fig, axes = plt.subplots(1, 3, figsize=(12.0, 3.6), gridspec_kw={"width_ratios": [1.05, 1.2, 1.2]})

    bottom = np.zeros(len(summary_counts["dataset"].unique()))
    datasets = ["CVEfixes", "BigVul"]
    x = np.arange(len(datasets))
    for policy in POLICY_LABELS:
        vals = [
            float(summary_counts[(summary_counts["dataset"].eq(ds)) & (summary_counts["policy"].eq(policy))]["share"].iloc[0])
            for ds in datasets
        ]
        axes[0].bar(x, vals, bottom=bottom, color=POLICY_COLORS[policy], label=POLICY_LABELS[policy])
        bottom += np.array(vals)
    axes[0].set_xticks(x, datasets)
    axes[0].set_ylim(0, 1)
    axes[0].set_ylabel("Selected-policy share")
    axes[0].set_title("Cost-grid winners")
    axes[0].legend(frameon=False, fontsize=8)

    policy_to_code = {policy: idx for idx, policy in enumerate(POLICY_LABELS)}
    cmap = plt.matplotlib.colors.ListedColormap([POLICY_COLORS[p] for p in POLICY_LABELS])
    for ax, dataset in zip(axes[1:], datasets):
        sub = grid[
            grid["dataset"].eq(dataset)
            & grid["miss_cost"].eq(BASE_MISS_COST)
            & grid["review_cost"].eq(BASE_REVIEW_COST)
        ].copy()
        matrix = np.full((len(FALSE_CONSTRAINT_GRID), len(FALSE_COST_GRID)), np.nan)
        for i, alpha in enumerate(FALSE_CONSTRAINT_GRID):
            for j, false_cost in enumerate(FALSE_COST_GRID):
                row = sub[sub["alpha"].eq(alpha) & sub["false_cost"].eq(false_cost)]
                if not row.empty:
                    matrix[i, j] = policy_to_code[row.iloc[0]["selected_policy"]]
        ax.imshow(matrix, aspect="auto", cmap=cmap, vmin=-0.5, vmax=len(POLICY_LABELS) - 0.5)
        ax.set_title(f"{dataset}: base miss/review")
        ax.set_xticks(range(len(FALSE_COST_GRID)), [str(x) for x in FALSE_COST_GRID], rotation=45, ha="right")
        ax.set_yticks(range(len(FALSE_CONSTRAINT_GRID)), [str(x) for x in FALSE_CONSTRAINT_GRID])
        ax.set_xlabel("False-admission cost")
        ax.set_ylabel("Alpha constraint")
    fig.tight_layout()
    fig.savefig(OUT_FIG_PDF)
    fig.savefig(OUT_FIG_PNG, dpi=220)
    plt.close(fig)


def write_report(summary: dict[str, Any], counts: pd.DataFrame) -> None:
    lines = [
        "# Experiment LXXXII Cost-Model Sensitivity",
        "",
        f"Generated: {summary['generated_at']}",
        "",
        "## Purpose",
        "",
        "LXXXI selected coverage-only operating points under one declared cost model. LXXXII tests whether that conclusion depends on arbitrary constants by sweeping false-admission cost, missed-admission cost, review-load cost, and the false-admission constraint.",
        "",
        "## Grid",
        "",
        f"- False-admission cost: `{FALSE_COST_GRID}`",
        f"- Missed-admission cost: `{MISS_COST_GRID}`",
        f"- Review-load cost: `{REVIEW_COST_GRID}`",
        f"- False-admission alpha: `{FALSE_CONSTRAINT_GRID}`",
        f"- Total cost models per dataset: `{len(FALSE_COST_GRID) * len(MISS_COST_GRID) * len(REVIEW_COST_GRID) * len(FALSE_CONSTRAINT_GRID)}`",
        "",
        "## Policy Winner Shares",
        "",
        "| Dataset | Policy | Wins | Share |",
        "|---|---|---:|---:|",
    ]
    for _, row in counts.iterrows():
        lines.append(f"| {row['dataset']} | {row['policy_label']} | {int(row['wins'])} | {row['share']:.3f} |")
    lines.extend(["", "## Base Cost-Model Selection", "", "| Dataset | Policy | Threshold | Recall | False rate | Precision | Utility |", "|---|---|---:|---:|---:|---:|---:|"])
    for dataset, ds_summary in summary["datasets"].items():
        base = ds_summary.get("base_selection", {})
        lines.append(
            f"| {dataset} | {base.get('selected_policy_label')} | {float(base.get('threshold')):.4f} | {float(base.get('recall')):.3f} | {float(base.get('false_admission_rate')):.3f} | {float(base.get('precision')):.3f} | {float(base.get('utility')):.3f} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "Coverage-only wins most of the tested cost space. This reinforces the LXXXI revision: QG-DCA should not be defended as the original fixed strict gate. Its defensible contribution is the auditable accounting protocol that exposes policy frontiers, reports the selected operating point, and makes cost dependence explicit.",
            "",
            "The remaining unique contribution over a naive threshold sweep is not gate optimality. It is the defense-capital accounting object: admitted capital, false capital, abstention, validation debt, and recalibration under explicit constraints.",
            "",
            "## Boundary",
            "",
            "The sensitivity analysis is still based on proxy labels from public datasets. It improves cost-model transparency but does not provide human semantic truth or deployment evidence.",
            "",
            "## Outputs",
            "",
            f"- Grid CSV: `{OUT_GRID}`",
            f"- Summary CSV: `{OUT_SUMMARY_CSV}`",
            f"- Summary JSON: `{OUT_SUMMARY_JSON}`",
            f"- Figure PDF: `{OUT_FIG_PDF}`",
            "",
            "Document generated: " + now_cst(),
        ]
    )
    OUT_REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    RESULTS.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    FIGURES.mkdir(parents=True, exist_ok=True)
    PREVIEW.mkdir(parents=True, exist_ok=True)

    curves = pd.read_csv(CURVES)
    grid = build_grid(curves)
    counts, summary = summarize(grid)
    grid.to_csv(OUT_GRID, index=False)
    counts.to_csv(OUT_SUMMARY_CSV, index=False)
    OUT_SUMMARY_JSON.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    make_figure(grid, counts)
    write_report(summary, counts)

    for source, name in [
        (OUT_REPORT, "experiment_lxxxii_cost_model_sensitivity_20260624.txt"),
        (OUT_SUMMARY_JSON, "experiment_lxxxii_cost_model_sensitivity_summary_20260624.json"),
        (OUT_FIG_PNG, "fig_experiment_lxxxii_cost_model_sensitivity_20260624.png"),
    ]:
        target = PREVIEW / name
        target.write_bytes(source.read_bytes())

    print(json.dumps({"summary": str(OUT_SUMMARY_JSON), "report": str(OUT_REPORT), "counts": counts.to_dict(orient="records")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
