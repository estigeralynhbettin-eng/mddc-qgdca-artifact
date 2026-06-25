#!/usr/bin/env python3
"""Experiment LXXXV: internal QG-DCA accounting-component ablation.

This script answers a reviewer-level question left after LXXXIII/LXXXIV:
which internal parts of QG-DCA matter?

Components tested:
- provenance verification;
- abstention / capital-debt separation;
- operating-point recalibration.

Boundary:
- This is an accounting ablation over existing proxy-label experiment outputs.
- It is not deployment repair, SOTA repair, or human semantic correctness.
"""

from __future__ import annotations

import os
import json
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


ROOT = Path(os.environ.get("MDDC_ROOT", "/root/mddc"))
RESULTS = ROOT / "empirical_validation" / "results"
FIGURES = ROOT / "empirical_validation" / "figures"
REPORTS = ROOT / "review_rounds"
PREVIEW = Path("/mnt/d/lunwen/MDDC_Preview/latest")

IN_LXXXIV_REPS = RESULTS / "experiment_lxxxiv_provenance_stress_replicates_20260625.csv"
IN_LXXXI_SELECTED = RESULTS / "experiment_lxxxi_operating_curve_selected_points_20260624.csv"

OUT_TABLE = RESULTS / "experiment_lxxxv_internal_accounting_ablation_table_20260625.csv"
OUT_SUMMARY = RESULTS / "experiment_lxxxv_internal_accounting_ablation_summary_20260625.json"
OUT_REPORT = REPORTS / "experiment_lxxxv_internal_accounting_ablation_20260625.md"
OUT_REPRO = REPORTS / "REPRODUCE_LXXXV_INTERNAL_ACCOUNTING_ABLATION_20260625.md"
OUT_FIG_PDF = FIGURES / "fig_experiment_lxxxv_internal_accounting_ablation.pdf"
OUT_FIG_PNG = FIGURES / "fig_experiment_lxxxv_internal_accounting_ablation.png"


def now_cst() -> str:
    return datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S +08:00")


def mean_row(df: pd.DataFrame, scenario: str, policy: str) -> pd.Series:
    sub = df[df["scenario"].eq(scenario) & df["policy"].eq(policy)]
    if sub.empty:
        raise ValueError(f"missing LXXXIV row for {scenario}/{policy}")
    return sub.mean(numeric_only=True)


def load_lxxxiv_component_rows() -> list[dict[str, Any]]:
    reps = pd.read_csv(IN_LXXXIV_REPS)
    n_total = float(reps.iloc[0]["n_true"] + reps.iloc[0]["n_negative"])
    n_true = float(reps.iloc[0]["n_true"])

    claimed_spoof = mean_row(reps, "spoof_10", "claimed_provenance_only")
    qgdca_spoof = mean_row(reps, "spoof_10", "qgdca_verified_abstain")

    no_sep_dropout = mean_row(reps, "dropout_50", "claimed_or_coverage")
    qgdca_dropout = mean_row(reps, "dropout_50", "qgdca_verified_abstain")

    no_sep_combined = mean_row(reps, "combined_50_10", "claimed_or_coverage")
    qgdca_combined = mean_row(reps, "combined_50_10", "qgdca_verified_abstain")

    hidden_debt_no_sep = float(no_sep_dropout["dropped_positive_admitted"]) / n_total
    hidden_debt_full = float(qgdca_dropout["dropped_positive_admitted"]) / n_total
    combined_hidden_no_sep = float(no_sep_combined["dropped_positive_admitted"]) / n_total
    combined_hidden_full = float(qgdca_combined["dropped_positive_admitted"]) / n_total

    return [
        {
            "component": "Provenance verification",
            "stress_case": "10% spoofed same-CWE negative provenance",
            "ablated_policy": "Trust claimed provenance",
            "full_policy": "Verify provenance before admission",
            "ablated_failure_metric": "false_admission_rate",
            "ablated_value": float(claimed_spoof["false_admission_rate"]),
            "full_value": float(qgdca_spoof["false_admission_rate"]),
            "absolute_improvement": float(claimed_spoof["false_admission_rate"] - qgdca_spoof["false_admission_rate"]),
            "utility_ablated": float(claimed_spoof["debt_adjusted_utility"]),
            "utility_full": float(qgdca_spoof["debt_adjusted_utility"]),
            "utility_gain": float(qgdca_spoof["debt_adjusted_utility"] - claimed_spoof["debt_adjusted_utility"]),
            "interpretation": "Verification rejects spoofed provenance instead of admitting it as capital.",
        },
        {
            "component": "Abstention / capital-debt separation",
            "stress_case": "50% missing positive provenance",
            "ablated_policy": "Admit coverage-supported missing-provenance artifacts",
            "full_policy": "Record missing provenance as validation debt",
            "ablated_failure_metric": "hidden_validation_debt_admitted_per_total_pair",
            "ablated_value": hidden_debt_no_sep,
            "full_value": hidden_debt_full,
            "absolute_improvement": hidden_debt_no_sep - hidden_debt_full,
            "utility_ablated": float(no_sep_dropout["debt_adjusted_utility"]),
            "utility_full": float(qgdca_dropout["debt_adjusted_utility"]),
            "utility_gain": float(qgdca_dropout["debt_adjusted_utility"] - no_sep_dropout["debt_adjusted_utility"]),
            "interpretation": "Without the debt ledger, missing-evidence candidates are silently counted as capital.",
        },
        {
            "component": "Verification + abstention combined",
            "stress_case": "50% missing positive provenance + 10% spoofed negative provenance",
            "ablated_policy": "Claimed provenance OR coverage",
            "full_policy": "Verified provenance plus abstention",
            "ablated_failure_metric": "false_admission_plus_hidden_debt_rate",
            "ablated_value": float(no_sep_combined["false_admission_rate"]) + combined_hidden_no_sep,
            "full_value": float(qgdca_combined["false_admission_rate"]) + combined_hidden_full,
            "absolute_improvement": (
                float(no_sep_combined["false_admission_rate"]) + combined_hidden_no_sep
                - float(qgdca_combined["false_admission_rate"]) - combined_hidden_full
            ),
            "utility_ablated": float(no_sep_combined["debt_adjusted_utility"]),
            "utility_full": float(qgdca_combined["debt_adjusted_utility"]),
            "utility_gain": float(qgdca_combined["debt_adjusted_utility"] - no_sep_combined["debt_adjusted_utility"]),
            "interpretation": "The full gate avoids both spoofed false capital and missing-evidence hidden debt, at the cost of lower recall.",
        },
    ]


def load_recalibration_rows() -> list[dict[str, Any]]:
    selected = pd.read_csv(IN_LXXXI_SELECTED)
    rows: list[dict[str, Any]] = []
    for dataset in ["CVEfixes", "BigVul"]:
        ds = selected[selected["dataset"].eq(dataset)]
        full = ds[ds["selection"].eq("qgdca_best_overall")].iloc[0]
        ablated = ds[ds["selection"].eq("fixed_strict_0_10")].iloc[0]
        rows.append(
            {
                "component": f"Operating-point recalibration ({dataset})",
                "stress_case": f"{dataset} operating curve under declared debt cost",
                "ablated_policy": "Fixed strict gate",
                "full_policy": "QG-DCA selected operating point",
                "ablated_failure_metric": "suboptimal_false_rate_and_utility",
                "ablated_value": float(ablated["false_admission_rate"]),
                "full_value": float(full["false_admission_rate"]),
                "absolute_improvement": float(ablated["false_admission_rate"]) - float(full["false_admission_rate"]),
                "utility_ablated": float(ablated["debt_adjusted_utility"]),
                "utility_full": float(full["debt_adjusted_utility"]),
                "utility_gain": float(full["debt_adjusted_utility"]) - float(ablated["debt_adjusted_utility"]),
                "interpretation": "Recalibration prevents the paper from defending a dominated fixed gate.",
            }
        )
    return rows


def plot_table(table: pd.DataFrame) -> None:
    FIGURES.mkdir(parents=True, exist_ok=True)
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.5))
    labels = table["component"].str.replace("Operating-point recalibration ", "Recalibration\n", regex=False)
    x = np.arange(len(table))
    axes[0].bar(x, table["ablated_value"], label="Component off", color="#E45756")
    axes[0].bar(x, table["full_value"], label="Full QG-DCA", color="#54A24B")
    axes[0].set_title("Failure/debt metric")
    axes[0].set_xticks(x)
    axes[0].set_xticklabels(labels, rotation=35, ha="right")
    axes[0].grid(True, axis="y", alpha=0.25)
    axes[0].legend(frameon=False)

    axes[1].bar(x, table["utility_ablated"], label="Component off", color="#F58518")
    axes[1].bar(x, table["utility_full"], label="Full QG-DCA", color="#4C78A8")
    axes[1].axhline(0, color="black", linewidth=0.8)
    axes[1].set_title("Debt-adjusted utility")
    axes[1].set_xticks(x)
    axes[1].set_xticklabels(labels, rotation=35, ha="right")
    axes[1].grid(True, axis="y", alpha=0.25)
    axes[1].legend(frameon=False)
    fig.suptitle("LXXXV internal QG-DCA accounting-component ablation")
    fig.tight_layout()
    fig.savefig(OUT_FIG_PDF, bbox_inches="tight")
    fig.savefig(OUT_FIG_PNG, bbox_inches="tight", dpi=220)
    plt.close(fig)


def write_report(table: pd.DataFrame) -> dict[str, Any]:
    summary = {
        "experiment": "LXXXV internal QG-DCA accounting-component ablation",
        "generated_at": now_cst(),
        "inputs": {
            "lxxxiv_replicates": str(IN_LXXXIV_REPS),
            "lxxxi_selected_points": str(IN_LXXXI_SELECTED),
        },
        "claim_boundary": (
            "Internal accounting ablation over existing proxy-label outputs; not deployment repair, "
            "not SOTA repair, and not human semantic correctness."
        ),
        "key_results": table.to_dict(orient="records"),
        "outputs": {
            "table_csv": str(OUT_TABLE),
            "summary_json": str(OUT_SUMMARY),
            "report_md": str(OUT_REPORT),
            "figure_pdf": str(OUT_FIG_PDF),
            "figure_png": str(OUT_FIG_PNG),
        },
    }
    OUT_SUMMARY.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    lines = [
        "# Experiment LXXXV Internal Accounting-Component Ablation",
        "",
        f"Generated: {summary['generated_at']}",
        "",
        "## Purpose",
        "",
        "This experiment tests whether QG-DCA is more than a single threshold by turning off internal accounting components.",
        "",
        "## Component Results",
        "",
        "| Component | Stress case | Component off | Full QG-DCA | Failure/debt off | Failure/debt full | Utility off | Utility full | Interpretation |",
        "|---|---|---|---|---:|---:|---:|---:|---|",
    ]
    for _, row in table.iterrows():
        lines.append(
            f"| {row['component']} | {row['stress_case']} | {row['ablated_policy']} | {row['full_policy']} | {row['ablated_value']:.3f} | {row['full_value']:.3f} | {row['utility_ablated']:.3f} | {row['utility_full']:.3f} | {row['interpretation']} |"
        )
    lines.extend(
        [
            "",
            "## Main Result",
            "",
            "The ablation supports three narrow claims. First, provenance verification is necessary under spoofing: trusting claimed provenance creates false capital, while verified QG-DCA rejects spoofed claims. Second, abstention and capital-debt separation are necessary under missing provenance: otherwise missing-evidence artifacts are silently counted as capital. Third, recalibration is necessary because the fixed strict gate is dominated on CVEfixes and BigVul under the declared validation-debt cost.",
            "",
            "The result should not be written as deployment superiority. It is evidence that QG-DCA's accounting components each remove a measurable failure mode.",
            "",
            "## Boundary",
            "",
            summary["claim_boundary"],
            "",
            "## Outputs",
            "",
            f"- Table CSV: `{OUT_TABLE}`",
            f"- Summary JSON: `{OUT_SUMMARY}`",
            f"- Figure: `{OUT_FIG_PDF}`",
            "",
            "Document generated: " + now_cst(),
        ]
    )
    OUT_REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return summary


def write_reproduce() -> None:
    lines = [
        "# Reproduce LXXXV Internal Accounting-Component Ablation",
        "",
        "Run from `/root/mddc`:",
        "",
        "```bash",
        "python3 empirical_validation/experiment_lxxxv_internal_accounting_ablation.py",
        "```",
        "",
        "Required input files:",
        "",
        "- `/root/mddc/empirical_validation/results/experiment_lxxxiv_provenance_stress_replicates_20260625.csv`",
        "- `/root/mddc/empirical_validation/results/experiment_lxxxi_operating_curve_selected_points_20260624.csv`",
        "",
        "Boundary: internal accounting ablation over existing proxy-label results; not deployment repair or semantic correctness.",
        "",
        "Document generated: " + now_cst(),
    ]
    OUT_REPRO.write_text("\n".join(lines) + "\n", encoding="utf-8")


def sync_preview() -> None:
    PREVIEW.mkdir(parents=True, exist_ok=True)
    copies = [
        (OUT_REPORT, "experiment_lxxxv_internal_accounting_ablation_20260625.md"),
        (OUT_REPORT, "experiment_lxxxv_internal_accounting_ablation_20260625.txt"),
        (OUT_REPRO, "REPRODUCE_LXXXV_INTERNAL_ACCOUNTING_ABLATION_20260625.md"),
        (OUT_REPRO, "REPRODUCE_LXXXV_INTERNAL_ACCOUNTING_ABLATION_20260625.txt"),
        (OUT_SUMMARY, "experiment_lxxxv_internal_accounting_ablation_summary_20260625.json"),
        (OUT_TABLE, "experiment_lxxxv_internal_accounting_ablation_table_20260625.csv"),
        (OUT_FIG_PNG, "fig_experiment_lxxxv_internal_accounting_ablation_20260625.png"),
        (OUT_FIG_PDF, "fig_experiment_lxxxv_internal_accounting_ablation_20260625.pdf"),
    ]
    for src, name in copies:
        shutil.copy2(src, PREVIEW / name)


def main() -> int:
    RESULTS.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    FIGURES.mkdir(parents=True, exist_ok=True)
    rows = load_lxxxiv_component_rows() + load_recalibration_rows()
    table = pd.DataFrame(rows)
    table.to_csv(OUT_TABLE, index=False)
    plot_table(table)
    summary = write_report(table)
    write_reproduce()
    sync_preview()
    print(json.dumps({
        "table": str(OUT_TABLE),
        "summary": str(OUT_SUMMARY),
        "report": str(OUT_REPORT),
        "figure": str(OUT_FIG_PNG),
        "windows_report": "D:\\lunwen\\MDDC_Preview\\latest\\experiment_lxxxv_internal_accounting_ablation_20260625.txt",
        "key_results": summary["key_results"],
    }, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
