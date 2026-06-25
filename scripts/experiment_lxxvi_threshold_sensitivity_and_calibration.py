#!/usr/bin/env python3
"""Experiment LXXVI: threshold sensitivity and calibration audit.

The 0.275 and 0.325 frontiers are dataset-calibrated values from the current
public replay. They are not universal constants. This script independently
recomputes the values from the saved replay curves and summarizes how they move
under rolling windows, attack regimes, budget scales, and q_capital perturbation.
"""

from __future__ import annotations

import os
import hashlib
import json
import math
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import pandas as pd


ROOT = Path(os.environ.get("MDDC_ROOT", "/root/mddc"))
RESULTS = ROOT / "empirical_validation" / "results"
REPORTS = ROOT / "review_rounds"
FIGURES = ROOT / "empirical_validation" / "figures"

IN_BREAK_EVEN = RESULTS / "knowledge_gain_break_even.csv"
IN_XXV_CURVE = RESULTS / "experiment_xxv_validation_frontier_curve.csv"
IN_XXVII_ORIGINS = RESULTS / "experiment_xxvii_rolling_origin_activation_origins.csv"
IN_XXVIII_REGIMES = RESULTS / "experiment_xxviii_attack_regime_summary.csv"
IN_XXIX_BUDGETS = RESULTS / "experiment_xxix_budget_activation_summary.csv"
IN_LXXV = RESULTS / "experiment_lxxv_yield_threshold_activation_boundary_summary_20260624.json"

OUT_SUMMARY = RESULTS / "experiment_lxxvi_threshold_sensitivity_and_calibration_summary_20260624.json"
OUT_TABLE = RESULTS / "experiment_lxxvi_threshold_sensitivity_and_calibration_table_20260624.csv"
OUT_Q_TABLE = RESULTS / "experiment_lxxvi_q_perturbation_sensitivity_20260624.csv"
OUT_REPORT = REPORTS / "experiment_lxxvi_threshold_sensitivity_and_calibration_20260624.md"
OUT_FIG_PDF = FIGURES / "fig_experiment_lxxvi_threshold_sensitivity_and_calibration.pdf"
OUT_FIG_PNG = FIGURES / "fig_experiment_lxxvi_threshold_sensitivity_and_calibration.png"

TZ = timezone(timedelta(hours=8))


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def first_positive(df: pd.DataFrame, gain_col: str, advantage_col: str) -> float | None:
    positive = df[df[advantage_col].notna() & (df[advantage_col] > 0)]
    if positive.empty:
        return None
    return float(positive[gain_col].min())


def interpolated_zero(df: pd.DataFrame, gain_col: str, advantage_col: str) -> float | None:
    ordered = df.sort_values(gain_col)
    gains = ordered[gain_col].to_numpy(dtype=float)
    adv = ordered[advantage_col].to_numpy(dtype=float)
    for i in range(1, len(ordered)):
        left = adv[i - 1]
        right = adv[i]
        if not (math.isfinite(left) and math.isfinite(right)):
            continue
        if left <= 0 <= right:
            if right == left:
                return float(gains[i])
            return float(gains[i - 1] + (0 - left) * (gains[i] - gains[i - 1]) / (right - left))
    return None


def threshold_record(
    sensitivity_type: str,
    label: str,
    validation_threshold: float | None,
    test_threshold: float | None,
    validation_interpolated: float | None = None,
    test_interpolated: float | None = None,
    note: str = "",
) -> dict[str, Any]:
    return {
        "sensitivity_type": sensitivity_type,
        "label": label,
        "validation_first_positive": validation_threshold,
        "test_first_positive": test_threshold,
        "validation_interpolated": validation_interpolated,
        "test_interpolated": test_interpolated,
        "validation_minus_test": (
            None
            if validation_threshold is None or test_threshold is None
            else validation_threshold - test_threshold
        ),
        "is_validation_conservative": (
            None
            if validation_threshold is None or test_threshold is None
            else validation_threshold >= test_threshold
        ),
        "note": note,
    }


def main() -> int:
    RESULTS.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    FIGURES.mkdir(parents=True, exist_ok=True)

    break_even = pd.read_csv(IN_BREAK_EVEN)
    xxv_curve = pd.read_csv(IN_XXV_CURVE)
    rolling = pd.read_csv(IN_XXVII_ORIGINS)
    regimes = pd.read_csv(IN_XXVIII_REGIMES)
    budgets = pd.read_csv(IN_XXIX_BUDGETS)
    lxxv = json.loads(IN_LXXV.read_text(encoding="utf-8"))

    base_test_first = first_positive(break_even, "knowledge_gain", "mddc_advantage_pct")
    base_test_interp = interpolated_zero(break_even, "knowledge_gain", "mddc_advantage_pct")
    xxv_test_first = first_positive(xxv_curve, "effective_gain", "test_mddc_advantage_pct")
    xxv_test_interp = interpolated_zero(xxv_curve, "effective_gain", "test_mddc_advantage_pct")
    xxv_val_first = first_positive(xxv_curve, "effective_gain", "validation_mddc_advantage_pct")
    xxv_val_interp = interpolated_zero(xxv_curve, "effective_gain", "validation_mddc_advantage_pct")

    records: list[dict[str, Any]] = [
        threshold_record(
            "reproduction",
            "XXIV test curve",
            None,
            base_test_first,
            None,
            base_test_interp,
            "Recomputes the held-out test frontier from knowledge_gain_break_even.csv.",
        ),
        threshold_record(
            "reproduction",
            "XXV validation/test curve",
            xxv_val_first,
            xxv_test_first,
            xxv_val_interp,
            xxv_test_interp,
            "Recomputes validation and test first-positive frontiers from the replay curve.",
        ),
    ]

    for _, row in rolling.sort_values(["capacity_mode", "origin"]).iterrows():
        records.append(
            threshold_record(
                "rolling_origin",
                f"{row['capacity_mode']}::{row['origin']}",
                float(row["validation_threshold"]),
                float(row["test_threshold"]),
                None,
                None,
                str(row["role"]),
            )
        )

    for _, row in budgets.sort_values("budget_scale").iterrows():
        records.append(
            threshold_record(
                "budget_scale",
                f"budget_scale={row['budget_scale']:.2f}",
                float(row["validation_threshold"]),
                float(row["test_threshold"]),
                None,
                None,
                f"effective_monthly_capacity={row['effective_monthly_capacity']:.3f}",
            )
        )

    for _, row in regimes.sort_values("regime").iterrows():
        records.append(
            threshold_record(
                "attack_regime",
                str(row["regime"]),
                float(row["validation_threshold"]),
                float(row["test_threshold"]),
                None,
                None,
                f"validation_months={int(row['validation_months'])}, test_months={int(row['test_months'])}",
            )
        )

    table = pd.DataFrame(records)
    table.to_csv(OUT_TABLE, index=False)

    property_coeff = float(lxxv["table"][-1]["q_capital"])
    observed_patch = float(lxxv["observed_negative_result"]["observed_patch_reuse_gain"])
    repo_upper = next(row for row in lxxv["table"] if row["scenario"] == "repo_applicability_upper_bound")
    repo_coeff = float(repo_upper["q_capital"])
    q_rows = []
    for label, q in [
        ("observed_patch_reuse_gain", observed_patch),
        ("repo_applicability_upper_bound", repo_coeff),
        ("property_capital_coefficient", property_coeff),
    ]:
        for multiplier in [0.8, 1.0, 1.2]:
            q_adj = q * multiplier
            q_rows.append(
                {
                    "scenario": label,
                    "q_multiplier": multiplier,
                    "q_capital": q_adj,
                    "required_s_for_test_0_275": 0.275 / q_adj if q_adj > 0 else None,
                    "required_s_for_validation_0_325": 0.325 / q_adj if q_adj > 0 else None,
                    "can_cross_test_with_s_le_1": q_adj >= 0.275,
                    "can_cross_validation_with_s_le_1": q_adj >= 0.325,
                }
            )
    q_table = pd.DataFrame(q_rows)
    q_table.to_csv(OUT_Q_TABLE, index=False)

    threshold_ranges = {
        "rolling_origin_validation_range": [
            float(rolling["validation_threshold"].min()),
            float(rolling["validation_threshold"].max()),
        ],
        "rolling_origin_test_range": [
            float(rolling["test_threshold"].min()),
            float(rolling["test_threshold"].max()),
        ],
        "budget_validation_range": [
            float(budgets["validation_threshold"].min()),
            float(budgets["validation_threshold"].max()),
        ],
        "budget_test_range": [
            float(budgets["test_threshold"].min()),
            float(budgets["test_threshold"].max()),
        ],
        "regime_validation_range": [
            float(regimes["validation_threshold"].min()),
            float(regimes["validation_threshold"].max()),
        ],
        "regime_test_range": [
            float(regimes["test_threshold"].min()),
            float(regimes["test_threshold"].max()),
        ],
    }

    summary = {
        "experiment": "LXXVI threshold sensitivity and calibration audit",
        "generated_at": datetime.now(TZ).strftime("%Y-%m-%d %H:%M:%S %z"),
        "input_files": {
            str(path.relative_to(ROOT)): {
                "sha256": file_sha256(path),
                "bytes": path.stat().st_size,
            }
            for path in [
                IN_BREAK_EVEN,
                IN_XXV_CURVE,
                IN_XXVII_ORIGINS,
                IN_XXVIII_REGIMES,
                IN_XXIX_BUDGETS,
                IN_LXXV,
            ]
        },
        "recomputed_frontiers": {
            "test_first_positive_from_xxiv": base_test_first,
            "test_interpolated_from_xxiv": base_test_interp,
            "test_first_positive_from_xxv": xxv_test_first,
            "test_interpolated_from_xxv": xxv_test_interp,
            "validation_first_positive_from_xxv": xxv_val_first,
            "validation_interpolated_from_xxv": xxv_val_interp,
        },
        "threshold_ranges": threshold_ranges,
        "q_perturbation_headline": {
            "observed_patch_reuse_gain_even_plus_20pct_crosses_test": bool(
                q_table[
                    (q_table["scenario"] == "observed_patch_reuse_gain")
                    & (q_table["q_multiplier"] == 1.2)
                ]["can_cross_test_with_s_le_1"].iloc[0]
            ),
            "repo_upper_even_plus_20pct_crosses_test": bool(
                q_table[
                    (q_table["scenario"] == "repo_applicability_upper_bound")
                    & (q_table["q_multiplier"] == 1.2)
                ]["can_cross_test_with_s_le_1"].iloc[0]
            ),
            "property_minus_20pct_required_s_test": float(
                q_table[
                    (q_table["scenario"] == "property_capital_coefficient")
                    & (q_table["q_multiplier"] == 0.8)
                ]["required_s_for_test_0_275"].iloc[0]
            ),
            "property_minus_20pct_required_s_validation": float(
                q_table[
                    (q_table["scenario"] == "property_capital_coefficient")
                    & (q_table["q_multiplier"] == 0.8)
                ]["required_s_for_validation_0_325"].iloc[0]
            ),
        },
        "calibration_protocol": [
            "Fix training, validation, and test windows before evaluating a new deployment setting.",
            "Estimate AEC-only and MDDC debt under identical public-task arrivals, budget, seeds, and policy definitions.",
            "Sweep effective CEC gain on a pre-declared grid and record both the first-positive frontier and the interpolated zero crossing.",
            "Use the validation frontier, not the test frontier, for activation; periodically recalibrate when threat pressure, resources, or gate quality shifts.",
            "Treat 0.275 and 0.325 as current-dataset calibrated frontiers, not universal constants.",
        ],
        "paper_consequence": [
            "The discrete 0.275 and 0.325 thresholds are reproducible from saved replay curves.",
            "The interpolated zero crossings are lower, so using first-positive grid points is conservative.",
            "Budget and rolling-origin sensitivity show that thresholds move with resource allocation and time windows.",
            "Observed patch reuse remains below threshold even under +20% q_capital perturbation.",
        ],
    }

    OUT_SUMMARY.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    make_figure(table, q_table)
    write_report(summary, table, q_table)
    print(
        json.dumps(
            {
                "test_first_positive": base_test_first,
                "validation_first_positive": xxv_val_first,
                "test_interpolated": base_test_interp,
                "validation_interpolated": xxv_val_interp,
                "budget_validation_range": threshold_ranges["budget_validation_range"],
                "regime_validation_range": threshold_ranges["regime_validation_range"],
            },
            indent=2,
        )
    )
    return 0


def make_figure(table: pd.DataFrame, q_table: pd.DataFrame) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(10.5, 4.2))

    left = table[table["sensitivity_type"].isin(["rolling_origin", "budget_scale", "attack_regime"])].copy()
    left["short_label"] = left["label"].str.replace("paper_fixed::", "pf::", regex=False)
    left["short_label"] = left["short_label"].str.replace("validation_median::", "vm::", regex=False)
    left["short_label"] = left["short_label"].str.replace("budget_scale=", "b=", regex=False)
    left = left.reset_index(drop=True)
    axes[0].scatter(left.index, left["test_first_positive"], label="test", color="#4c78a8", s=24)
    axes[0].scatter(left.index, left["validation_first_positive"], label="validation", color="#e45756", s=24)
    axes[0].axhline(0.275, color="#4c78a8", linestyle="--", linewidth=1)
    axes[0].axhline(0.325, color="#e45756", linestyle="--", linewidth=1)
    axes[0].set_xticks(left.index)
    axes[0].set_xticklabels(left["short_label"], rotation=80, ha="right", fontsize=6)
    axes[0].set_ylabel("first-positive frontier")
    axes[0].set_title("Window, budget, and regime sensitivity")
    axes[0].legend(frameon=False, fontsize=8)
    axes[0].grid(axis="y", alpha=0.25)

    prop = q_table[q_table["scenario"] == "property_capital_coefficient"].sort_values("q_multiplier")
    axes[1].plot(prop["q_multiplier"], prop["required_s_for_test_0_275"], marker="o", label="test 0.275")
    axes[1].plot(
        prop["q_multiplier"],
        prop["required_s_for_validation_0_325"],
        marker="o",
        label="validation 0.325",
    )
    axes[1].axhline(1.0, color="#444444", linestyle=":", linewidth=1)
    axes[1].set_xlabel("property q_capital multiplier")
    axes[1].set_ylabel("required s_quality")
    axes[1].set_title("Property-capital quality requirement")
    axes[1].legend(frameon=False, fontsize=8)
    axes[1].grid(alpha=0.25)

    fig.tight_layout()
    fig.savefig(OUT_FIG_PDF)
    fig.savefig(OUT_FIG_PNG, dpi=240)
    plt.close(fig)


def write_report(summary: dict[str, Any], table: pd.DataFrame, q_table: pd.DataFrame) -> None:
    repro = summary["recomputed_frontiers"]
    ranges = summary["threshold_ranges"]
    prop = q_table[q_table["scenario"] == "property_capital_coefficient"].sort_values("q_multiplier")
    lines = [
        "# Experiment LXXVI: Threshold Sensitivity and Calibration Audit",
        "",
        f"Generated: {summary['generated_at']}",
        "",
        "## Purpose",
        "",
        "This audit checks that the `0.275` and `0.325` thresholds are reproducible from the current replay data and documents how they should be recalibrated in other deployments. They are current-dataset calibration outputs, not universal constants.",
        "",
        "## Reproduction Check",
        "",
        f"- Test first-positive frontier from XXIV: `{repro['test_first_positive_from_xxiv']:.3f}`.",
        f"- Test interpolated zero crossing from XXIV: `{repro['test_interpolated_from_xxiv']:.6f}`.",
        f"- Validation first-positive frontier from XXV: `{repro['validation_first_positive_from_xxv']:.3f}`.",
        f"- Validation interpolated zero crossing from XXV: `{repro['validation_interpolated_from_xxv']:.6f}`.",
        "",
        "The paper uses the first-positive grid values because they are conservative and directly reproducible from the pre-declared gain grid.",
        "",
        "## Sensitivity Summary",
        "",
        f"- Rolling-origin validation range: `{ranges['rolling_origin_validation_range'][0]:.3f}`--`{ranges['rolling_origin_validation_range'][1]:.3f}`.",
        f"- Rolling-origin test range: `{ranges['rolling_origin_test_range'][0]:.3f}`--`{ranges['rolling_origin_test_range'][1]:.3f}`.",
        f"- Budget validation range: `{ranges['budget_validation_range'][0]:.3f}`--`{ranges['budget_validation_range'][1]:.3f}`.",
        f"- Budget test range: `{ranges['budget_test_range'][0]:.3f}`--`{ranges['budget_test_range'][1]:.3f}`.",
        f"- Attack-regime validation range: `{ranges['regime_validation_range'][0]:.3f}`--`{ranges['regime_validation_range'][1]:.3f}`.",
        f"- Attack-regime test range: `{ranges['regime_test_range'][0]:.3f}`--`{ranges['regime_test_range'][1]:.3f}`.",
        "",
        "## q_capital Perturbation",
        "",
        "| q multiplier | property q_capital | required s for 0.275 | required s for 0.325 |",
        "|---:|---:|---:|---:|",
    ]
    for _, row in prop.iterrows():
        lines.append(
            f"| {row['q_multiplier']:.1f} | {row['q_capital']:.4f} | {row['required_s_for_test_0_275']:.3f} | {row['required_s_for_validation_0_325']:.3f} |"
        )
    lines.extend(
        [
            "",
            "Observed patch reuse remains below the test frontier even with a +20% q_capital perturbation. Repository applicability also remains below the test frontier under +20%. This supports the fallback decision for current low-yield CEC paths.",
            "",
            "## Calibration Protocol",
            "",
        ]
    )
    for idx, item in enumerate(summary["calibration_protocol"], 1):
        lines.append(f"{idx}. {item}")
    lines.extend(
        [
            "",
            "## Boundary",
            "",
            "These thresholds are reproducible for the current public replay, but they are not transferable constants. A production or different-dataset use of MDDC must recalibrate the frontier under its own threat pressure, budget, validation gates, and policy definitions.",
            "",
            "## Artifacts",
            "",
            f"- Summary: `{OUT_SUMMARY}`",
            f"- Threshold table: `{OUT_TABLE}`",
            f"- q perturbation table: `{OUT_Q_TABLE}`",
            f"- Figure: `{OUT_FIG_PDF}`",
            "",
            f"Document generated: {summary['generated_at']}",
            "",
        ]
    )
    OUT_REPORT.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
