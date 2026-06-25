#!/usr/bin/env python3
"""Experiment LXXV: yield-threshold activation boundary.

This experiment turns the negative KEV/replay finding into an explicit MDDC
control rule: activate CEC-derived knowledge only when its qualified effective
gain exceeds a data-derived break-even frontier; otherwise fall back to AEC-only.
"""

from __future__ import annotations

import os

import csv
import json
import math
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt


ROOT = Path(os.environ.get("MDDC_ROOT", "/root/mddc"))
RESULTS = ROOT / "empirical_validation" / "results"
REPORTS = ROOT / "review_rounds"
FIGURES = ROOT / "empirical_validation" / "figures"

IN_XXIV = RESULTS / "experiment_xxiv_qualification_frontier.json"
IN_XXV = RESULTS / "experiment_xxv_frontier_aware_controller.json"
IN_XXIX = RESULTS / "experiment_xxix_budget_activation_robustness.json"

OUT_TABLE = RESULTS / "experiment_lxxv_yield_threshold_activation_boundary_table_20260624.csv"
OUT_SUMMARY = RESULTS / "experiment_lxxv_yield_threshold_activation_boundary_summary_20260624.json"
OUT_REPORT = REPORTS / "experiment_lxxv_yield_threshold_activation_boundary_20260624.md"
OUT_FIG_PDF = FIGURES / "fig_experiment_lxxv_yield_threshold_activation_boundary.pdf"
OUT_FIG_PNG = FIGURES / "fig_experiment_lxxv_yield_threshold_activation_boundary.png"

TZ = timezone(timedelta(hours=8))


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def div(a: float, b: float) -> float:
    return a / b if b else float("inf")


def classify(effective_gain: float, test_threshold: float, validation_threshold: float) -> str:
    if effective_gain >= validation_threshold:
        return "activate_mddc_validation_conservative"
    if effective_gain >= test_threshold:
        return "borderline_test_only"
    return "fallback_aec_only"


def main() -> None:
    RESULTS.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    FIGURES.mkdir(parents=True, exist_ok=True)

    xxiv = load(IN_XXIV)
    xxv = load(IN_XXV)
    xxix = load(IN_XXIX)

    test_threshold = float(xxv["thresholds"]["test_first_positive_gain"])
    validation_threshold = float(xxv["thresholds"]["validation_first_positive_gain"])
    interpolated_threshold = float(xxiv["thresholds"].get("linear_interpolated_break_even_gain", test_threshold))

    observed = xxiv["observed_capital_accounting"]
    property_path = xxiv["property_path"]
    property_coeff = float(property_path["property_coefficient"])

    scenario_specs = [
        {
            "scenario": "observed_patch_reuse_gain",
            "q_capital": 0.0392,
            "s_quality": 1.0,
            "note": "Observed same-CWE patch-scope efficiency gain from training artifacts.",
        },
        {
            "scenario": "current_all_static_qualified",
            "q_capital": float(observed["overall_static_qualification_rate"]),
            "s_quality": 1.0,
            "note": "All generated candidates that pass static qualification, treated as an optimistic upper bound.",
        },
        {
            "scenario": "current_knowledge_static_qualified",
            "q_capital": float(observed["knowledge_static_qualification_rate"]),
            "s_quality": 1.0,
            "note": "Knowledge-arm static-qualified capital, treated as an optimistic upper bound.",
        },
        {
            "scenario": "repo_applicability_upper_bound",
            "q_capital": float(observed["repo_applicability_upper_bound"]),
            "s_quality": 1.0,
            "note": "Repository applicability without security qualification, an upper bound rather than admissible capital.",
        },
        {
            "scenario": "measured_property_delivery_proxy",
            "q_capital": property_coeff,
            "s_quality": float(property_path["measured_s_quality_proxy"]),
            "note": "Measured property-guided delivery proxy from Exp XIII.",
        },
        {
            "scenario": "property_test_threshold",
            "q_capital": property_coeff,
            "s_quality": div(test_threshold, property_coeff),
            "note": "Minimum property-path quality required to cross the held-out test frontier.",
        },
        {
            "scenario": "property_validation_threshold",
            "q_capital": property_coeff,
            "s_quality": div(validation_threshold, property_coeff),
            "note": "Minimum property-path quality required to cross the validation-period conservative frontier.",
        },
        {
            "scenario": "property_full_quality_upper_bound",
            "q_capital": property_coeff,
            "s_quality": 1.0,
            "note": "Theoretical full-quality property-capital upper bound.",
        },
    ]

    xxv_by_scenario = {row["scenario"]: row for row in xxv["scenarios"]}
    table: list[dict[str, Any]] = []
    for spec in scenario_specs:
        effective_gain = float(spec["q_capital"]) * float(spec["s_quality"])
        controller_row = xxv_by_scenario.get(
            {
                "current_all_static_qualified": "current_static_qualified_capital",
                "measured_property_delivery_proxy": "property_delivery_proxy",
                "property_test_threshold": "property_test_frontier",
                "property_validation_threshold": "property_validation_frontier",
            }.get(spec["scenario"], spec["scenario"]),
            {},
        )
        row = {
            "scenario": spec["scenario"],
            "q_capital": float(spec["q_capital"]),
            "s_quality": float(spec["s_quality"]),
            "effective_gain": effective_gain,
            "required_s_for_test_threshold": div(test_threshold, float(spec["q_capital"])),
            "required_s_for_validation_threshold": div(validation_threshold, float(spec["q_capital"])),
            "crosses_interpolated_threshold": effective_gain >= interpolated_threshold,
            "crosses_test_threshold_0_275": effective_gain >= test_threshold,
            "crosses_validation_threshold_0_325": effective_gain >= validation_threshold,
            "activation_decision": classify(effective_gain, test_threshold, validation_threshold),
            "controller_selected_policy": controller_row.get("selected_policy"),
            "always_on_mddc_advantage_pct": controller_row.get("always_mddc_advantage_pct"),
            "penalty_prevented_vs_always_on": controller_row.get("penalty_prevented_vs_always_on"),
            "note": spec["note"],
        }
        table.append(row)

    budget_thresholds = xxix["headline"]["thresholds"]
    observed_gain_penalty_range = xxix["headline"]["observed_gain_penalty_prevented_range"]

    summary = {
        "experiment": "LXXV yield-threshold activation boundary",
        "generated_at": datetime.now(TZ).strftime("%Y-%m-%d %H:%M:%S %z"),
        "inputs": [str(IN_XXIV), str(IN_XXV), str(IN_XXIX)],
        "formula": "effective_gain = q_capital * s_quality",
        "thresholds": {
            "interpolated_break_even": interpolated_threshold,
            "heldout_test_first_positive": test_threshold,
            "validation_conservative": validation_threshold,
            "budget_conditioned_validation_range": xxix["headline"]["validation_threshold_range"],
        },
        "property_path_required_s_quality": {
            "for_interpolated_break_even": div(interpolated_threshold, property_coeff),
            "for_test_threshold_0_275": div(test_threshold, property_coeff),
            "for_validation_threshold_0_325": div(validation_threshold, property_coeff),
        },
        "observed_negative_result": {
            "observed_patch_reuse_gain": 0.0392,
            "selected_policy": xxv_by_scenario["observed_patch_reuse_gain"]["selected_policy"],
            "always_on_mddc_advantage_pct": xxv_by_scenario["observed_patch_reuse_gain"][
                "always_mddc_advantage_pct"
            ],
            "penalty_prevented_vs_always_on": xxv_by_scenario["observed_patch_reuse_gain"][
                "penalty_prevented_vs_always_on"
            ],
            "budget_sensitivity_penalty_prevented_range": observed_gain_penalty_range,
        },
        "table": table,
        "paper_consequence": [
            "The 0.275 value is the first positive held-out test frontier at which MDDC can beat AEC-only in the replay.",
            "The 0.325 value is the stricter validation-period activation threshold used to avoid post-hoc activation.",
            "Current patch-reuse/static-qualified CEC yields remain far below both thresholds; correct controller behavior is AEC-only fallback.",
            "Property capital can be a viable CEC path only if its downstream quality reaches about 0.618 for test activation and about 0.730 for conservative validation activation.",
            "This is a bounded activation rule, not a claim that CEC is universally better than AEC.",
        ],
    }

    with OUT_TABLE.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(table[0].keys()))
        writer.writeheader()
        writer.writerows(table)
    OUT_SUMMARY.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    make_figure(table, test_threshold, validation_threshold)
    write_report(summary)

    print(
        json.dumps(
            {
                "test_threshold": test_threshold,
                "validation_threshold": validation_threshold,
                "property_s_test": summary["property_path_required_s_quality"]["for_test_threshold_0_275"],
                "property_s_validation": summary["property_path_required_s_quality"][
                    "for_validation_threshold_0_325"
                ],
                "observed_patch_reuse_decision": table[0]["activation_decision"],
            },
            indent=2,
        )
    )


def make_figure(table: list[dict[str, Any]], test_threshold: float, validation_threshold: float) -> None:
    plot_rows = [
        row
        for row in table
        if row["scenario"]
        in {
            "observed_patch_reuse_gain",
            "current_all_static_qualified",
            "current_knowledge_static_qualified",
            "repo_applicability_upper_bound",
            "measured_property_delivery_proxy",
            "property_test_threshold",
            "property_validation_threshold",
            "property_full_quality_upper_bound",
        }
    ]
    labels = [
        row["scenario"]
        .replace("observed_", "obs_")
        .replace("current_", "cur_")
        .replace("_threshold", "_thr")
        .replace("_qualified", "_qual")
        for row in plot_rows
    ]
    values = [row["effective_gain"] for row in plot_rows]
    colors = [
        "#4c78a8" if row["activation_decision"] == "fallback_aec_only" else "#54a24b" for row in plot_rows
    ]
    fig, ax = plt.subplots(figsize=(9.2, 4.6))
    ax.bar(range(len(values)), values, color=colors)
    ax.axhline(test_threshold, color="#f58518", linestyle="--", linewidth=1.5, label="test frontier 0.275")
    ax.axhline(validation_threshold, color="#e45756", linestyle="-.", linewidth=1.5, label="validation frontier 0.325")
    ax.set_ylabel("effective gain = q_capital * s_quality")
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=35, ha="right", fontsize=8)
    ax.set_title("LXXV: CEC activation requires qualified yield above the frontier")
    ax.legend(frameon=False, loc="upper left")
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    fig.savefig(OUT_FIG_PDF)
    fig.savefig(OUT_FIG_PNG, dpi=240)
    plt.close(fig)


def write_report(summary: dict[str, Any]) -> None:
    rows = summary["table"]
    lines = [
        "# Experiment LXXV: Yield-Threshold Activation Boundary",
        "",
        f"Generated: {summary['generated_at']}",
        "",
        "## Purpose",
        "",
        "This experiment formalizes the KEV/replay negative result as a controller boundary. MDDC does not activate CEC-derived knowledge just because it exists; it activates only when qualified effective gain crosses a data-derived threshold.",
        "",
        "## Rule",
        "",
        "`effective_gain = q_capital * s_quality`",
        "",
        f"- Held-out test frontier: `{summary['thresholds']['heldout_test_first_positive']:.3f}`.",
        f"- Conservative validation frontier: `{summary['thresholds']['validation_conservative']:.3f}`.",
        "",
        "## Main Findings",
        "",
        f"- Observed patch-reuse gain is `0.0392`, so the controller selects `{summary['observed_negative_result']['selected_policy']}`.",
        f"- Always-on MDDC would be `{summary['observed_negative_result']['always_on_mddc_advantage_pct']:.2f}%` worse in the observed replay, and gating prevents `{summary['observed_negative_result']['penalty_prevented_vs_always_on']:.3f}` mean-debt penalty.",
        f"- Property capital requires `s_quality >= {summary['property_path_required_s_quality']['for_test_threshold_0_275']:.3f}` for the test frontier and `s_quality >= {summary['property_path_required_s_quality']['for_validation_threshold_0_325']:.3f}` for the conservative validation frontier.",
        "",
        "## Activation Table",
        "",
        "| Scenario | q_capital | s_quality | effective_gain | Decision |",
        "|---|---:|---:|---:|---|",
    ]
    for row in rows:
        lines.append(
            f"| {row['scenario']} | {row['q_capital']:.4f} | {row['s_quality']:.4f} | {row['effective_gain']:.4f} | {row['activation_decision']} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "The negative replay is not discarded. It becomes the empirical reason for a qualification gate: below the frontier, MDDC should abstain from CEC activation and fall back to AEC-only. Above the frontier, qualified property capital becomes a plausible activation path.",
            "",
            "## Boundary",
            "",
            "This is a threshold/accounting experiment. It does not prove deployment-grade repair and does not claim that CEC is universally better than AEC.",
            "",
            "## Artifacts",
            "",
            f"- Table: `{OUT_TABLE}`",
            f"- Summary: `{OUT_SUMMARY}`",
            f"- Figure: `{OUT_FIG_PDF}`",
            "",
            f"Document generated: {summary['generated_at']}",
            "",
        ]
    )
    OUT_REPORT.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    main()

