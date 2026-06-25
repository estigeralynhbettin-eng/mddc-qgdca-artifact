#!/usr/bin/env python3
"""Experiment LXXXIV: noisy/partial/spoofed provenance stress test.

The LXXXIII result showed that provenance gating removes same-CWE borrowed
artifacts, but a strict reviewer can object that exact CVE/commit provenance is
close to definitional. This experiment stress-tests the admission layer under
missing and spoofed provenance claims.

Boundary:
- This is a provenance/accounting stress test over the LXXXIII proxy-label
  sample.
- It is not deployment-grade repair evidence, SOTA repair evidence, or human
  semantic truth.
"""

from __future__ import annotations

import os
import json
import math
import shutil
from datetime import datetime, timezone, timedelta
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

IN_PAIRS = RESULTS / "experiment_lxxxiii_hf_external_component_pairs_20260624.csv"
IN_SELECTED = RESULTS / "experiment_lxxxiii_hf_external_component_selected_20260624.csv"

OUT_REPLICATES = RESULTS / "experiment_lxxxiv_provenance_stress_replicates_20260625.csv"
OUT_SUMMARY_CSV = RESULTS / "experiment_lxxxiv_provenance_stress_summary_20260625.csv"
OUT_SUMMARY_JSON = RESULTS / "experiment_lxxxiv_provenance_stress_summary_20260625.json"
OUT_REPORT = REPORTS / "experiment_lxxxiv_provenance_stress_test_20260625.md"
OUT_REPRO = REPORTS / "REPRODUCE_LXXXIV_PROVENANCE_STRESS_TEST_20260625.md"
OUT_FIG_PDF = FIGURES / "fig_experiment_lxxxiv_provenance_stress_test.pdf"
OUT_FIG_PNG = FIGURES / "fig_experiment_lxxxiv_provenance_stress_test.png"

RANDOM_SEED = 20260625
REPLICATES = 200

FALSE_COST = 3.0
MISS_COST = 0.25
REVIEW_COST = 0.05

SCENARIOS = [
    ("clean", 0.00, 0.00),
    ("dropout_25", 0.25, 0.00),
    ("dropout_50", 0.50, 0.00),
    ("spoof_01", 0.00, 0.01),
    ("spoof_05", 0.00, 0.05),
    ("spoof_10", 0.00, 0.10),
    ("combined_25_05", 0.25, 0.05),
    ("combined_50_10", 0.50, 0.10),
]

POLICY_LABELS = {
    "coverage_only": "Coverage only",
    "claimed_provenance_only": "Claimed provenance only",
    "claimed_or_coverage": "Claimed provenance OR coverage",
    "verified_provenance_only": "Verified provenance only",
    "qgdca_verified_abstain": "QG-DCA verified + abstain",
}


def now_cst() -> str:
    return datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S +08:00")


def wilson(k: float, n: float, z: float = 1.96) -> tuple[float, float]:
    if n <= 0:
        return (math.nan, math.nan)
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt((p * (1 - p) + z * z / (4 * n)) / n) / denom
    return max(0.0, center - half), min(1.0, center + half)


def load_thresholds() -> dict[str, float]:
    selected = pd.read_csv(IN_SELECTED)
    same = selected[
        selected["negative_mode"].eq("same_cwe_different_cve")
        & selected["selection_scope"].eq("best_per_policy")
    ]
    out = {
        "coverage_only": 0.5294117647058824,
        "qgdca_full": 0.33282652727272727,
    }
    for policy in out:
        row = same[same["policy"].eq(policy)]
        if not row.empty:
            out[policy] = float(row.iloc[0]["threshold"])
    return out


def load_pairs() -> pd.DataFrame:
    df = pd.read_csv(IN_PAIRS)
    df = df[df["pair_mode"].isin(["true_pair", "same_cwe_different_cve"])].copy()
    df["label"] = df["label"].astype(int)
    df["coverage"] = pd.to_numeric(df["coverage"], errors="coerce").fillna(0.0)
    df["qgdca_full"] = pd.to_numeric(df["qgdca_full"], errors="coerce").replace([np.inf, -np.inf], np.nan)
    df["actual_match"] = df["ref_cve"].eq(df["cand_cve"])
    if df["label"].sum() == 0 or (df["label"].eq(0).sum() == 0):
        raise ValueError("LXXXIV requires both true pairs and same-CWE controls")
    return df.reset_index(drop=True)


def policy_actions(
    policy: str,
    df: pd.DataFrame,
    claimed_exact: np.ndarray,
    thresholds: dict[str, float],
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Return admit, reject, abstain boolean arrays."""
    label = df["label"].to_numpy(dtype=int)
    coverage = df["coverage"].to_numpy(dtype=float)
    actual_match = df["actual_match"].to_numpy(dtype=bool)
    qg_score = df["qgdca_full"].fillna(-1e9).to_numpy(dtype=float)
    cov_gate = coverage >= thresholds["coverage_only"]
    qg_gate = qg_score >= thresholds["qgdca_full"]

    if policy == "coverage_only":
        admit = cov_gate
        abstain = np.zeros(len(df), dtype=bool)
    elif policy == "claimed_provenance_only":
        admit = claimed_exact
        abstain = np.zeros(len(df), dtype=bool)
    elif policy == "claimed_or_coverage":
        admit = claimed_exact | cov_gate
        abstain = np.zeros(len(df), dtype=bool)
    elif policy == "verified_provenance_only":
        admit = claimed_exact & actual_match
        abstain = np.zeros(len(df), dtype=bool)
    elif policy == "qgdca_verified_abstain":
        verified = claimed_exact & actual_match
        spoofed_claim = claimed_exact & ~actual_match
        admit = verified & qg_gate
        # Promising artifacts with missing provenance are validation debt, not capital.
        abstain = (~claimed_exact & cov_gate) | (verified & ~qg_gate)
        # Spoofed claims are explicit rejects, not abstentions.
        abstain = abstain & ~spoofed_claim
    else:
        raise ValueError(f"unknown policy {policy}")

    reject = ~(admit | abstain)
    # Safety assertion: admitted positives/negatives are defined only by the label.
    assert len(admit) == len(label)
    return admit, reject, abstain


def metric_row(
    scenario: str,
    replicate: int,
    policy: str,
    df: pd.DataFrame,
    claimed_exact: np.ndarray,
    dropped_positive: np.ndarray,
    spoofed_negative: np.ndarray,
    thresholds: dict[str, float],
) -> dict[str, Any]:
    labels = df["label"].to_numpy(dtype=int)
    admit, reject, abstain = policy_actions(policy, df, claimed_exact, thresholds)
    pos = labels == 1
    neg = labels == 0
    tp = int((admit & pos).sum())
    fp = int((admit & neg).sum())
    fn = int((~admit & pos).sum())
    n_pos = int(pos.sum())
    n_neg = int(neg.sum())
    n = int(len(df))
    abstain_count = int(abstain.sum())
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / n_pos if n_pos else 0.0
    false_rate = fp / n_neg if n_neg else 0.0
    utility = (tp - FALSE_COST * fp - MISS_COST * fn - REVIEW_COST * abstain_count) / n_pos
    spoof_total = int(spoofed_negative.sum())
    spoof_admit = int((admit & spoofed_negative).sum())
    dropped_total = int(dropped_positive.sum())
    dropped_admit = int((admit & dropped_positive).sum())
    dropped_abstain = int((abstain & dropped_positive).sum())
    return {
        "scenario": scenario,
        "replicate": replicate,
        "policy": policy,
        "policy_label": POLICY_LABELS[policy],
        "true_positive": tp,
        "false_admission": fp,
        "false_negative": fn,
        "admitted": int(admit.sum()),
        "rejected": int(reject.sum()),
        "abstained": abstain_count,
        "n_true": n_pos,
        "n_negative": n_neg,
        "recall": recall,
        "false_admission_rate": false_rate,
        "precision": precision,
        "abstain_rate": abstain_count / n,
        "debt_adjusted_utility": utility,
        "spoofed_negative_count": spoof_total,
        "spoofed_negative_admitted": spoof_admit,
        "spoofed_negative_admission_rate": spoof_admit / spoof_total if spoof_total else 0.0,
        "dropped_positive_count": dropped_total,
        "dropped_positive_admitted": dropped_admit,
        "dropped_positive_abstained": dropped_abstain,
        "dropped_positive_abstain_rate": dropped_abstain / dropped_total if dropped_total else 0.0,
    }


def run_stress(df: pd.DataFrame, thresholds: dict[str, float]) -> pd.DataFrame:
    rng = np.random.default_rng(RANDOM_SEED)
    labels = df["label"].to_numpy(dtype=int)
    actual_match = df["actual_match"].to_numpy(dtype=bool)
    pos = labels == 1
    neg = labels == 0
    rows: list[dict[str, Any]] = []
    for scenario, dropout_rate, spoof_rate in SCENARIOS:
        for replicate in range(REPLICATES):
            # Positive true pairs normally carry exact provenance. Dropout simulates
            # missing or partial provenance in an otherwise valid candidate.
            dropped_positive = pos & (rng.random(len(df)) < dropout_rate)
            # Same-CWE negative controls normally do not carry exact provenance.
            # Spoofing simulates a claimed source CVE/commit that does not verify.
            spoofed_negative = neg & (rng.random(len(df)) < spoof_rate)
            claimed_exact = (actual_match & ~dropped_positive) | spoofed_negative
            for policy in POLICY_LABELS:
                rows.append(
                    metric_row(
                        scenario,
                        replicate,
                        policy,
                        df,
                        claimed_exact,
                        dropped_positive,
                        spoofed_negative,
                        thresholds,
                    )
                )
    return pd.DataFrame(rows)


def summarize(reps: pd.DataFrame) -> pd.DataFrame:
    metric_cols = [
        "true_positive",
        "false_admission",
        "false_negative",
        "admitted",
        "rejected",
        "abstained",
        "recall",
        "false_admission_rate",
        "precision",
        "abstain_rate",
        "debt_adjusted_utility",
        "spoofed_negative_admission_rate",
        "dropped_positive_abstain_rate",
    ]
    grouped = reps.groupby(["scenario", "policy", "policy_label"], as_index=False)
    means = grouped[metric_cols].mean()
    stds = grouped[["recall", "false_admission_rate", "abstain_rate", "debt_adjusted_utility"]].std(ddof=1)
    stds = stds.rename(
        columns={
            "recall": "recall_std",
            "false_admission_rate": "false_admission_rate_std",
            "abstain_rate": "abstain_rate_std",
            "debt_adjusted_utility": "debt_adjusted_utility_std",
        }
    )
    out = means.merge(stds, on=["scenario", "policy", "policy_label"], how="left")
    out["scenario_order"] = out["scenario"].map({s[0]: i for i, s in enumerate(SCENARIOS)})
    out["policy_order"] = out["policy"].map({p: i for i, p in enumerate(POLICY_LABELS)})
    out = out.sort_values(["scenario_order", "policy_order"]).drop(columns=["scenario_order", "policy_order"])
    return out


def plot_summary(summary: pd.DataFrame) -> None:
    FIGURES.mkdir(parents=True, exist_ok=True)
    policies = list(POLICY_LABELS)
    colors = {
        "coverage_only": "#4C78A8",
        "claimed_provenance_only": "#F58518",
        "claimed_or_coverage": "#E45756",
        "verified_provenance_only": "#72B7B2",
        "qgdca_verified_abstain": "#54A24B",
    }
    scenarios = [s[0] for s in SCENARIOS]
    x = np.arange(len(scenarios))
    fig, axes = plt.subplots(2, 2, figsize=(12, 7), sharex=True)
    panels = [
        ("false_admission_rate", "False-admission rate"),
        ("recall", "Recall"),
        ("abstain_rate", "Abstain / validation-debt rate"),
        ("debt_adjusted_utility", "Debt-adjusted utility"),
    ]
    for ax, (metric, title) in zip(axes.flat, panels):
        for policy in policies:
            sub = summary[summary["policy"].eq(policy)].set_index("scenario").reindex(scenarios)
            ax.plot(x, sub[metric], marker="o", linewidth=1.8, label=POLICY_LABELS[policy], color=colors[policy])
        ax.set_title(title)
        ax.grid(True, axis="y", alpha=0.25)
        ax.set_xticks(x)
        ax.set_xticklabels(scenarios, rotation=35, ha="right")
    axes[0, 0].set_ylim(bottom=0)
    axes[0, 1].set_ylim(0, 1.05)
    axes[1, 0].set_ylim(bottom=0)
    axes[1, 1].axhline(0, color="black", linewidth=0.8)
    handles, labels = axes[0, 0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", ncol=3, frameon=False)
    fig.suptitle("LXXXIV provenance stress test: missing and spoofed provenance", y=0.99)
    fig.tight_layout(rect=[0, 0, 1, 0.92])
    fig.savefig(OUT_FIG_PDF, bbox_inches="tight")
    fig.savefig(OUT_FIG_PNG, bbox_inches="tight", dpi=220)
    plt.close(fig)


def select(summary: pd.DataFrame, scenario: str, policy: str) -> dict[str, float]:
    row = summary[summary["scenario"].eq(scenario) & summary["policy"].eq(policy)].iloc[0]
    return {k: float(row[k]) for k in [
        "recall",
        "false_admission_rate",
        "precision",
        "abstain_rate",
        "debt_adjusted_utility",
        "spoofed_negative_admission_rate",
        "dropped_positive_abstain_rate",
    ]}


def write_report(df: pd.DataFrame, thresholds: dict[str, float], summary: pd.DataFrame) -> dict[str, Any]:
    clean_q = select(summary, "clean", "qgdca_verified_abstain")
    spoof_claim = select(summary, "spoof_10", "claimed_provenance_only")
    spoof_q = select(summary, "spoof_10", "qgdca_verified_abstain")
    combined_claim = select(summary, "combined_50_10", "claimed_or_coverage")
    combined_q = select(summary, "combined_50_10", "qgdca_verified_abstain")
    dropout_q = select(summary, "dropout_50", "qgdca_verified_abstain")
    cov_clean = select(summary, "clean", "coverage_only")

    n_true = int(df["label"].eq(1).sum())
    n_neg = int(df["label"].eq(0).sum())
    q_false_upper = wilson(0, n_neg)[1]
    result = {
        "experiment": "LXXXIV provenance stress test",
        "generated_at": now_cst(),
        "random_seed": RANDOM_SEED,
        "replicates": REPLICATES,
        "sample": {
            "true_pairs": n_true,
            "same_cwe_controls": n_neg,
        },
        "thresholds": thresholds,
        "key_results": {
            "clean_coverage_only": cov_clean,
            "clean_qgdca_verified_abstain": clean_q,
            "spoof_10_claimed_provenance_only": spoof_claim,
            "spoof_10_qgdca_verified_abstain": spoof_q,
            "dropout_50_qgdca_verified_abstain": dropout_q,
            "combined_50_10_claimed_or_coverage": combined_claim,
            "combined_50_10_qgdca_verified_abstain": combined_q,
            "qgdca_false_rate_wilson95_upper_when_zero": q_false_upper,
        },
        "claim_boundary": (
            "Noisy/spoofed provenance stress over proxy-label pairs; not deployment "
            "repair, not SOTA repair, and not human semantic correctness."
        ),
        "outputs": {
            "replicates_csv": str(OUT_REPLICATES),
            "summary_csv": str(OUT_SUMMARY_CSV),
            "summary_json": str(OUT_SUMMARY_JSON),
            "report_md": str(OUT_REPORT),
            "figure_pdf": str(OUT_FIG_PDF),
            "figure_png": str(OUT_FIG_PNG),
        },
    }
    OUT_SUMMARY_JSON.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    focus = summary[
        summary["scenario"].isin(["clean", "spoof_10", "dropout_50", "combined_50_10"])
        & summary["policy"].isin(["coverage_only", "claimed_provenance_only", "claimed_or_coverage", "qgdca_verified_abstain"])
    ].copy()
    focus["policy"] = pd.Categorical(focus["policy"], categories=list(POLICY_LABELS), ordered=True)
    focus["scenario"] = pd.Categorical(focus["scenario"], categories=[s[0] for s in SCENARIOS], ordered=True)
    focus = focus.sort_values(["scenario", "policy"])

    lines = [
        "# Experiment LXXXIV Provenance Stress Test",
        "",
        f"Generated: {result['generated_at']}",
        "",
        "## Purpose",
        "",
        "LXXXIII showed that provenance gating removes same-CWE borrowed artifacts, but exact provenance can look definitional. LXXXIV tests whether the admission layer remains useful when provenance is missing, partial, or spoofed.",
        "",
        "## Fixed Design",
        "",
        f"- True MegaVul pairs: `{n_true}`.",
        f"- Same-CWE/different-CVE controls: `{n_neg}`.",
        f"- Replicates per scenario: `{REPLICATES}`.",
        f"- Random seed: `{RANDOM_SEED}`.",
        f"- Coverage threshold: `{thresholds['coverage_only']:.6f}` from LXXXIII.",
        f"- QG-DCA score threshold: `{thresholds['qgdca_full']:.6f}` from LXXXIII.",
        "",
        "Perturbations:",
        "",
        "- `dropout_x`: remove exact provenance claims from x% of true pairs.",
        "- `spoof_x`: add false exact-provenance claims to x% of same-CWE controls.",
        "- `combined_x_y`: apply both positive dropout and negative spoofing.",
        "",
        "QG-DCA verified + abstain admits only verified provenance with a passing QG-DCA score. Spoofed provenance is rejected. Missing but promising provenance becomes validation debt, not admitted capital.",
        "",
        "## Focus Results",
        "",
        "| Scenario | Policy | Recall | False rate | Precision | Abstain | Utility |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for _, row in focus.iterrows():
        lines.append(
            f"| {row['scenario']} | {row['policy_label']} | {row['recall']:.3f} | {row['false_admission_rate']:.3f} | {row['precision']:.3f} | {row['abstain_rate']:.3f} | {row['debt_adjusted_utility']:.3f} |"
        )
    lines.extend(
        [
            "",
            "## Main Result",
            "",
            f"Under 10% spoofed negative provenance, `claimed_provenance_only` admits spoofed controls with mean false-admission rate `{spoof_claim['false_admission_rate']:.3f}`, while QG-DCA verified + abstain keeps false admission at `{spoof_q['false_admission_rate']:.3f}`.",
            "",
            f"Under 50% positive provenance dropout, QG-DCA does not turn missing provenance into capital. Its recall falls to `{dropout_q['recall']:.3f}` and abstain/validation-debt rate rises to `{dropout_q['abstain_rate']:.3f}`.",
            "",
            f"Under the combined 50% dropout + 10% spoof setting, `claimed_or_coverage` has false-admission rate `{combined_claim['false_admission_rate']:.3f}`. QG-DCA verified + abstain keeps false admission at `{combined_q['false_admission_rate']:.3f}` while explicitly recording abstention debt `{combined_q['abstain_rate']:.3f}`.",
            "",
            "This turns the exact-provenance result into a falsifiable operating rule: unverifiable provenance is not admitted, and spoofed provenance is rejected rather than counted as knowledge capital.",
            "",
            "## Boundary",
            "",
            result["claim_boundary"],
            "",
            "The experiment still relies on proxy labels from MegaVul-derived pairs. It strengthens provenance/accounting validity, not deployment repair or semantic correctness.",
            "",
            "## Outputs",
            "",
            f"- Replicate CSV: `{OUT_REPLICATES}`",
            f"- Summary CSV: `{OUT_SUMMARY_CSV}`",
            f"- Summary JSON: `{OUT_SUMMARY_JSON}`",
            f"- Figure: `{OUT_FIG_PDF}`",
            "",
            "Document generated: " + now_cst(),
        ]
    )
    OUT_REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return result


def write_reproduce() -> None:
    lines = [
        "# Reproduce LXXXIV Provenance Stress Test",
        "",
        "Run from `/root/mddc`:",
        "",
        "```bash",
        "python3 empirical_validation/experiment_lxxxiv_provenance_stress_test.py",
        "```",
        "",
        "Required input files:",
        "",
        "- `/root/mddc/empirical_validation/results/experiment_lxxxiii_hf_external_component_pairs_20260624.csv`",
        "- `/root/mddc/empirical_validation/results/experiment_lxxxiii_hf_external_component_selected_20260624.csv`",
        "",
        f"Random seed: `{RANDOM_SEED}`.",
        f"Replicates per scenario: `{REPLICATES}`.",
        "",
        "Boundary: this is a noisy/spoofed provenance accounting stress test over proxy-label data. It does not establish deployment repair or semantic correctness.",
        "",
        "Document generated: " + now_cst(),
    ]
    OUT_REPRO.write_text("\n".join(lines) + "\n", encoding="utf-8")


def sync_preview() -> None:
    PREVIEW.mkdir(parents=True, exist_ok=True)
    copies = [
        (OUT_REPORT, "experiment_lxxxiv_provenance_stress_test_20260625.md"),
        (OUT_REPORT, "experiment_lxxxiv_provenance_stress_test_20260625.txt"),
        (OUT_REPRO, "REPRODUCE_LXXXIV_PROVENANCE_STRESS_TEST_20260625.md"),
        (OUT_REPRO, "REPRODUCE_LXXXIV_PROVENANCE_STRESS_TEST_20260625.txt"),
        (OUT_SUMMARY_JSON, "experiment_lxxxiv_provenance_stress_summary_20260625.json"),
        (OUT_SUMMARY_CSV, "experiment_lxxxiv_provenance_stress_summary_20260625.csv"),
        (OUT_FIG_PNG, "fig_experiment_lxxxiv_provenance_stress_test_20260625.png"),
        (OUT_FIG_PDF, "fig_experiment_lxxxiv_provenance_stress_test_20260625.pdf"),
    ]
    for src, name in copies:
        shutil.copy2(src, PREVIEW / name)


def main() -> int:
    RESULTS.mkdir(parents=True, exist_ok=True)
    FIGURES.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    thresholds = load_thresholds()
    df = load_pairs()
    reps = run_stress(df, thresholds)
    summary = summarize(reps)
    reps.to_csv(OUT_REPLICATES, index=False)
    summary.to_csv(OUT_SUMMARY_CSV, index=False)
    plot_summary(summary)
    result = write_report(df, thresholds, summary)
    write_reproduce()
    sync_preview()
    print(json.dumps({
        "summary": str(OUT_SUMMARY_JSON),
        "report": str(OUT_REPORT),
        "figure": str(OUT_FIG_PNG),
        "key_results": result["key_results"],
        "windows_report": "D:\\lunwen\\MDDC_Preview\\latest\\experiment_lxxxiv_provenance_stress_test_20260625.txt",
    }, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
