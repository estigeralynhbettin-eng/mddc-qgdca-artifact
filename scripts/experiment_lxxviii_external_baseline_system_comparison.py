#!/usr/bin/env python3
"""Experiment LXXVIII: external baseline/system comparison.

This experiment compares MDDC qualification gates against external or naive
operational baselines without new model calls. It uses three frozen pools:

1. ASR gate-control pool from LXXIII.
2. CVEfixes patch-context pool with CVSS-only and structural baselines.
3. Existing XLVIII utility pool with qwen/deepseek/claude score baselines.

The purpose is false-admission and validation-debt accounting, not deployment
superiority.
"""

from __future__ import annotations

import os

import json
import math
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import pandas as pd


ROOT = Path(os.environ.get("MDDC_ROOT", "/root/mddc"))
sys.path.insert(0, str(ROOT / "empirical_validation"))

import experiment_lxxiv_cvefixes_independent_gate_replication as lxxiv  # noqa: E402


RESULTS = ROOT / "empirical_validation" / "results"
REPORTS = ROOT / "review_rounds"
FIGURES = ROOT / "empirical_validation" / "figures"
RAW_CVEFIXES = ROOT / "empirical_validation" / "data" / "raw" / "cvefixes"

PREREG = ROOT / "empirical_validation" / "experiment_lxxvii_lxxviii_preregistration_20260624.md"
LXXIII_POLICY = RESULTS / "experiment_lxxiii_gate_stability_and_admission_policy_table_20260624.csv"
LXXIII_CONTROL = RESULTS / "experiment_lxxiii_gate_stability_control_summary_20260624.csv"
LXXVII_SUMMARY = RESULTS / "experiment_lxxvii_patch_differential_oracle_summary_20260624.json"
LXXIV_ROWS = RESULTS / "experiment_lxxiv_cvefixes_independent_gate_rows_20260624.csv"
LXXIV_CONTROLS = RESULTS / "experiment_lxxiv_cvefixes_independent_gate_controls_20260624.csv"
UTILITY_ROWS = RESULTS / "experiment_xlviii_gate_utility_rows.csv"

OUT_ASR = RESULTS / "experiment_lxxviii_external_baseline_asr_policies_20260624.csv"
OUT_CVE_POLICIES = RESULTS / "experiment_lxxviii_external_baseline_cvefixes_policies_20260624.csv"
OUT_CVE_CONTROLS = RESULTS / "experiment_lxxviii_external_baseline_cvefixes_controls_20260624.csv"
OUT_UTILITY = RESULTS / "experiment_lxxviii_external_baseline_utility_policies_20260624.csv"
OUT_SUMMARY = RESULTS / "experiment_lxxviii_external_baseline_system_comparison_summary_20260624.json"
OUT_REPORT = REPORTS / "experiment_lxxviii_external_baseline_system_comparison_20260624.md"
OUT_FIG_PDF = FIGURES / "fig_experiment_lxxviii_external_baseline_system_comparison.pdf"
OUT_FIG_PNG = FIGURES / "fig_experiment_lxxviii_external_baseline_system_comparison.png"

RANDOM_SEED = 20260624
CONTROL_TRIALS = 200
CONTROL_PAIRS_PER_TRIAL = 1500
CVSS_THRESHOLD = 7.0


def now_cst() -> str:
    return datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S +08:00")


def as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, float) and math.isnan(value):
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def wilson(k: int, n: int, z: float = 1.959963984540054) -> list[float]:
    if n <= 0:
        return [float("nan"), float("nan")]
    phat = k / n
    denom = 1 + z * z / n
    centre = phat + z * z / (2 * n)
    margin = z * math.sqrt((phat * (1 - phat) + z * z / (4 * n)) / n)
    return [(centre - margin) / denom, (centre + margin) / denom]


def false_reduction(baseline: float, mddc: float) -> float:
    if baseline <= 0:
        return float("nan")
    return (baseline - mddc) / baseline


def summarize_asr() -> pd.DataFrame:
    policy = pd.read_csv(LXXIII_POLICY)
    controls = pd.read_csv(LXXIII_CONTROL)
    same = controls[controls["control_mode"].eq("same_category_different_rule")].copy()
    rows: list[dict[str, Any]] = []
    for _, prow in policy.iterrows():
        gate = prow["gate"]
        ctrl = same[same["gate"].eq(gate)].iloc[0]
        rows.append(
            {
                "pool": "ASR objective gate controls",
                "policy": gate,
                "n_true": int(prow["n"]),
                "true_admitted": int(prow["true_admitted"]),
                "true_admission_rate": float(prow["true_rate"]),
                "true_wilson_low": float(prow["wilson_low"]),
                "true_wilson_high": float(prow["wilson_high"]),
                "negative_mode": "same_category_different_rule",
                "negative_trials": int(ctrl["trials"]),
                "negative_n_per_trial": int(ctrl["n_pairs"]),
                "false_admissions_mean": float(ctrl["control_mean_admitted"]),
                "false_admissions_max": int(ctrl["control_max_admitted"]),
                "false_admission_rate_mean": float(ctrl["control_mean_admitted"]) / float(ctrl["n_pairs"]),
                "validation_debt_per_100": 100.0 * float(ctrl["control_mean_admitted"]) / float(ctrl["n_pairs"]),
                "reference": "LXXIII same-category different-rule controls",
            }
        )
    if LXXVII_SUMMARY.exists():
        data = json.loads(LXXVII_SUMMARY.read_text(encoding="utf-8"))
        for ctrl in data.get("negative_controls", []):
            rows.append(
                {
                    "pool": "ASR patch-differential oracle",
                    "policy": "mddc_strict_patch_differential_surrogate",
                    "n_true": int(data["n_strict_admissions"]),
                    "true_admitted": int(data["true_oracle_validated"]),
                    "true_admission_rate": float(data["true_oracle_rate"]),
                    "true_wilson_low": float(data["true_oracle_wilson95"][0]),
                    "true_wilson_high": float(data["true_oracle_wilson95"][1]),
                    "negative_mode": ctrl["mode"],
                    "negative_trials": int(ctrl["trials"]),
                    "negative_n_per_trial": int(data["n_strict_admissions"]),
                    "false_admissions_mean": float(ctrl["mean_false_validations"]),
                    "false_admissions_max": int(ctrl["max_false_validations"]),
                    "false_admission_rate_mean": float(ctrl["mean_false_validation_rate"]),
                    "validation_debt_per_100": 100.0 * float(ctrl["mean_false_validation_rate"]),
                    "reference": "LXXVII patch-diff surrogate controls",
                }
            )
    df = pd.DataFrame(rows)
    df.to_csv(OUT_ASR, index=False)
    return df


def cve_cvss(row: pd.Series) -> float:
    for col in ["cvss3_base_score", "cvss2_base_score"]:
        value = row.get(col)
        if value is not None and not (isinstance(value, float) and math.isnan(value)):
            try:
                return float(value)
            except (TypeError, ValueError):
                pass
    severity = str(row.get("severity", "")).strip().upper()
    return {"CRITICAL": 9.0, "HIGH": 8.0, "MEDIUM": 5.0, "LOW": 2.0}.get(severity, float("nan"))


def load_cvefixes_cvss_columns() -> pd.DataFrame:
    columns = ["cve_id", "hash", "cvss2_base_score", "cvss3_base_score", "severity"]
    frames = [pd.read_parquet(path, columns=columns) for path in sorted(RAW_CVEFIXES.glob("*.parquet"))]
    df = pd.concat(frames, ignore_index=True)
    df = df.drop_duplicates(subset=["cve_id", "hash"]).reset_index(drop=True)
    return df


def prepare_cve_records() -> tuple[pd.DataFrame, list[dict[str, Any]], list[dict[str, Any]]]:
    raw = lxxiv.load_cvefixes()
    refs, cands, rows = lxxiv.prepare_records(raw)
    df = pd.DataFrame(rows)
    cvss_values = []
    for _, raw_row in raw.reset_index(drop=True).iterrows():
        cvss_values.append(cve_cvss(raw_row))
    df["cvss"] = cvss_values
    for idx, value in enumerate(cvss_values):
        refs[idx]["cvss"] = value
    return df, refs, cands


def cve_policy_decisions(score: dict[str, bool], ref: dict[str, Any]) -> dict[str, bool]:
    cvss = ref.get("cvss")
    high = bool(cvss is not None and not (isinstance(cvss, float) and math.isnan(cvss)) and float(cvss) >= CVSS_THRESHOLD)
    strict = bool(score["strict_mddc_gate"])
    return {
        "cvss_only": high,
        "structural_only": bool(score.get("structural_only", score.get("structural_only_gate", False))),
        "category_gate": bool(score["category_gate"]),
        "mddc_strict": strict,
        "cvss_plus_mddc_strict": high and strict,
    }


def choose_cve_pairs(
    mode: str,
    refs: list[dict[str, Any]],
    rng: random.Random,
    n_pairs: int,
) -> list[tuple[int, int]]:
    indices = list(range(len(refs)))
    pairs: list[tuple[int, int]] = []
    by_category: dict[str, list[int]] = {}
    for idx, ref in enumerate(refs):
        by_category.setdefault(str(ref["ref_category"]), []).append(idx)
    while len(pairs) < n_pairs:
        i = rng.choice(indices)
        if mode == "any_deranged":
            choices = [j for j in indices if j != i]
        elif mode == "cross_category":
            choices = [j for j in indices if refs[j]["ref_category"] != refs[i]["ref_category"]]
        elif mode == "same_category_different_cve":
            choices = [j for j in by_category.get(str(refs[i]["ref_category"]), []) if j != i]
        else:
            raise ValueError(mode)
        if not choices:
            continue
        pairs.append((i, rng.choice(choices)))
    return pairs


def summarize_cvefixes() -> tuple[pd.DataFrame, pd.DataFrame]:
    raw = load_cvefixes_cvss_columns().reset_index(drop=True)
    rows_df = pd.read_csv(LXXIV_ROWS).copy()
    rows_df = rows_df.sort_values("idx").reset_index(drop=True)
    cvss_values = [cve_cvss(row) for _, row in raw.iterrows()]
    rows_df["cvss"] = cvss_values
    policy_names = ["cvss_only", "structural_only", "category_gate", "mddc_strict"]
    true_counts = {
        "cvss_only": int((rows_df["cvss"].fillna(-1).astype(float) >= CVSS_THRESHOLD).sum()),
        "structural_only": int(rows_df["structural_only_gate"].astype(bool).sum()),
        "category_gate": int(rows_df["category_gate"].astype(bool).sum()),
        "mddc_strict": int(rows_df["strict_mddc_gate"].astype(bool).sum()),
    }
    cvss_available = int(rows_df["cvss"].notna().sum())

    policy_rows: list[dict[str, Any]] = []
    for name in policy_names:
        k = true_counts[name]
        policy_rows.append(
            {
                "pool": "CVEfixes true pairs",
                "policy": name,
                "n_true": len(rows_df),
                "true_admitted": k,
                "true_admission_rate": k / len(rows_df),
                "true_wilson_low": wilson(k, len(rows_df))[0],
                "true_wilson_high": wilson(k, len(rows_df))[1],
                "cvss_available": cvss_available,
            }
        )

    control_rows: list[dict[str, Any]] = []
    lxxiv_controls = pd.read_csv(LXXIV_CONTROLS)
    rename = {
        "structural_only_admitted": "structural_only",
        "category_gate_admitted": "category_gate",
        "strict_mddc_gate_admitted": "mddc_strict",
    }
    for _, row in lxxiv_controls.iterrows():
        for source_col, policy in rename.items():
            false_count = int(row[source_col])
            n_pairs = int(row["n_pairs"])
            control_rows.append(
                {
                    "mode": row["mode"],
                    "trial": int(row["trial"]),
                    "policy": policy,
                    "n_pairs": n_pairs,
                    "false_admissions": false_count,
                    "false_admission_rate": false_count / n_pairs if n_pairs else float("nan"),
                }
            )

    rng = random.Random(RANDOM_SEED)
    non_other = rows_df[rows_df["ref_category"].ne("other")].copy()
    high_cvss_flags = (non_other["cvss"].fillna(-1).astype(float) >= CVSS_THRESHOLD).to_list()
    for mode in ["any_deranged", "cross_category", "same_category_different_cve"]:
        for trial in range(CONTROL_TRIALS):
            sample = [rng.choice(high_cvss_flags) for _ in range(CONTROL_PAIRS_PER_TRIAL)]
            false_count = int(sum(sample))
            control_rows.append(
                {
                    "mode": mode,
                    "trial": trial,
                    "policy": "cvss_only",
                    "n_pairs": CONTROL_PAIRS_PER_TRIAL,
                    "false_admissions": false_count,
                    "false_admission_rate": false_count / CONTROL_PAIRS_PER_TRIAL,
                }
            )

    policies = pd.DataFrame(policy_rows)
    controls = pd.DataFrame(control_rows)
    policies.to_csv(OUT_CVE_POLICIES, index=False)
    controls.to_csv(OUT_CVE_CONTROLS, index=False)
    return policies, controls


def summarize_utility() -> pd.DataFrame:
    if not UTILITY_ROWS.exists():
        df = pd.DataFrame()
        df.to_csv(OUT_UTILITY, index=False)
        return df
    df = pd.read_csv(UTILITY_ROWS)
    policies = {
        "qwen_confidence_ge_0_7": df["qwen_confidence"].fillna(0).astype(float) >= 0.7,
        "deepseek_score_ge_4": df["deepseek_score"].fillna(0).astype(float) >= 4.0,
        "claude_score_ge_4": df["claude_score"].fillna(0).astype(float) >= 4.0,
        "mean_judge_score_ge_4": df["mean_judge_score"].fillna(0).astype(float) >= 4.0,
        "structural_core_gate": df["structural_core_gate"].apply(as_bool),
        "mddc_utility_gate": (
            df["parse_ok"].apply(as_bool)
            & ~df["abstain"].apply(as_bool)
            & df["api_match"].apply(as_bool)
            & df["category_match"].apply(as_bool)
            & df["executable_condition_present"].apply(as_bool)
            & df["transferable_property_present"].apply(as_bool)
            & (df["quality_score"].fillna(0).astype(float) >= 0.8)
        ),
    }
    correct = df["correct_proxy"].apply(as_bool)
    rows: list[dict[str, Any]] = []
    for name, admitted in policies.items():
        admitted = admitted.astype(bool)
        tp = int((admitted & correct).sum())
        fp = int((admitted & ~correct).sum())
        fn = int((~admitted & correct).sum())
        n_admit = int(admitted.sum())
        n = len(df)
        rows.append(
            {
                "pool": "XLVIII utility pool",
                "policy": name,
                "n": n,
                "admitted": n_admit,
                "true_positive": tp,
                "false_admission": fp,
                "false_negative": fn,
                "admission_rate": n_admit / n,
                "precision": tp / n_admit if n_admit else float("nan"),
                "recall": tp / int(correct.sum()) if int(correct.sum()) else float("nan"),
                "false_admission_rate_among_admitted": fp / n_admit if n_admit else 0.0,
                "validation_debt_per_100_admissions": 100.0 * fp / n_admit if n_admit else 0.0,
            }
        )
    out = pd.DataFrame(rows)
    out.to_csv(OUT_UTILITY, index=False)
    return out


def aggregate_cve_controls(controls: pd.DataFrame) -> pd.DataFrame:
    return (
        controls.groupby(["mode", "policy"])
        .agg(
            trials=("trial", "count"),
            n_pairs=("n_pairs", "mean"),
            mean_false_admissions=("false_admissions", "mean"),
            max_false_admissions=("false_admissions", "max"),
            mean_false_admission_rate=("false_admission_rate", "mean"),
            max_false_admission_rate=("false_admission_rate", "max"),
        )
        .reset_index()
    )


def make_figure(asr: pd.DataFrame, cve_ctrl_agg: pd.DataFrame, utility: pd.DataFrame) -> None:
    FIGURES.mkdir(parents=True, exist_ok=True)
    fig, axes = plt.subplots(1, 3, figsize=(12, 3.6))

    asr_same = asr[(asr["pool"].eq("ASR objective gate controls")) & (asr["negative_mode"].eq("same_category_different_rule"))]
    axes[0].bar(asr_same["policy"], asr_same["false_admission_rate_mean"], color="#2f5597")
    axes[0].set_title("ASR close-control false rate")
    axes[0].set_ylim(0, max(0.3, float(asr_same["false_admission_rate_mean"].max()) * 1.2))
    axes[0].tick_params(axis="x", rotation=35, labelsize=7)

    cve_same = cve_ctrl_agg[cve_ctrl_agg["mode"].eq("same_category_different_cve")]
    axes[1].bar(cve_same["policy"], cve_same["mean_false_admission_rate"], color="#70ad47")
    axes[1].set_title("CVEfixes false rate")
    axes[1].set_ylim(0, 1)
    axes[1].tick_params(axis="x", rotation=35, labelsize=7)

    if not utility.empty:
        axes[2].bar(utility["policy"], utility["false_admission_rate_among_admitted"], color="#a5a5a5")
        axes[2].set_title("Utility pool false among admitted")
        axes[2].set_ylim(0, 1)
        axes[2].tick_params(axis="x", rotation=35, labelsize=7)
    else:
        axes[2].axis("off")

    fig.tight_layout()
    fig.savefig(OUT_FIG_PDF)
    fig.savefig(OUT_FIG_PNG, dpi=220)
    plt.close(fig)


def main() -> int:
    RESULTS.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)

    asr = summarize_asr()
    cve_policies, cve_controls = summarize_cvefixes()
    cve_ctrl_agg = aggregate_cve_controls(cve_controls)
    utility = summarize_utility()
    make_figure(asr, cve_ctrl_agg, utility)

    def cve_false(mode: str, policy: str) -> float:
        row = cve_ctrl_agg[(cve_ctrl_agg["mode"].eq(mode)) & (cve_ctrl_agg["policy"].eq(policy))]
        return float(row.iloc[0]["mean_false_admission_rate"]) if not row.empty else float("nan")

    structural_false = cve_false("same_category_different_cve", "structural_only")
    cvss_false = cve_false("same_category_different_cve", "cvss_only")
    mddc_false = cve_false("same_category_different_cve", "mddc_strict")
    cvss_reduction = false_reduction(cvss_false, mddc_false)
    structural_reduction = false_reduction(structural_false, mddc_false)

    utility_summary = {}
    if not utility.empty:
        for policy in ["qwen_confidence_ge_0_7", "deepseek_score_ge_4", "mddc_utility_gate"]:
            row = utility[utility["policy"].eq(policy)]
            if not row.empty:
                utility_summary[policy] = row.iloc[0].to_dict()

    asr_strict = asr[(asr["pool"].eq("ASR objective gate controls")) & (asr["policy"].eq("strict_hard_capital"))]
    asr_balanced = asr[(asr["pool"].eq("ASR objective gate controls")) & (asr["policy"].eq("balanced_candidate_pool"))]
    asr_strict_false = float(asr_strict.iloc[0]["false_admission_rate_mean"]) if not asr_strict.empty else float("nan")
    asr_balanced_false = float(asr_balanced.iloc[0]["false_admission_rate_mean"]) if not asr_balanced.empty else float("nan")

    summary = {
        "experiment": "LXXVIII external baseline/system comparison",
        "generated_at": now_cst(),
        "preregistration": str(PREREG),
        "claim_boundary": "False-admission and validation-debt comparison; not deployment superiority.",
        "random_seed": RANDOM_SEED,
        "control_trials": CONTROL_TRIALS,
        "control_pairs_per_trial": CONTROL_PAIRS_PER_TRIAL,
        "headline": {
            "asr_strict_same_category_false_rate": asr_strict_false,
            "asr_balanced_same_category_false_rate": asr_balanced_false,
            "cvefixes_same_category_cvss_only_false_rate": cvss_false,
            "cvefixes_same_category_structural_false_rate": structural_false,
            "cvefixes_same_category_mddc_strict_false_rate": mddc_false,
            "mddc_false_reduction_vs_cvss_only": cvss_reduction,
            "mddc_false_reduction_vs_structural_only": structural_reduction,
            "meets_50pct_vs_cvss": bool(cvss_reduction >= 0.50),
            "meets_50pct_vs_structural": bool(structural_reduction >= 0.50),
        },
        "utility_pool": utility_summary,
        "outputs": {
            "asr_policies_csv": str(OUT_ASR),
            "cvefixes_policies_csv": str(OUT_CVE_POLICIES),
            "cvefixes_controls_csv": str(OUT_CVE_CONTROLS),
            "utility_policies_csv": str(OUT_UTILITY),
            "summary_json": str(OUT_SUMMARY),
            "report_md": str(OUT_REPORT),
            "figure_pdf": str(OUT_FIG_PDF),
            "figure_png": str(OUT_FIG_PNG),
        },
    }
    OUT_SUMMARY.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    cve_ctrl_agg_path = RESULTS / "experiment_lxxviii_external_baseline_cvefixes_controls_aggregate_20260624.csv"
    cve_ctrl_agg.to_csv(cve_ctrl_agg_path, index=False)
    summary["outputs"]["cvefixes_controls_aggregate_csv"] = str(cve_ctrl_agg_path)
    OUT_SUMMARY.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    lines = [
        "# Experiment LXXVIII External Baseline/System Comparison",
        "",
        f"Generated: {summary['generated_at']}",
        "",
        "## Material Passport",
        "",
        "- Mode: code experiment / reproducibility validation",
        "- Data access: existing public datasets and frozen prior experiment rows",
        "- Pre-registration: `" + str(PREREG) + "`",
        "- Claim boundary: false-admission accounting, not deployment-rate superiority",
        "",
        "## Headline",
        "",
        f"- ASR strict same-category false rate: `{asr_strict_false:.6f}`",
        f"- ASR balanced same-category false rate: `{asr_balanced_false:.6f}`",
        f"- CVEfixes CVSS-only same-category false rate: `{cvss_false:.6f}`",
        f"- CVEfixes structural-only same-category false rate: `{structural_false:.6f}`",
        f"- CVEfixes MDDC-strict same-category false rate: `{mddc_false:.6f}`",
        f"- MDDC false-admission reduction vs CVSS-only: `{cvss_reduction:.6f}`",
        f"- MDDC false-admission reduction vs structural-only: `{structural_reduction:.6f}`",
        "",
        "## Interpretation",
        "",
        "This experiment tests whether qualification-gated admission reduces false capital admission against external or naive baselines. "
        "It should be read together with LXXVII: LXXVII did not clear the behavioral-oracle threshold, so LXXVIII supports false-admission accounting rather than behavioral semantic truth.",
        "",
        "## Outputs",
        "",
        f"- ASR policies: `{OUT_ASR}`",
        f"- CVEfixes policies: `{OUT_CVE_POLICIES}`",
        f"- CVEfixes controls: `{OUT_CVE_CONTROLS}`",
        f"- Utility policies: `{OUT_UTILITY}`",
        f"- Summary: `{OUT_SUMMARY}`",
        f"- Figure PDF: `{OUT_FIG_PDF}`",
        "",
        "Document generated: " + now_cst(),
    ]
    OUT_REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"summary": str(OUT_SUMMARY), "report": str(OUT_REPORT), "headline": summary["headline"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

