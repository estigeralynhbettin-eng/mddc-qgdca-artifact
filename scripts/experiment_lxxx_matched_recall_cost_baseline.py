#!/usr/bin/env python3
"""Experiment LXXX: matched-recall and cost-aware baseline comparison.

Claude Opus 4.8 flagged that the existing false-admission comparisons could be
partly explained by recall loss. This experiment fixes the recall level to the
MDDC strict gate on the true-pair pool, then compares false admissions on
same-category controls against tuned score-only and coverage-only baselines.

The experiment uses only existing public datasets and frozen result files. It is
not a deployment or human semantic validation experiment.
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
import experiment_lxxix_bigvul_cross_dataset_replication as lxxix  # noqa: E402


RESULTS = ROOT / "empirical_validation" / "results"
REPORTS = ROOT / "review_rounds"
FIGURES = ROOT / "empirical_validation" / "figures"
RAW_BIGVUL = ROOT / "empirical_validation" / "data" / "raw" / "bigvul" / "all_c_cpp_release2.0.csv"
RAW_CVEFIXES = ROOT / "empirical_validation" / "data" / "raw" / "cvefixes"
UTILITY_ROWS = RESULTS / "experiment_xlviii_gate_utility_rows.csv"

OUT_DATASET_ROWS = RESULTS / "experiment_lxxx_matched_recall_dataset_policies_20260624.csv"
OUT_DATASET_CONTROLS = RESULTS / "experiment_lxxx_matched_recall_control_trials_20260624.csv"
OUT_DATASET_AGG = RESULTS / "experiment_lxxx_matched_recall_control_aggregate_20260624.csv"
OUT_UTILITY = RESULTS / "experiment_lxxx_matched_recall_utility_policy_table_20260624.csv"
OUT_SUMMARY = RESULTS / "experiment_lxxx_matched_recall_cost_baseline_summary_20260624.json"
OUT_REPORT = REPORTS / "experiment_lxxx_matched_recall_cost_baseline_20260624.md"
OUT_FIG_PDF = FIGURES / "fig_experiment_lxxx_matched_recall_cost_baseline.pdf"
OUT_FIG_PNG = FIGURES / "fig_experiment_lxxx_matched_recall_cost_baseline.png"

RANDOM_SEED = 20260624
CONTROL_TRIALS = 200
CONTROL_PAIRS_PER_TRIAL = 1500


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


def cve_cvss(row: pd.Series) -> float:
    for col in ["cvss3_base_score", "cvss2_base_score"]:
        value = row.get(col)
        if value is None or (isinstance(value, float) and math.isnan(value)):
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    severity = str(row.get("severity", "")).strip().upper()
    return {"CRITICAL": 9.0, "HIGH": 8.0, "MEDIUM": 5.0, "LOW": 2.0}.get(severity, float("nan"))


def coverage(ref: dict[str, Any], cand: dict[str, Any]) -> float:
    ref_tokens = ref.get("ref_tokens", set())
    cand_tokens = cand.get("candidate_tokens", set())
    return len(ref_tokens & cand_tokens) / max(1, len(ref_tokens))


def choose_threshold(scores: list[float], target_count: int) -> dict[str, Any]:
    finite = [float(s) for s in scores if not math.isnan(float(s))]
    if not finite:
        return {"threshold": float("nan"), "admitted": 0, "recall": 0.0}
    candidates = sorted(set(finite), reverse=True)
    best = None
    n = len(scores)
    for threshold in candidates:
        admitted = sum((not math.isnan(float(s))) and float(s) >= threshold for s in scores)
        diff = abs(admitted - target_count)
        item = {"threshold": threshold, "admitted": admitted, "recall": admitted / n if n else 0.0, "diff": diff}
        if best is None or (item["diff"], -item["threshold"]) < (best["diff"], -best["threshold"]):
            best = item
    return best or {"threshold": float("nan"), "admitted": 0, "recall": 0.0}


def choose_threshold_at_least_tp(scores: pd.Series, correct: pd.Series, target_tp: int) -> dict[str, Any]:
    values = sorted({float(v) for v in scores.dropna().tolist()}, reverse=True)
    best = None
    for threshold in values:
        admitted = scores.fillna(float("-inf")).astype(float) >= threshold
        tp = int((admitted & correct).sum())
        fp = int((admitted & ~correct).sum())
        if tp < target_tp:
            continue
        item = {
            "threshold": threshold,
            "admitted": int(admitted.sum()),
            "true_positive": tp,
            "false_admission": fp,
            "false_negative": int((~admitted & correct).sum()),
            "precision": tp / int(admitted.sum()) if int(admitted.sum()) else float("nan"),
            "recall": tp / int(correct.sum()) if int(correct.sum()) else float("nan"),
        }
        if best is None or (item["false_admission"], item["admitted"], -item["threshold"]) < (
            best["false_admission"],
            best["admitted"],
            -best["threshold"],
        ):
            best = item
    if best is None:
        admitted = scores.notna()
        tp = int((admitted & correct).sum())
        fp = int((admitted & ~correct).sum())
        best = {
            "threshold": float("nan"),
            "admitted": int(admitted.sum()),
            "true_positive": tp,
            "false_admission": fp,
            "false_negative": int((~admitted & correct).sum()),
            "precision": tp / int(admitted.sum()) if int(admitted.sum()) else float("nan"),
            "recall": tp / int(correct.sum()) if int(correct.sum()) else float("nan"),
        }
    return best


def sample_same_category_pairs(refs: list[dict[str, Any]], rng: random.Random) -> list[tuple[int, int]]:
    by_category: dict[str, list[int]] = {}
    for idx, ref in enumerate(refs):
        by_category.setdefault(str(ref["ref_category"]), []).append(idx)
    usable = [idx for idx, ref in enumerate(refs) if ref["ref_category"] != "other" and len(by_category[str(ref["ref_category"])]) > 1]
    pairs: list[tuple[int, int]] = []
    for _ in range(CONTROL_PAIRS_PER_TRIAL):
        ref_idx = rng.choice(usable)
        pool = by_category[str(refs[ref_idx]["ref_category"])]
        cand_idx = rng.choice(pool)
        while cand_idx == ref_idx:
            cand_idx = rng.choice(pool)
        pairs.append((ref_idx, cand_idx))
    return pairs


def load_cvefixes() -> tuple[str, list[dict[str, Any]], list[dict[str, Any]], pd.DataFrame]:
    raw = lxxiv.load_cvefixes().reset_index(drop=True)
    refs, cands, rows = lxxiv.prepare_records(raw)
    rows_df = pd.DataFrame(rows)
    score_columns = ["cve_id", "hash", "cvss2_base_score", "cvss3_base_score", "severity"]
    score_frames = [pd.read_parquet(path, columns=score_columns) for path in sorted(RAW_CVEFIXES.glob("*.parquet"))]
    score_df = pd.concat(score_frames, ignore_index=True).drop_duplicates(subset=["cve_id", "hash"]).reset_index(drop=True)
    if len(score_df) != len(rows_df):
        merged = rows_df[["cve_id", "hash"]].merge(score_df, on=["cve_id", "hash"], how="left")
        rows_df["risk_score"] = [cve_cvss(row) for _, row in merged.iterrows()]
    else:
        rows_df["risk_score"] = [cve_cvss(row) for _, row in score_df.iterrows()]
    for idx, value in enumerate(rows_df["risk_score"].tolist()):
        refs[idx]["risk_score"] = value
    return "CVEfixes", refs, cands, rows_df


def load_bigvul() -> tuple[str, list[dict[str, Any]], list[dict[str, Any]], pd.DataFrame]:
    raw = pd.read_csv(RAW_BIGVUL)
    refs, cands, rows = lxxix.prepare_records(raw)
    rows_df = pd.DataFrame(rows)
    rows_df["risk_score"] = pd.to_numeric(rows_df["score"], errors="coerce")
    for idx, value in enumerate(rows_df["risk_score"].tolist()):
        refs[idx]["risk_score"] = value
    return "BigVul", refs, cands, rows_df


def dataset_policy_eval(name: str, refs: list[dict[str, Any]], cands: list[dict[str, Any]], rows_df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    n = len(rows_df)
    strict_true = rows_df["strict_mddc_gate"].apply(as_bool)
    target_count = int(strict_true.sum())
    target_recall = target_count / n if n else 0.0

    risk_threshold = choose_threshold(pd.to_numeric(rows_df["risk_score"], errors="coerce").fillna(float("nan")).tolist(), target_count)
    coverage_threshold = choose_threshold(pd.to_numeric(rows_df["token_coverage"], errors="coerce").fillna(float("nan")).tolist(), target_count)

    true_policies = [
        {
            "dataset": name,
            "policy": "mddc_strict_gate",
            "threshold": lxxiv.TOKEN_COVERAGE_THRESHOLD if name == "CVEfixes" else lxxix.TOKEN_COVERAGE_THRESHOLD,
            "true_admitted": target_count,
            "n_true": n,
            "true_recall": target_recall,
            "matched_to_mddc_recall": True,
            "policy_note": "category-consistent token evidence gate",
        },
        {
            "dataset": name,
            "policy": "risk_score_tuned",
            "threshold": risk_threshold["threshold"],
            "true_admitted": int(risk_threshold["admitted"]),
            "n_true": n,
            "true_recall": float(risk_threshold["recall"]),
            "matched_to_mddc_recall": abs(float(risk_threshold["recall"]) - target_recall) <= 0.02,
            "policy_note": "CVSS/BigVul score threshold tuned to MDDC recall",
        },
        {
            "dataset": name,
            "policy": "coverage_only_tuned",
            "threshold": coverage_threshold["threshold"],
            "true_admitted": int(coverage_threshold["admitted"]),
            "n_true": n,
            "true_recall": float(coverage_threshold["recall"]),
            "matched_to_mddc_recall": abs(float(coverage_threshold["recall"]) - target_recall) <= 0.02,
            "policy_note": "token-coverage threshold without category consistency",
        },
        {
            "dataset": name,
            "policy": "random_at_mddc_recall",
            "threshold": target_recall,
            "true_admitted": target_count,
            "n_true": n,
            "true_recall": target_recall,
            "matched_to_mddc_recall": True,
            "policy_note": "random admission at the same true-pair recall",
        },
    ]

    rng = random.Random(RANDOM_SEED + (0 if name == "CVEfixes" else 1000))
    control_rows: list[dict[str, Any]] = []
    for trial in range(CONTROL_TRIALS):
        pairs = sample_same_category_pairs(refs, rng)
        counts = {row["policy"]: 0 for row in true_policies}
        for ref_idx, cand_idx in pairs:
            ref = refs[ref_idx]
            cand = cands[cand_idx]
            cov = coverage(ref, cand)
            category = bool(cand.get("structural")) and ref["ref_category"] != "other" and ref["ref_category"] in cand.get("candidate_categories", set())
            strict = category and cov >= (lxxiv.TOKEN_COVERAGE_THRESHOLD if name == "CVEfixes" else lxxix.TOKEN_COVERAGE_THRESHOLD)
            risk = ref.get("risk_score", float("nan"))
            risk_admit = (not math.isnan(float(risk))) and float(risk) >= float(risk_threshold["threshold"])
            coverage_admit = cov >= float(coverage_threshold["threshold"])
            counts["mddc_strict_gate"] += int(strict)
            counts["risk_score_tuned"] += int(risk_admit)
            counts["coverage_only_tuned"] += int(coverage_admit)
            counts["random_at_mddc_recall"] += int(rng.random() < target_recall)
        for policy, count in counts.items():
            control_rows.append(
                {
                    "dataset": name,
                    "trial": trial,
                    "policy": policy,
                    "control_mode": "same_category_different_cve",
                    "n_pairs": len(pairs),
                    "false_admissions": count,
                    "false_admission_rate": count / len(pairs) if pairs else float("nan"),
                }
            )
    return pd.DataFrame(true_policies), pd.DataFrame(control_rows)


def utility_policy_eval() -> pd.DataFrame:
    df = pd.read_csv(UTILITY_ROWS)
    correct = df["correct_proxy"].apply(as_bool)
    mddc = (
        df["parse_ok"].apply(as_bool)
        & ~df["abstain"].apply(as_bool)
        & df["api_match"].apply(as_bool)
        & df["category_match"].apply(as_bool)
        & df["executable_condition_present"].apply(as_bool)
        & df["transferable_property_present"].apply(as_bool)
        & (df["quality_score"].fillna(0).astype(float) >= 0.8)
    )
    mddc_tp = int((mddc & correct).sum())
    total_true = int(correct.sum())

    rows: list[dict[str, Any]] = []

    def add_row(policy: str, admitted: pd.Series, threshold: Any, note: str) -> None:
        tp = int((admitted & correct).sum())
        fp = int((admitted & ~correct).sum())
        fn = int((~admitted & correct).sum())
        n_admit = int(admitted.sum())
        rows.append(
            {
                "pool": "XLVIII utility pool",
                "policy": policy,
                "threshold": threshold,
                "target_true_positive": mddc_tp,
                "n": len(df),
                "total_true": total_true,
                "admitted": n_admit,
                "true_positive": tp,
                "false_admission": fp,
                "false_negative": fn,
                "precision": tp / n_admit if n_admit else float("nan"),
                "recall": tp / total_true if total_true else float("nan"),
                "false_admissions_per_true_positive": fp / tp if tp else float("inf"),
                "review_load_per_true_positive": n_admit / tp if tp else float("inf"),
                "policy_note": note,
            }
        )

    add_row("mddc_utility_gate", mddc, 0.8, "full QG-DCA utility gate")
    for col, label in [
        ("qwen_confidence", "qwen_confidence_tuned"),
        ("deepseek_score", "deepseek_score_tuned"),
        ("claude_score", "claude_score_tuned"),
        ("mean_judge_score", "mean_judge_score_tuned"),
        ("quality_score", "quality_score_only_tuned"),
    ]:
        info = choose_threshold_at_least_tp(pd.to_numeric(df[col], errors="coerce"), correct, mddc_tp)
        admitted = pd.to_numeric(df[col], errors="coerce").fillna(float("-inf")) >= float(info["threshold"])
        add_row(label, admitted, info["threshold"], f"{col} threshold tuned to reach at least MDDC true-positive count")
    add_row("structural_core_gate", df["structural_core_gate"].apply(as_bool), True, "structural fields without full utility gate")
    return pd.DataFrame(rows)


def aggregate_controls(control_df: pd.DataFrame, policy_df: pd.DataFrame) -> pd.DataFrame:
    agg = (
        control_df.groupby(["dataset", "policy"])
        .agg(
            trials=("trial", "count"),
            n_pairs=("n_pairs", "mean"),
            mean_false_admissions=("false_admissions", "mean"),
            mean_false_admission_rate=("false_admission_rate", "mean"),
            max_false_admission_rate=("false_admission_rate", "max"),
        )
        .reset_index()
    )
    return agg.merge(policy_df, on=["dataset", "policy"], how="left")


def make_figure(agg: pd.DataFrame, utility: pd.DataFrame) -> None:
    FIGURES.mkdir(parents=True, exist_ok=True)
    fig, axes = plt.subplots(1, 3, figsize=(12.0, 3.4))
    colors = {
        "mddc_strict_gate": "#2f5597",
        "risk_score_tuned": "#a5a5a5",
        "coverage_only_tuned": "#70ad47",
        "random_at_mddc_recall": "#c00000",
    }
    for ax, dataset in zip(axes[:2], ["CVEfixes", "BigVul"]):
        sub = agg[agg["dataset"].eq(dataset)].copy()
        order = ["risk_score_tuned", "coverage_only_tuned", "random_at_mddc_recall", "mddc_strict_gate"]
        sub["policy"] = pd.Categorical(sub["policy"], categories=order, ordered=True)
        sub = sub.sort_values("policy")
        ax.bar(sub["policy"].astype(str), sub["mean_false_admission_rate"], color=[colors[p] for p in sub["policy"].astype(str)])
        ax.set_ylim(0, 1.0)
        ax.set_title(f"{dataset}: matched recall")
        ax.set_ylabel("Same-category false rate")
        ax.tick_params(axis="x", rotation=35, labelsize=7)
    util_order = ["qwen_confidence_tuned", "deepseek_score_tuned", "quality_score_only_tuned", "structural_core_gate", "mddc_utility_gate"]
    util = utility[utility["policy"].isin(util_order)].copy()
    util["policy"] = pd.Categorical(util["policy"], categories=util_order, ordered=True)
    util = util.sort_values("policy")
    axes[2].bar(util["policy"].astype(str), util["false_admissions_per_true_positive"], color="#8064a2")
    axes[2].set_title("Utility pool: debt per TP")
    axes[2].set_ylabel("False admissions / TP")
    axes[2].tick_params(axis="x", rotation=35, labelsize=7)
    fig.tight_layout()
    fig.savefig(OUT_FIG_PDF)
    fig.savefig(OUT_FIG_PNG, dpi=220)
    plt.close(fig)


def main() -> int:
    RESULTS.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    FIGURES.mkdir(parents=True, exist_ok=True)

    policy_frames = []
    control_frames = []
    for loader in [load_cvefixes, load_bigvul]:
        name, refs, cands, rows_df = loader()
        p, c = dataset_policy_eval(name, refs, cands, rows_df)
        policy_frames.append(p)
        control_frames.append(c)
    policies = pd.concat(policy_frames, ignore_index=True)
    controls = pd.concat(control_frames, ignore_index=True)
    utility = utility_policy_eval()
    agg = aggregate_controls(controls, policies)

    policies.to_csv(OUT_DATASET_ROWS, index=False)
    controls.to_csv(OUT_DATASET_CONTROLS, index=False)
    agg.to_csv(OUT_DATASET_AGG, index=False)
    utility.to_csv(OUT_UTILITY, index=False)
    make_figure(agg, utility)

    def get_false(dataset: str, policy: str) -> float:
        row = agg[agg["dataset"].eq(dataset) & agg["policy"].eq(policy)]
        return float(row.iloc[0]["mean_false_admission_rate"]) if not row.empty else float("nan")

    summary = {
        "experiment": "LXXX matched-recall and cost-aware baseline comparison",
        "generated_at": now_cst(),
        "claim_boundary": "Matched-recall false-admission accounting and utility-cost comparison; not human semantic truth or deployment superiority.",
        "random_seed": RANDOM_SEED,
        "control_trials": CONTROL_TRIALS,
        "control_pairs_per_trial": CONTROL_PAIRS_PER_TRIAL,
        "headline": {
            "cvefixes_mddc_recall": float(policies[policies["dataset"].eq("CVEfixes") & policies["policy"].eq("mddc_strict_gate")].iloc[0]["true_recall"]),
            "cvefixes_false_rates": {
                "risk_score_tuned": get_false("CVEfixes", "risk_score_tuned"),
                "coverage_only_tuned": get_false("CVEfixes", "coverage_only_tuned"),
                "random_at_mddc_recall": get_false("CVEfixes", "random_at_mddc_recall"),
                "mddc_strict_gate": get_false("CVEfixes", "mddc_strict_gate"),
            },
            "bigvul_mddc_recall": float(policies[policies["dataset"].eq("BigVul") & policies["policy"].eq("mddc_strict_gate")].iloc[0]["true_recall"]),
            "bigvul_false_rates": {
                "risk_score_tuned": get_false("BigVul", "risk_score_tuned"),
                "coverage_only_tuned": get_false("BigVul", "coverage_only_tuned"),
                "random_at_mddc_recall": get_false("BigVul", "random_at_mddc_recall"),
                "mddc_strict_gate": get_false("BigVul", "mddc_strict_gate"),
            },
            "utility_mddc": utility[utility["policy"].eq("mddc_utility_gate")].iloc[0].to_dict(),
        },
        "outputs": {
            "dataset_policy_csv": str(OUT_DATASET_ROWS),
            "control_trials_csv": str(OUT_DATASET_CONTROLS),
            "control_aggregate_csv": str(OUT_DATASET_AGG),
            "utility_policy_csv": str(OUT_UTILITY),
            "summary_json": str(OUT_SUMMARY),
            "report_md": str(OUT_REPORT),
            "figure_pdf": str(OUT_FIG_PDF),
            "figure_png": str(OUT_FIG_PNG),
        },
    }
    OUT_SUMMARY.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    cve = summary["headline"]["cvefixes_false_rates"]
    big = summary["headline"]["bigvul_false_rates"]
    mddc_util = utility[utility["policy"].eq("mddc_utility_gate")].iloc[0]
    best_non_mddc = utility[~utility["policy"].eq("mddc_utility_gate")].sort_values(["false_admission", "admitted"]).iloc[0]
    lines = [
        "# Experiment LXXX Matched-Recall and Cost-Aware Baseline Comparison",
        "",
        f"Generated: {summary['generated_at']}",
        "",
        "## Purpose",
        "",
        "This experiment addresses the recall-confounding critique. It tunes score-only, coverage-only, and random baselines to the MDDC strict gate's true-pair recall, then compares same-category false admissions. It also reports a unit-review utility comparison in the XLVIII pool.",
        "",
        "## Headline",
        "",
        f"- CVEfixes matched recall: `{summary['headline']['cvefixes_mddc_recall']:.3f}`.",
        f"- CVEfixes same-category false rates at matched recall: risk-score `{cve['risk_score_tuned']:.3f}`, coverage-only `{cve['coverage_only_tuned']:.3f}`, random `{cve['random_at_mddc_recall']:.3f}`, MDDC strict `{cve['mddc_strict_gate']:.3f}`.",
        f"- BigVul matched recall: `{summary['headline']['bigvul_mddc_recall']:.3f}`.",
        f"- BigVul same-category false rates at matched recall: risk-score `{big['risk_score_tuned']:.3f}`, coverage-only `{big['coverage_only_tuned']:.3f}`, random `{big['random_at_mddc_recall']:.3f}`, MDDC strict `{big['mddc_strict_gate']:.3f}`.",
        f"- Utility pool MDDC: `{int(mddc_util['true_positive'])}` true positives, `{int(mddc_util['false_admission'])}` false admissions, review load per TP `{mddc_util['review_load_per_true_positive']:.3f}`.",
        f"- Best non-MDDC utility baseline by false admissions: `{best_non_mddc['policy']}` with `{int(best_non_mddc['true_positive'])}` true positives and `{int(best_non_mddc['false_admission'])}` false admissions.",
        "",
        "## Boundary",
        "",
        "This is a fairness and cost-accounting check. The target labels remain benchmark-reference or utility-proxy labels. The experiment does not establish human semantic correctness or deployment-rate superiority.",
        "",
        "## Outputs",
        "",
        f"- Dataset policy table: `{OUT_DATASET_ROWS}`",
        f"- Control trials: `{OUT_DATASET_CONTROLS}`",
        f"- Control aggregate: `{OUT_DATASET_AGG}`",
        f"- Utility table: `{OUT_UTILITY}`",
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
