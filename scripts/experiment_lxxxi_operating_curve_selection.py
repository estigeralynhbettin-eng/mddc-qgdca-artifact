#!/usr/bin/env python3
"""Experiment LXXXI: operating-curve and debt-adjusted selection.

This experiment addresses the LXXX boundary: a tuned coverage-only baseline can
beat the fixed MDDC strict gate at a single matched-recall point. The intended
method claim is therefore not that one fixed gate is always best, but that
QG-DCA reports and selects operating points under validation-debt costs.

The experiment builds full recall / false-admission / precision / utility
curves for CVEfixes and BigVul using public/frozen data only.
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
RAW_CVEFIXES = ROOT / "empirical_validation" / "data" / "raw" / "cvefixes"
RAW_BIGVUL = ROOT / "empirical_validation" / "data" / "raw" / "bigvul" / "all_c_cpp_release2.0.csv"

OUT_CURVES = RESULTS / "experiment_lxxxi_operating_curve_points_20260624.csv"
OUT_SELECTED = RESULTS / "experiment_lxxxi_operating_curve_selected_points_20260624.csv"
OUT_SUMMARY = RESULTS / "experiment_lxxxi_operating_curve_selection_summary_20260624.json"
OUT_REPORT = REPORTS / "experiment_lxxxi_operating_curve_selection_20260624.md"
OUT_FIG_PDF = FIGURES / "fig_experiment_lxxxi_operating_curve_selection.pdf"
OUT_FIG_PNG = FIGURES / "fig_experiment_lxxxi_operating_curve_selection.png"

RANDOM_SEED = 20260624
NEGATIVE_PAIRS = 8000
FALSE_COST = 3.0
MISS_COST = 0.25
REVIEW_COST = 0.05
FALSE_CONSTRAINT = 0.15


def now_cst() -> str:
    return datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S +08:00")


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
    return len(ref.get("ref_tokens", set()) & cand.get("candidate_tokens", set())) / max(1, len(ref.get("ref_tokens", set())))


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


def sample_same_category_pairs(refs: list[dict[str, Any]], cands: list[dict[str, Any]], seed_offset: int) -> pd.DataFrame:
    rng = random.Random(RANDOM_SEED + seed_offset)
    by_category: dict[str, list[int]] = {}
    for idx, ref in enumerate(refs):
        by_category.setdefault(str(ref["ref_category"]), []).append(idx)
    usable = [idx for idx, ref in enumerate(refs) if ref["ref_category"] != "other" and len(by_category[str(ref["ref_category"])]) > 1]
    rows: list[dict[str, Any]] = []
    for pair_idx in range(NEGATIVE_PAIRS):
        ref_idx = rng.choice(usable)
        pool = by_category[str(refs[ref_idx]["ref_category"])]
        cand_idx = rng.choice(pool)
        while cand_idx == ref_idx:
            cand_idx = rng.choice(pool)
        ref = refs[ref_idx]
        cand = cands[cand_idx]
        cov = coverage(ref, cand)
        category = bool(cand.get("structural")) and ref["ref_category"] != "other" and ref["ref_category"] in cand.get("candidate_categories", set())
        rows.append(
            {
                "pair_idx": pair_idx,
                "risk_score": ref.get("risk_score", float("nan")),
                "coverage": cov,
                "category_match": category,
                "category_coverage_score": cov if category else float("-inf"),
            }
        )
    return pd.DataFrame(rows)


def threshold_grid(series: pd.Series, max_points: int = 120) -> list[float]:
    finite = sorted({float(x) for x in series.dropna().tolist() if not math.isinf(float(x))}, reverse=True)
    if not finite:
        return []
    if len(finite) <= max_points:
        return finite
    step = max(1, len(finite) // max_points)
    grid = finite[::step]
    if finite[-1] not in grid:
        grid.append(finite[-1])
    return grid


def policy_curves(dataset: str, positives: pd.DataFrame, negatives: pd.DataFrame) -> pd.DataFrame:
    policy_defs = [
        ("risk_score", "Risk score", "risk_score"),
        ("coverage_only", "Coverage only", "coverage"),
        ("category_plus_coverage", "Category+coverage", "category_coverage_score"),
    ]
    n_pos = len(positives)
    n_neg = len(negatives)
    rows: list[dict[str, Any]] = []
    for policy, label, score_col in policy_defs:
        pos_scores = pd.to_numeric(positives[score_col], errors="coerce")
        neg_scores = pd.to_numeric(negatives[score_col], errors="coerce")
        for threshold in threshold_grid(pd.concat([pos_scores, neg_scores], ignore_index=True)):
            tp = int((pos_scores >= threshold).sum())
            fp = int((neg_scores >= threshold).sum())
            fn = n_pos - tp
            admitted = tp + fp
            recall = tp / n_pos if n_pos else 0.0
            false_rate = fp / n_neg if n_neg else 0.0
            precision = tp / admitted if admitted else 1.0
            review_rate = admitted / (n_pos + n_neg)
            # The utility is normalized per true-pair opportunity. False capital
            # is weighted more heavily than missed admission because it can
            # pollute H_q(t), while abstention/miss leaves the item unadmitted.
            utility = recall - FALSE_COST * false_rate - MISS_COST * (1.0 - recall) - REVIEW_COST * review_rate
            rows.append(
                {
                    "dataset": dataset,
                    "policy": policy,
                    "policy_label": label,
                    "threshold": threshold,
                    "true_positive": tp,
                    "false_admission": fp,
                    "false_negative": fn,
                    "admitted": admitted,
                    "n_true": n_pos,
                    "n_negative": n_neg,
                    "recall": recall,
                    "false_admission_rate": false_rate,
                    "precision": precision,
                    "review_rate": review_rate,
                    "validation_debt_cost": FALSE_COST * false_rate + MISS_COST * (1.0 - recall) + REVIEW_COST * review_rate,
                    "debt_adjusted_utility": utility,
                    "meets_false_constraint": false_rate <= FALSE_CONSTRAINT,
                }
            )
    return pd.DataFrame(rows)


def positives_from_rows(rows_df: pd.DataFrame) -> pd.DataFrame:
    out = pd.DataFrame()
    out["risk_score"] = pd.to_numeric(rows_df["risk_score"], errors="coerce")
    out["coverage"] = pd.to_numeric(rows_df["token_coverage"], errors="coerce")
    out["category_match"] = rows_df["category_gate"].astype(bool)
    out["category_coverage_score"] = out["coverage"].where(out["category_match"], float("-inf"))
    return out


def select_points(curves: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for dataset, group in curves.groupby("dataset"):
        best_overall = group.sort_values(["debt_adjusted_utility", "recall", "precision"], ascending=[False, False, False]).iloc[0]
        constrained = group[group["meets_false_constraint"]]
        best_constrained = constrained.sort_values(["debt_adjusted_utility", "recall", "precision"], ascending=[False, False, False]).iloc[0]
        category_group = group[group["policy"].eq("category_plus_coverage")].copy()
        category_group["distance_to_fixed_strict"] = category_group["threshold"].sub(0.10).abs()
        fixed_row = category_group.sort_values(["distance_to_fixed_strict", "threshold"], ascending=[True, False]).iloc[0]
        for label, row in [("qgdca_best_overall", best_overall), ("qgdca_best_under_false_constraint", best_constrained), ("fixed_strict_0_10", fixed_row)]:
            item = row.to_dict()
            item["selection"] = label
            rows.append(item)
    return pd.DataFrame(rows)


def make_figure(curves: pd.DataFrame, selected: pd.DataFrame) -> None:
    FIGURES.mkdir(parents=True, exist_ok=True)
    colors = {"risk_score": "#a5a5a5", "coverage_only": "#70ad47", "category_plus_coverage": "#2f5597"}
    fig, axes = plt.subplots(2, 2, figsize=(10.4, 7.0), sharex="col")
    for col, dataset in enumerate(["CVEfixes", "BigVul"]):
        sub = curves[curves["dataset"].eq(dataset)]
        for policy, group in sub.groupby("policy"):
            group = group.sort_values("recall")
            axes[0, col].plot(group["recall"], group["false_admission_rate"], label=policy, color=colors[policy], linewidth=1.8)
            axes[1, col].plot(group["recall"], group["debt_adjusted_utility"], label=policy, color=colors[policy], linewidth=1.8)
        for _, row in selected[selected["dataset"].eq(dataset)].iterrows():
            marker = "o" if row["selection"] == "qgdca_best_under_false_constraint" else "x"
            axes[0, col].scatter(row["recall"], row["false_admission_rate"], color="black", marker=marker, s=30, zorder=5)
            axes[1, col].scatter(row["recall"], row["debt_adjusted_utility"], color="black", marker=marker, s=30, zorder=5)
        axes[0, col].axhline(FALSE_CONSTRAINT, color="#c00000", linestyle="--", linewidth=1.0)
        axes[0, col].set_title(f"{dataset}: false admission curve")
        axes[1, col].set_title(f"{dataset}: debt-adjusted utility")
        axes[1, col].set_xlabel("Recall")
        axes[0, col].set_ylim(0, 1.02)
        axes[0, col].set_ylabel("False-admission rate")
        axes[1, col].set_ylabel("Utility")
        axes[0, col].grid(alpha=0.2)
        axes[1, col].grid(alpha=0.2)
    handles, labels = axes[0, 0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", ncol=3, frameon=False)
    fig.tight_layout(rect=[0, 0, 1, 0.94])
    fig.savefig(OUT_FIG_PDF)
    fig.savefig(OUT_FIG_PNG, dpi=220)
    plt.close(fig)


def main() -> int:
    RESULTS.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    FIGURES.mkdir(parents=True, exist_ok=True)

    curve_frames = []
    for seed_offset, loader in enumerate([load_cvefixes, load_bigvul]):
        dataset, refs, cands, rows_df = loader()
        positives = positives_from_rows(rows_df)
        negatives = sample_same_category_pairs(refs, cands, 1000 * seed_offset)
        curve_frames.append(policy_curves(dataset, positives, negatives))
    curves = pd.concat(curve_frames, ignore_index=True)
    selected = select_points(curves)
    curves.to_csv(OUT_CURVES, index=False)
    selected.to_csv(OUT_SELECTED, index=False)
    make_figure(curves, selected)

    summary = {
        "experiment": "LXXXI operating-curve and debt-adjusted selection",
        "generated_at": now_cst(),
        "claim_boundary": "Operating-point selection under proxy labels; not human semantic truth or deployment superiority.",
        "random_seed": RANDOM_SEED,
        "negative_pairs_per_dataset": NEGATIVE_PAIRS,
        "cost_model": {
            "false_admission_cost": FALSE_COST,
            "miss_cost": MISS_COST,
            "review_cost": REVIEW_COST,
            "false_constraint": FALSE_CONSTRAINT,
            "utility": "recall - false_cost*false_rate - miss_cost*(1-recall) - review_cost*review_rate",
        },
        "selected_points": selected.to_dict(orient="records"),
        "outputs": {
            "curves_csv": str(OUT_CURVES),
            "selected_csv": str(OUT_SELECTED),
            "summary_json": str(OUT_SUMMARY),
            "report_md": str(OUT_REPORT),
            "figure_pdf": str(OUT_FIG_PDF),
            "figure_png": str(OUT_FIG_PNG),
        },
    }
    OUT_SUMMARY.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    lines = [
        "# Experiment LXXXI Operating-Curve and Debt-Adjusted Selection",
        "",
        f"Generated: {summary['generated_at']}",
        "",
        "## Purpose",
        "",
        "LXXX showed that a fixed strict gate is not Pareto-optimal at one matched-recall point. LXXXI therefore evaluates complete operating curves and treats QG-DCA as an accounting protocol that selects and audits an operating point under validation-debt costs.",
        "",
        "## Cost Model",
        "",
        f"- False-admission cost: `{FALSE_COST}`",
        f"- Missed-admission cost: `{MISS_COST}`",
        f"- Review-load cost: `{REVIEW_COST}`",
        f"- False-admission constraint: `{FALSE_CONSTRAINT}`",
        "",
        "## Selected Operating Points",
        "",
        "| Dataset | Selection | Policy | Threshold | Recall | False rate | Precision | Utility |",
        "|---|---|---|---:|---:|---:|---:|---:|",
    ]
    for _, row in selected.iterrows():
        lines.append(
            f"| {row['dataset']} | {row['selection']} | {row['policy']} | {row['threshold']:.4f} | {row['recall']:.3f} | {row['false_admission_rate']:.3f} | {row['precision']:.3f} | {row['debt_adjusted_utility']:.3f} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "The result resolves the coverage-only boundary by changing the claim: QG-DCA is not a fixed strict gate. It is the protocol that exposes the curve, records the debt model, and selects an operating point. If a simpler coverage-only point dominates under the declared cost model, QG-DCA should select or report that point instead of defending the fixed strict gate.",
            "",
            "## Boundary",
            "",
            "The labels remain benchmark-reference and proxy labels. This experiment improves operating-point validity but does not provide human semantic truth or deployment-rate evidence.",
            "",
            "## Outputs",
            "",
            f"- Curve points: `{OUT_CURVES}`",
            f"- Selected points: `{OUT_SELECTED}`",
            f"- Summary: `{OUT_SUMMARY}`",
            f"- Figure PDF: `{OUT_FIG_PDF}`",
            "",
            "Document generated: " + now_cst(),
        ]
    )
    OUT_REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"summary": str(OUT_SUMMARY), "report": str(OUT_REPORT), "selected": selected.to_dict(orient="records")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

