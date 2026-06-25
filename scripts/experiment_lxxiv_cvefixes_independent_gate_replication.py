#!/usr/bin/env python3
"""Experiment LXXIV: independent CVEfixes gate replication.

This experiment addresses a reviewer concern that the ASR rule-capital gate may
be too tied to ASRDataset. It applies an analogous qualification-gate pattern to
CVEfixes vulnerability-fixing commits, a separate public dataset.

Boundary: CVEfixes does not contain ASR rule XML, so this is a patch-metadata and
patch-context benchmark-agreement replication, not a rule-semantic correctness
claim and not deployment evidence.
"""

from __future__ import annotations

import os

import json
import math
import random
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


ROOT = Path(os.environ.get("MDDC_ROOT", "/root/mddc"))
RAW = ROOT / "empirical_validation" / "data" / "raw" / "cvefixes"
RESULTS = ROOT / "empirical_validation" / "results"
REPORTS = ROOT / "review_rounds"
FIGURES = ROOT / "empirical_validation" / "figures"

OUT_ROWS = RESULTS / "experiment_lxxiv_cvefixes_independent_gate_rows_20260624.csv"
OUT_CONTROLS = RESULTS / "experiment_lxxiv_cvefixes_independent_gate_controls_20260624.csv"
OUT_SUMMARY = RESULTS / "experiment_lxxiv_cvefixes_independent_gate_summary_20260624.json"
OUT_REPORT = REPORTS / "experiment_lxxiv_cvefixes_independent_gate_replication_20260624.md"
OUT_FIG_PDF = FIGURES / "fig_experiment_lxxiv_cvefixes_independent_gate_replication.pdf"
OUT_FIG_PNG = FIGURES / "fig_experiment_lxxiv_cvefixes_independent_gate_replication.png"

RANDOM_SEED = 20260624
TOKEN_COVERAGE_THRESHOLD = 0.10
CONTROL_TRIALS = 200
CONTROL_PAIRS_PER_TRIAL = 1500
TEXT_LIMIT = 6000


CATEGORY_DEFS: dict[str, dict[str, Any]] = {
    "path_traversal": {
        "cwes": {"CWE-22", "CWE-23", "CWE-36", "CWE-73"},
        "terms": ["path", "directory", "traversal", "file", "canonical", "normalize", "filename"],
    },
    "xss": {
        "cwes": {"CWE-79", "CWE-80", "CWE-116"},
        "terms": ["xss", "script", "html", "escape", "sanitize", "encode", "cross", "site"],
    },
    "sql_injection": {
        "cwes": {"CWE-89", "CWE-564"},
        "terms": ["sql", "query", "injection", "prepared", "statement", "parameterized"],
    },
    "command_injection": {
        "cwes": {"CWE-78", "CWE-77", "CWE-74", "CWE-94"},
        "terms": ["command", "shell", "exec", "injection", "eval", "template"],
    },
    "xxe": {
        "cwes": {"CWE-611", "CWE-827"},
        "terms": ["xml", "xxe", "entity", "doctype", "external"],
    },
    "deserialization": {
        "cwes": {"CWE-502"},
        "terms": ["deserialize", "deserialization", "serialization", "pickle", "objectinputstream"],
    },
    "auth_access": {
        "cwes": {"CWE-200", "CWE-269", "CWE-287", "CWE-285", "CWE-862", "CWE-863", "CWE-284", "CWE-352"},
        "terms": ["auth", "permission", "access", "privilege", "csrf", "token", "role", "credential", "password", "session"],
    },
    "resource_dos": {
        "cwes": {"CWE-400", "CWE-835", "CWE-770", "CWE-789", "CWE-674"},
        "terms": ["dos", "denial", "resource", "loop", "timeout", "limit", "memory", "exhaustion", "size"],
    },
    "crypto_secret": {
        "cwes": {"CWE-327", "CWE-326", "CWE-319", "CWE-798", "CWE-295"},
        "terms": ["crypto", "encrypt", "tls", "ssl", "secret", "certificate", "signature", "key", "password"],
    },
    "memory_safety": {
        "cwes": {"CWE-119", "CWE-120", "CWE-125", "CWE-787", "CWE-416", "CWE-476", "CWE-190", "CWE-193"},
        "terms": ["buffer", "overflow", "bounds", "null", "pointer", "memory", "integer", "free", "length"],
    },
    "ssrf_redirect": {
        "cwes": {"CWE-918", "CWE-601"},
        "terms": ["ssrf", "redirect", "url", "host", "request", "http", "uri"],
    },
}


STOPWORDS = {
    "the",
    "and",
    "for",
    "with",
    "that",
    "this",
    "from",
    "are",
    "was",
    "were",
    "has",
    "have",
    "had",
    "not",
    "but",
    "can",
    "may",
    "before",
    "after",
    "fixed",
    "fix",
    "issue",
    "affects",
    "users",
    "recommended",
    "product",
    "vulnerability",
    "vulnerable",
    "security",
    "commit",
    "diff",
    "code",
    "file",
}


def now_cst() -> str:
    return datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S +08:00")


def clean(value: Any, limit: int = TEXT_LIMIT) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and math.isnan(value):
        return ""
    return str(value).lower()[:limit]


def tokens(text: str) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-z][a-z0-9_]{2,}", text.lower())
        if token not in STOPWORDS and not token.startswith("cwe")
    }


def cwe_list(value: Any) -> list[str]:
    text = clean(value, 500)
    return re.findall(r"CWE-\d+", text.upper())


def infer_reference_category(cwe_id: Any, cwe_name: Any, cwe_description: Any, cve_description: Any) -> str:
    cwes = set(cwe_list(cwe_id))
    text = " ".join([clean(cwe_name, 1500), clean(cwe_description, 1500), clean(cve_description, 1500)])
    for category, spec in CATEGORY_DEFS.items():
        if cwes & set(spec["cwes"]):
            return category
    for category, spec in CATEGORY_DEFS.items():
        if any(term in text for term in spec["terms"]):
            return category
    return "other"


def infer_candidate_categories(text: str) -> set[str]:
    return {
        category
        for category, spec in CATEGORY_DEFS.items()
        if any(term in text for term in spec["terms"])
    }


def wilson(k: int, n: int, z: float = 1.959963984540054) -> list[float]:
    if n <= 0:
        return [float("nan"), float("nan")]
    phat = k / n
    denom = 1 + z * z / n
    centre = phat + z * z / (2 * n)
    margin = z * math.sqrt((phat * (1 - phat) + z * z / (4 * n)) / n)
    return [(centre - margin) / denom, (centre + margin) / denom]


def load_cvefixes() -> pd.DataFrame:
    columns = [
        "cve_id",
        "hash",
        "repo_url",
        "cve_description",
        "cwe_id",
        "cwe_name",
        "cwe_description",
        "commit_message",
        "diff_with_context",
        "security_keywords",
        "language",
        "file_paths",
    ]
    frames = [pd.read_parquet(path, columns=columns) for path in sorted(RAW.glob("*.parquet"))]
    df = pd.concat(frames, ignore_index=True)
    df = df.drop_duplicates(subset=["cve_id", "hash"]).reset_index(drop=True)
    return df


def prepare_records(df: pd.DataFrame) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    refs: list[dict[str, Any]] = []
    cands: list[dict[str, Any]] = []
    row_records: list[dict[str, Any]] = []
    for idx, row in enumerate(df.itertuples(index=False)):
        reference_text = " ".join(
            [
                clean(row.cve_description, 2500),
                clean(row.cwe_name, 1200),
                clean(row.cwe_description, 1200),
            ]
        )
        candidate_text = " ".join(
            [
                clean(row.commit_message, 1200),
                clean(row.diff_with_context, 5000),
                clean(row.security_keywords, 1200),
            ]
        )
        ref_category = infer_reference_category(row.cwe_id, row.cwe_name, row.cwe_description, row.cve_description)
        cand_categories = infer_candidate_categories(candidate_text)
        ref_tokens = tokens(reference_text)
        cand_tokens = tokens(candidate_text)
        structural = bool(
            clean(row.cve_id, 100)
            and cwe_list(row.cwe_id)
            and clean(row.commit_message, 200)
            and clean(row.diff_with_context, 200)
            and clean(row.repo_url, 300)
            and clean(row.hash, 100)
        )
        category_gate = structural and ref_category != "other" and ref_category in cand_categories
        token_coverage = len(ref_tokens & cand_tokens) / max(1, len(ref_tokens))
        strict_gate = category_gate and token_coverage >= TOKEN_COVERAGE_THRESHOLD
        refs.append(
            {
                "idx": idx,
                "ref_category": ref_category,
                "ref_tokens": ref_tokens,
                "cwe_id": clean(row.cwe_id, 200),
            }
        )
        cands.append(
            {
                "idx": idx,
                "structural": structural,
                "candidate_categories": cand_categories,
                "candidate_tokens": cand_tokens,
            }
        )
        row_records.append(
            {
                "idx": idx,
                "cve_id": row.cve_id,
                "hash": row.hash,
                "repo_url": row.repo_url,
                "language": row.language,
                "cwe_id": row.cwe_id,
                "ref_category": ref_category,
                "candidate_categories": ";".join(sorted(cand_categories)),
                "token_coverage": token_coverage,
                "structural_only_gate": structural,
                "category_gate": category_gate,
                "strict_mddc_gate": strict_gate,
            }
        )
    return refs, cands, row_records


def score_pair(ref: dict[str, Any], cand: dict[str, Any]) -> dict[str, bool]:
    structural = bool(cand["structural"])
    category = structural and ref["ref_category"] != "other" and ref["ref_category"] in cand["candidate_categories"]
    token_coverage = len(ref["ref_tokens"] & cand["candidate_tokens"]) / max(1, len(ref["ref_tokens"]))
    strict = category and token_coverage >= TOKEN_COVERAGE_THRESHOLD
    return {
        "structural_only": structural,
        "category_gate": category,
        "strict_mddc_gate": strict,
    }


def control_trials(refs: list[dict[str, Any]], cands: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rng = random.Random(RANDOM_SEED)
    by_category: dict[str, list[int]] = defaultdict(list)
    non_other = [idx for idx, ref in enumerate(refs) if ref["ref_category"] != "other"]
    for idx, ref in enumerate(refs):
        by_category[ref["ref_category"]].append(idx)
    category_keys = [cat for cat in by_category if cat != "other"]
    cross_category_choices = {
        cat: [other_cat for other_cat in category_keys if other_cat != cat] for cat in category_keys
    }

    rows: list[dict[str, Any]] = []
    modes = ["any_deranged", "cross_category", "same_category_different_cve"]
    for trial in range(CONTROL_TRIALS):
        sampled_refs = rng.sample(non_other, min(CONTROL_PAIRS_PER_TRIAL, len(non_other)))
        for mode in modes:
            counts = Counter()
            usable = 0
            for ref_idx in sampled_refs:
                ref = refs[ref_idx]
                if mode == "same_category_different_cve":
                    pool = by_category[ref["ref_category"]]
                    if len(pool) <= 1:
                        continue
                    cand_idx = rng.choice(pool)
                    while cand_idx == ref_idx:
                        cand_idx = rng.choice(pool)
                elif mode == "cross_category":
                    category_pool = cross_category_choices.get(ref["ref_category"], [])
                    if not category_pool:
                        continue
                    cand_idx = rng.choice(by_category[rng.choice(category_pool)])
                else:
                    cand_idx = rng.randrange(len(refs))
                    while cand_idx == ref_idx:
                        cand_idx = rng.randrange(len(refs))
                usable += 1
                pair = score_pair(ref, cands[cand_idx])
                counts.update({k: int(v) for k, v in pair.items()})
            rows.append(
                {
                    "mode": mode,
                    "trial": trial,
                    "n_pairs": usable,
                    "structural_only_admitted": counts["structural_only"],
                    "category_gate_admitted": counts["category_gate"],
                    "strict_mddc_gate_admitted": counts["strict_mddc_gate"],
                }
            )
    return rows


def summarize_gate(name: str, k: int, n: int) -> dict[str, Any]:
    lo, hi = wilson(k, n)
    return {"gate": name, "admitted": k, "n": n, "rate": k / n if n else 0.0, "wilson95": [lo, hi]}


def make_figure(summary: dict[str, Any], control_df: pd.DataFrame) -> None:
    FIGURES.mkdir(parents=True, exist_ok=True)
    true_rows = summary["true_pair_rates"]
    labels = ["Structural", "Category", "Strict"]
    rates = [
        true_rows["structural_only"]["rate"],
        true_rows["category_gate"]["rate"],
        true_rows["strict_mddc_gate"]["rate"],
    ]
    same = control_df[control_df["mode"] == "same_category_different_cve"]
    control_rates = [
        same["structural_only_admitted"].mean() / same["n_pairs"].mean(),
        same["category_gate_admitted"].mean() / same["n_pairs"].mean(),
        same["strict_mddc_gate_admitted"].mean() / same["n_pairs"].mean(),
    ]
    fig, axes = plt.subplots(1, 2, figsize=(8.2, 3.0))
    x = np.arange(3)
    axes[0].bar(x, rates, color=["#a5a5a5", "#70ad47", "#2f5597"])
    axes[0].set_xticks(x, labels, rotation=20, ha="right")
    axes[0].set_ylim(0, 1)
    axes[0].set_ylabel("True-pair admission rate")
    axes[0].set_title("CVEfixes true pairs")
    width = 0.35
    axes[1].bar(x - width / 2, rates, width=width, label="true pairs", color="#2f5597")
    axes[1].bar(x + width / 2, control_rates, width=width, label="same-category controls", color="#c00000")
    axes[1].set_xticks(x, labels, rotation=20, ha="right")
    axes[1].set_ylim(0, 1)
    axes[1].set_ylabel("Admission rate")
    axes[1].set_title("Baseline vs strict gate")
    axes[1].legend(frameon=False, fontsize=8)
    fig.tight_layout()
    fig.savefig(OUT_FIG_PDF)
    fig.savefig(OUT_FIG_PNG, dpi=220)
    plt.close(fig)


def write_report(summary: dict[str, Any]) -> None:
    strict = summary["true_pair_rates"]["strict_mddc_gate"]
    structural = summary["true_pair_rates"]["structural_only"]
    same = summary["control_summary"]["same_category_different_cve"]
    lines = [
        "# Experiment LXXIV: CVEfixes Independent Gate Replication",
        "",
        f"Generated: {summary['generated_at']}",
        "",
        "## Purpose",
        "",
        "This experiment applies the MDDC qualification-gate pattern to CVEfixes, a second public dataset independent of ASRDataset. CVEfixes has CVE/CWE descriptions, commits, and patch diffs, but not ASR rule XML. The result is therefore patch-context benchmark agreement, not rule-semantic correctness.",
        "",
        "## Main Result",
        "",
        f"- Evaluated CVEfixes true pairs: `{summary['n_true_pairs']}`.",
        f"- Structural-only baseline admits `{structural['admitted']}/{structural['n']}` = `{structural['rate']:.3f}` true pairs.",
        f"- Strict MDDC gate admits `{strict['admitted']}/{strict['n']}` = `{strict['rate']:.3f}`, Wilson 95% CI `[{strict['wilson95'][0]:.3f}, {strict['wilson95'][1]:.3f}]`.",
        f"- On same-category different-CVE controls, structural-only admits `{same['structural_only_mean_rate']:.3f}` while strict MDDC admits `{same['strict_mddc_gate_mean_rate']:.3f}`.",
        f"- False-admission reduction versus structural-only baseline on same-category controls: `{same['strict_false_admission_reduction_vs_structural_pct']:.1f}%`.",
        "",
        "## Control Summary",
        "",
        "| Control | Structural mean rate | Category mean rate | Strict mean rate | Strict max admits |",
        "|---|---:|---:|---:|---:|",
    ]
    for mode, row in summary["control_summary"].items():
        lines.append(
            f"| {mode} | {row['structural_only_mean_rate']:.3f} | {row['category_gate_mean_rate']:.3f} | {row['strict_mddc_gate_mean_rate']:.3f} | {row['strict_mddc_gate_max_admitted']} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "The independent CVEfixes replication supports the gate-accounting claim against a simpler baseline: structural presence alone admits nearly every deranged control, while the strict gate substantially reduces false admissions. This does not prove deployment success. It shows that the MDDC admission idea is not limited to ASRDataset XML.",
            "",
            "## Boundary",
            "",
            "The strict CVEfixes gate is a benchmark-agreement gate over public CVE/CWE and patch-context fields. It should not be described as a human semantic label or as executable security validation.",
            "",
            "## Artifacts",
            "",
            f"- Rows: `{OUT_ROWS}`",
            f"- Controls: `{OUT_CONTROLS}`",
            f"- Summary: `{OUT_SUMMARY}`",
            f"- Figure: `{OUT_FIG_PDF}`",
            "",
            f"Document generated: {summary['generated_at']}",
        ]
    )
    OUT_REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    RESULTS.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    df = load_cvefixes()
    refs, cands, row_records = prepare_records(df)
    rows_df = pd.DataFrame(row_records)
    rows_df.to_csv(OUT_ROWS, index=False)
    control_rows = control_trials(refs, cands)
    control_df = pd.DataFrame(control_rows)
    control_df.to_csv(OUT_CONTROLS, index=False)
    n = len(rows_df)
    true_pair_rates = {
        "structural_only": summarize_gate("structural_only", int(rows_df["structural_only_gate"].sum()), n),
        "category_gate": summarize_gate("category_gate", int(rows_df["category_gate"].sum()), n),
        "strict_mddc_gate": summarize_gate("strict_mddc_gate", int(rows_df["strict_mddc_gate"].sum()), n),
    }
    control_summary: dict[str, Any] = {}
    for mode, g in control_df.groupby("mode", sort=True):
        n_pairs_mean = float(g["n_pairs"].mean())
        struct_rate = float(g["structural_only_admitted"].mean() / n_pairs_mean)
        category_rate = float(g["category_gate_admitted"].mean() / n_pairs_mean)
        strict_rate = float(g["strict_mddc_gate_admitted"].mean() / n_pairs_mean)
        control_summary[mode] = {
            "trials": int(len(g)),
            "n_pairs_mean": n_pairs_mean,
            "structural_only_mean_rate": struct_rate,
            "category_gate_mean_rate": category_rate,
            "strict_mddc_gate_mean_rate": strict_rate,
            "structural_only_max_admitted": int(g["structural_only_admitted"].max()),
            "category_gate_max_admitted": int(g["category_gate_admitted"].max()),
            "strict_mddc_gate_max_admitted": int(g["strict_mddc_gate_admitted"].max()),
            "strict_false_admission_reduction_vs_structural_pct": float(100 * (1 - strict_rate / max(struct_rate, 1e-12))),
        }
    by_category = (
        rows_df.groupby("ref_category")
        .agg(n=("cve_id", "size"), strict_admitted=("strict_mddc_gate", "sum"), category_admitted=("category_gate", "sum"))
        .reset_index()
    )
    by_category["strict_rate"] = by_category["strict_admitted"] / by_category["n"]
    summary = {
        "experiment": "LXXIV CVEfixes independent gate replication",
        "generated_at": now_cst(),
        "random_seed": RANDOM_SEED,
        "input": [str(path) for path in sorted(RAW.glob("*.parquet"))],
        "n_true_pairs": n,
        "token_coverage_threshold": TOKEN_COVERAGE_THRESHOLD,
        "control_trials": CONTROL_TRIALS,
        "control_pairs_per_trial": CONTROL_PAIRS_PER_TRIAL,
        "true_pair_rates": true_pair_rates,
        "control_summary": control_summary,
        "by_reference_category": by_category.to_dict(orient="records"),
        "claim_boundary": "Independent CVEfixes patch-context benchmark-agreement replication; not ASR rule semantic correctness, human labels, or deployment evidence.",
        "paper_consequence": "Use as an independent replication showing the strict admission pattern reduces false admissions versus structural-only baseline on a non-ASR public dataset.",
    }
    OUT_SUMMARY.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    make_figure(summary, control_df)
    write_report(summary)
    print(json.dumps({
        "n_true_pairs": n,
        "strict_rate": true_pair_rates["strict_mddc_gate"]["rate"],
        "same_category_strict_control_rate": control_summary["same_category_different_cve"]["strict_mddc_gate_mean_rate"],
        "same_category_false_admission_reduction_pct": control_summary["same_category_different_cve"]["strict_false_admission_reduction_vs_structural_pct"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

