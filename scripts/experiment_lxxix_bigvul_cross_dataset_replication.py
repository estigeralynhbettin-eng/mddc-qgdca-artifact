#!/usr/bin/env python3
"""Experiment LXXIX: BigVul cross-dataset gate-accounting replication.

This replicates the LXXIV CVEfixes-style qualification gate on BigVul. BigVul
does not contain ASR XML rules, so the experiment is a patch-context replication:
CVE/CWE metadata is the reference side; commit message and patch hunks are the
candidate side.
"""

from __future__ import annotations

import os

import ast
import json
import math
import random
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import pandas as pd


ROOT = Path(os.environ.get("MDDC_ROOT", "/root/mddc"))
RAW = ROOT / "empirical_validation" / "data" / "raw" / "bigvul" / "all_c_cpp_release2.0.csv"
META = ROOT / "empirical_validation" / "data" / "raw" / "bigvul" / "bigvul_download_metadata_20260624.json"
RESULTS = ROOT / "empirical_validation" / "results"
REPORTS = ROOT / "review_rounds"
FIGURES = ROOT / "empirical_validation" / "figures"
PREREG = ROOT / "empirical_validation" / "experiment_lxxix_bigvul_preregistration_20260624.md"

OUT_ROWS = RESULTS / "experiment_lxxix_bigvul_cross_dataset_rows_20260624.csv"
OUT_CONTROLS = RESULTS / "experiment_lxxix_bigvul_cross_dataset_controls_20260624.csv"
OUT_SUMMARY = RESULTS / "experiment_lxxix_bigvul_cross_dataset_summary_20260624.json"
OUT_REPORT = REPORTS / "experiment_lxxix_bigvul_cross_dataset_replication_20260624.md"
OUT_FIG_PDF = FIGURES / "fig_experiment_lxxix_bigvul_cross_dataset_replication.pdf"
OUT_FIG_PNG = FIGURES / "fig_experiment_lxxix_bigvul_cross_dataset_replication.png"

RANDOM_SEED = 20260624
CONTROL_TRIALS = 200
CONTROL_PAIRS_PER_TRIAL = 1500
TOKEN_COVERAGE_THRESHOLD = 0.10


CATEGORY_DEFS: dict[str, dict[str, Any]] = {
    "path_traversal": {"cwes": {"CWE-22", "CWE-23", "CWE-36", "CWE-73"}, "terms": ["path", "directory", "traversal", "canonical", "normalize", "filename"]},
    "xss": {"cwes": {"CWE-79", "CWE-80", "CWE-116"}, "terms": ["xss", "script", "html", "escape", "sanitize", "encode"]},
    "sql_injection": {"cwes": {"CWE-89", "CWE-564"}, "terms": ["sql", "query", "injection", "prepared", "statement"]},
    "command_injection": {"cwes": {"CWE-78", "CWE-77", "CWE-74", "CWE-94"}, "terms": ["command", "shell", "exec", "injection", "eval", "script"]},
    "xxe": {"cwes": {"CWE-611", "CWE-827"}, "terms": ["xml", "xxe", "entity", "doctype", "external"]},
    "deserialization": {"cwes": {"CWE-502"}, "terms": ["deserialize", "serialization", "pickle", "object"]},
    "auth_access": {"cwes": {"CWE-200", "CWE-269", "CWE-287", "CWE-285", "CWE-862", "CWE-863", "CWE-284", "CWE-352"}, "terms": ["auth", "permission", "access", "privilege", "csrf", "token", "role", "credential", "password", "session"]},
    "resource_dos": {"cwes": {"CWE-400", "CWE-835", "CWE-770", "CWE-789", "CWE-674"}, "terms": ["dos", "denial", "resource", "loop", "timeout", "limit", "memory", "exhaustion", "size"]},
    "crypto_secret": {"cwes": {"CWE-327", "CWE-326", "CWE-319", "CWE-798", "CWE-295"}, "terms": ["crypto", "encrypt", "tls", "ssl", "secret", "certificate", "signature", "key", "password"]},
    "memory_safety": {"cwes": {"CWE-119", "CWE-120", "CWE-125", "CWE-787", "CWE-416", "CWE-476", "CWE-190", "CWE-193", "CWE-189"}, "terms": ["buffer", "overflow", "bounds", "null", "pointer", "memory", "integer", "free", "length"]},
    "ssrf_redirect": {"cwes": {"CWE-918", "CWE-601"}, "terms": ["ssrf", "redirect", "url", "host", "request", "http", "uri"]},
}

STOPWORDS = {
    "the", "and", "for", "with", "that", "this", "from", "are", "was", "were",
    "has", "have", "not", "but", "can", "may", "before", "after", "fixed",
    "fix", "issue", "vulnerability", "vulnerable", "security", "commit",
    "code", "file", "files", "changed", "summary", "project",
}


def now_cst() -> str:
    return datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S +08:00")


def clean(value: Any, limit: int = 10000) -> str:
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
    return re.findall(r"CWE-\d+", str(value or "").upper())


def infer_reference_category(cwe_id: Any, classification: Any, summary: Any) -> str:
    cwes = set(cwe_list(cwe_id))
    text = " ".join([clean(classification, 2000), clean(summary, 3000)])
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


def extract_patch_text(files_changed: Any) -> str:
    text = str(files_changed or "")
    patches: list[str] = []
    try:
        parsed = ast.literal_eval(text)
        if isinstance(parsed, dict):
            parsed = [parsed]
        if isinstance(parsed, list):
            for item in parsed:
                if isinstance(item, dict):
                    patches.append(str(item.get("patch", "")))
                    patches.append(str(item.get("filename", "")))
    except (SyntaxError, ValueError):
        patches.append(text)
    return "\n".join(patches)


def wilson(k: int, n: int, z: float = 1.959963984540054) -> list[float]:
    if n <= 0:
        return [float("nan"), float("nan")]
    phat = k / n
    denom = 1 + z * z / n
    centre = phat + z * z / (2 * n)
    margin = z * math.sqrt((phat * (1 - phat) + z * z / (4 * n)) / n)
    return [(centre - margin) / denom, (centre + margin) / denom]


def prepare_records(df: pd.DataFrame) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    refs: list[dict[str, Any]] = []
    cands: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    for idx, row in df.reset_index(drop=True).iterrows():
        patch_text = extract_patch_text(row.get("files_changed", ""))
        reference_text = " ".join([clean(row.get("summary", ""), 3000), clean(row.get("vulnerability_classification", ""), 1000)])
        candidate_text = " ".join([clean(row.get("commit_message", ""), 1000), clean(patch_text, 7000)])
        ref_category = infer_reference_category(row.get("cwe_id"), row.get("vulnerability_classification"), row.get("summary"))
        cand_categories = infer_candidate_categories(candidate_text)
        ref_tokens = tokens(reference_text)
        cand_tokens = tokens(candidate_text)
        structural = bool(clean(row.get("cve_id"), 100) and clean(row.get("commit_id"), 100) and clean(patch_text, 200))
        category_gate = structural and ref_category != "other" and ref_category in cand_categories
        coverage = len(ref_tokens & cand_tokens) / max(1, len(ref_tokens))
        strict = category_gate and coverage >= TOKEN_COVERAGE_THRESHOLD
        refs.append({"idx": idx, "ref_category": ref_category, "ref_tokens": ref_tokens, "cve_id": row.get("cve_id", "")})
        cands.append({"idx": idx, "structural": structural, "candidate_categories": cand_categories, "candidate_tokens": cand_tokens})
        rows.append({
            "idx": idx,
            "cve_id": row.get("cve_id", ""),
            "cwe_id": row.get("cwe_id", ""),
            "project": row.get("project", ""),
            "lang": row.get("lang", ""),
            "score": row.get("score", ""),
            "ref_category": ref_category,
            "candidate_categories": ";".join(sorted(cand_categories)),
            "token_coverage": coverage,
            "structural_only_gate": structural,
            "category_gate": category_gate,
            "strict_mddc_gate": strict,
        })
    return refs, cands, rows


def score_pair(ref: dict[str, Any], cand: dict[str, Any]) -> dict[str, bool]:
    structural = bool(cand["structural"])
    category = structural and ref["ref_category"] != "other" and ref["ref_category"] in cand["candidate_categories"]
    coverage = len(ref["ref_tokens"] & cand["candidate_tokens"]) / max(1, len(ref["ref_tokens"]))
    strict = category and coverage >= TOKEN_COVERAGE_THRESHOLD
    return {"structural_only_gate": structural, "category_gate": category, "strict_mddc_gate": strict}


def control_trials(refs: list[dict[str, Any]], cands: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rng = random.Random(RANDOM_SEED)
    by_category: dict[str, list[int]] = defaultdict(list)
    non_other = [idx for idx, ref in enumerate(refs) if ref["ref_category"] != "other"]
    for idx, ref in enumerate(refs):
        by_category[ref["ref_category"]].append(idx)
    category_keys = [cat for cat in by_category if cat != "other"]
    rows: list[dict[str, Any]] = []
    for trial in range(CONTROL_TRIALS):
        sampled_refs = rng.sample(non_other, min(CONTROL_PAIRS_PER_TRIAL, len(non_other)))
        for mode in ["any_deranged", "cross_category", "same_category_different_cve"]:
            counts = {"structural_only_gate": 0, "category_gate": 0, "strict_mddc_gate": 0}
            usable = 0
            for ref_idx in sampled_refs:
                ref = refs[ref_idx]
                if mode == "same_category_different_cve":
                    pool = [idx for idx in by_category[ref["ref_category"]] if idx != ref_idx]
                elif mode == "cross_category":
                    other_cats = [cat for cat in category_keys if cat != ref["ref_category"]]
                    pool = by_category[rng.choice(other_cats)] if other_cats else []
                else:
                    pool = [idx for idx in range(len(refs)) if idx != ref_idx]
                if not pool:
                    continue
                cand_idx = rng.choice(pool)
                pair = score_pair(ref, cands[cand_idx])
                usable += 1
                for key, value in pair.items():
                    counts[key] += int(value)
            rows.append({
                "mode": mode,
                "trial": trial,
                "n_pairs": usable,
                "structural_only_admitted": counts["structural_only_gate"],
                "category_gate_admitted": counts["category_gate"],
                "strict_mddc_gate_admitted": counts["strict_mddc_gate"],
            })
    return rows


def summarize(rows_df: pd.DataFrame, controls_df: pd.DataFrame) -> dict[str, Any]:
    n = len(rows_df)
    true_rates = {}
    for name, col in {
        "structural_only": "structural_only_gate",
        "category_gate": "category_gate",
        "strict_mddc_gate": "strict_mddc_gate",
    }.items():
        k = int(rows_df[col].sum())
        true_rates[name] = {"admitted": k, "n": n, "rate": k / n, "wilson95": wilson(k, n)}
    control_summary = {}
    for mode, group in controls_df.groupby("mode"):
        control_summary[mode] = {"trials": int(len(group)), "n_pairs_mean": float(group["n_pairs"].mean())}
        for label, col in {
            "structural_only": "structural_only_admitted",
            "category_gate": "category_gate_admitted",
            "strict_mddc_gate": "strict_mddc_gate_admitted",
        }.items():
            rate = group[col] / group["n_pairs"]
            control_summary[mode][label + "_mean_rate"] = float(rate.mean())
            control_summary[mode][label + "_max_rate"] = float(rate.max())
        base = control_summary[mode]["structural_only_mean_rate"]
        strict = control_summary[mode]["strict_mddc_gate_mean_rate"]
        control_summary[mode]["strict_false_admission_reduction_vs_structural_pct"] = 100 * (base - strict) / base if base else float("nan")
    return {
        "experiment": "LXXIX BigVul cross-dataset gate-accounting replication",
        "generated_at": now_cst(),
        "preregistration": str(PREREG),
        "input": str(RAW),
        "metadata": str(META),
        "random_seed": RANDOM_SEED,
        "token_coverage_threshold": TOKEN_COVERAGE_THRESHOLD,
        "control_trials": CONTROL_TRIALS,
        "control_pairs_per_trial": CONTROL_PAIRS_PER_TRIAL,
        "n_true_pairs": n,
        "true_pair_rates": true_rates,
        "control_summary": control_summary,
        "success_condition": {
            "same_category_reduction_ge_60pct": control_summary.get("same_category_different_cve", {}).get("strict_false_admission_reduction_vs_structural_pct", 0) >= 60,
            "strict_true_wilson_lower_ge_0_45": true_rates["strict_mddc_gate"]["wilson95"][0] >= 0.45,
        },
        "claim_boundary": "Patch-context replication on BigVul; not ASR rule semantic correctness and not deployment evidence.",
    }


def make_figure(summary: dict[str, Any], controls_df: pd.DataFrame) -> None:
    FIGURES.mkdir(parents=True, exist_ok=True)
    fig, axes = plt.subplots(1, 2, figsize=(8.6, 3.4))
    labels = ["structural_only", "category_gate", "strict_mddc_gate"]
    true = [summary["true_pair_rates"][key]["rate"] for key in labels]
    axes[0].bar(labels, true, color=["#a5a5a5", "#70ad47", "#2f5597"])
    axes[0].set_ylim(0, 1)
    axes[0].set_title("BigVul true-pair admission")
    axes[0].tick_params(axis="x", rotation=25, labelsize=8)

    same = controls_df[controls_df["mode"].eq("same_category_different_cve")]
    false_rates = [
        float((same["structural_only_admitted"] / same["n_pairs"]).mean()),
        float((same["category_gate_admitted"] / same["n_pairs"]).mean()),
        float((same["strict_mddc_gate_admitted"] / same["n_pairs"]).mean()),
    ]
    axes[1].bar(labels, false_rates, color=["#a5a5a5", "#70ad47", "#2f5597"])
    axes[1].set_ylim(0, 1)
    axes[1].set_title("Same-category false admission")
    axes[1].tick_params(axis="x", rotation=25, labelsize=8)
    fig.tight_layout()
    fig.savefig(OUT_FIG_PDF)
    fig.savefig(OUT_FIG_PNG, dpi=220)
    plt.close(fig)


def main() -> int:
    RESULTS.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    df = pd.read_csv(RAW)
    refs, cands, rows = prepare_records(df)
    rows_df = pd.DataFrame(rows)
    controls_df = pd.DataFrame(control_trials(refs, cands))
    rows_df.to_csv(OUT_ROWS, index=False)
    controls_df.to_csv(OUT_CONTROLS, index=False)
    summary = summarize(rows_df, controls_df)
    summary["outputs"] = {
        "rows_csv": str(OUT_ROWS),
        "controls_csv": str(OUT_CONTROLS),
        "summary_json": str(OUT_SUMMARY),
        "report_md": str(OUT_REPORT),
        "figure_pdf": str(OUT_FIG_PDF),
        "figure_png": str(OUT_FIG_PNG),
    }
    OUT_SUMMARY.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    make_figure(summary, controls_df)

    same = summary["control_summary"].get("same_category_different_cve", {})
    lines = [
        "# Experiment LXXIX BigVul Cross-Dataset Replication",
        "",
        f"Generated: {summary['generated_at']}",
        "",
        "## Material Passport",
        "",
        "- Mode: code experiment / cross-dataset replication",
        "- Data access: public BigVul CSV downloaded direct from GitHub raw",
        "- Claim boundary: patch-context gate replication, not ASR semantic correctness",
        "",
        "## Result",
        "",
        f"- BigVul true pairs: `{summary['n_true_pairs']}`",
        f"- Strict true admission: `{summary['true_pair_rates']['strict_mddc_gate']['admitted']}/{summary['n_true_pairs']}` = `{summary['true_pair_rates']['strict_mddc_gate']['rate']:.6f}`",
        f"- Strict Wilson 95% CI: `{summary['true_pair_rates']['strict_mddc_gate']['wilson95'][0]:.6f}`-`{summary['true_pair_rates']['strict_mddc_gate']['wilson95'][1]:.6f}`",
        f"- Same-category structural false rate: `{same.get('structural_only_mean_rate', float('nan')):.6f}`",
        f"- Same-category strict false rate: `{same.get('strict_mddc_gate_mean_rate', float('nan')):.6f}`",
        f"- Strict false-admission reduction vs structural: `{same.get('strict_false_admission_reduction_vs_structural_pct', float('nan')):.3f}%`",
        f"- Pre-registered success: `{all(summary['success_condition'].values())}`",
        "",
        "## Outputs",
        "",
        f"- Rows: `{OUT_ROWS}`",
        f"- Controls: `{OUT_CONTROLS}`",
        f"- Summary: `{OUT_SUMMARY}`",
        f"- Figure PDF: `{OUT_FIG_PDF}`",
        "",
        "Document generated: " + now_cst(),
    ]
    OUT_REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"summary": str(OUT_SUMMARY), "report": str(OUT_REPORT), "success": all(summary["success_condition"].values())}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

