#!/usr/bin/env python3
"""Experiment LXXVII: patch-differential oracle cross-check for ASR gates.

This experiment is deliberately objective and reproducible. ASRDataset provides
XML rule artifacts and patch commit URLs, but not complete before/after source
trees. Therefore this script uses public GitHub commit patches as a deterministic
surrogate:

- deleted/context patch lines approximate vulnerable-parent evidence;
- added patch lines approximate upstream-fixed evidence;
- shuffled patches provide negative controls.

It does not claim full Semgrep execution over checked-out repositories.
"""

from __future__ import annotations

import os

import hashlib
import json
import math
import random
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import pandas as pd


ROOT = Path(os.environ.get("MDDC_ROOT", "/root/mddc"))
sys.path.insert(0, str(ROOT / "empirical_validation"))

from experiment_lxiii_objective_semantic_qualification_expanded import parse_xml_context  # noqa: E402


RESULTS = ROOT / "empirical_validation" / "results"
REPORTS = ROOT / "review_rounds"
FIGURES = ROOT / "empirical_validation" / "figures"
CACHE = ROOT / "artifacts" / "patch_cache" / "lxxvii_asr_patch_differential"

LXIII_ROWS = RESULTS / "experiment_lxiii_objective_semantic_qualification_expanded_rows_20260623.csv"
LXII_ROWS = RESULTS / "experiment_lxii_asr_full_rule_capital_audit_rows.csv"
PREREG = ROOT / "empirical_validation" / "experiment_lxxvii_lxxviii_preregistration_20260624.md"

OUT_ROWS = RESULTS / "experiment_lxxvii_patch_differential_oracle_rows_20260624.csv"
OUT_CONTROLS = RESULTS / "experiment_lxxvii_patch_differential_oracle_controls_20260624.csv"
OUT_SUMMARY = RESULTS / "experiment_lxxvii_patch_differential_oracle_summary_20260624.json"
OUT_REPORT = REPORTS / "experiment_lxxvii_patch_differential_oracle_20260624.md"
OUT_FIG_PDF = FIGURES / "fig_experiment_lxxvii_patch_differential_oracle.pdf"
OUT_FIG_PNG = FIGURES / "fig_experiment_lxxvii_patch_differential_oracle.png"

RANDOM_SEED = 20260624
CONTROL_TRIALS = 1000
HTTP_TIMEOUT_SECONDS = 25


STOPWORDS = {
    "the",
    "and",
    "for",
    "with",
    "that",
    "this",
    "from",
    "into",
    "java",
    "org",
    "com",
    "net",
    "io",
    "lang",
    "util",
    "void",
    "string",
    "object",
    "true",
    "false",
    "null",
    "unknown",
    "type",
    "param",
    "parameter",
    "value",
}

SECURITY_LEXICON = {
    "allow",
    "allowlist",
    "auth",
    "authentication",
    "authorization",
    "base",
    "block",
    "canonical",
    "certificate",
    "check",
    "containment",
    "csrf",
    "decode",
    "doctype",
    "encode",
    "encryption",
    "escape",
    "external",
    "filter",
    "host",
    "html",
    "limit",
    "normalize",
    "permission",
    "realpath",
    "reject",
    "role",
    "safe",
    "sanitize",
    "signature",
    "startswith",
    "symlink",
    "token",
    "validate",
    "validation",
    "verify",
    "whitelist",
}

CATEGORY_TERMS = {
    "path": {"path", "traversal", "directory", "canonical", "normalize", "realpath", "startswith"},
    "xss": {"xss", "script", "html", "escape", "encode", "sanitize"},
    "xxe": {"xml", "xxe", "entity", "doctype", "external"},
    "ssrf": {"ssrf", "redirect", "url", "host", "http"},
    "sqli": {"sql", "query", "prepared", "statement", "parameter"},
    "command": {"command", "shell", "exec", "process", "template"},
    "deserialization": {"deserialize", "serialization", "pickle"},
    "dos": {"limit", "timeout", "size", "memory", "loop", "resource"},
    "auth": {"auth", "permission", "role", "token", "session", "csrf"},
    "crypto": {"crypto", "certificate", "signature", "secret", "key", "encrypt"},
}


@dataclass(frozen=True)
class PatchParts:
    url: str
    patch_url: str
    cache_path: str
    status: str
    bytes: int
    sha256: str
    added_text: str
    removed_text: str
    context_text: str
    error: str = ""


def now_cst() -> str:
    return datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S +08:00")


def normalize_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and math.isnan(value):
        return ""
    return str(value).lower()


def split_identifier(value: Any) -> set[str]:
    text = normalize_text(value)
    text = re.sub(r"([a-z])([A-Z])", r"\1 \2", str(value or ""))
    text = text.lower()
    raw = re.findall(r"[a-z][a-z0-9_]{2,}", text)
    return {tok for tok in raw if tok not in STOPWORDS and len(tok) >= 3}


def token_set(value: Any) -> set[str]:
    text = normalize_text(value)
    raw = re.findall(r"[a-z][a-z0-9_]{2,}", text)
    return {tok for tok in raw if tok not in STOPWORDS and len(tok) >= 3}


def count_hits(tokens: set[str], text: str) -> int:
    if not tokens or not text:
        return 0
    lowered = text.lower()
    return sum(1 for tok in tokens if tok in lowered)


def patch_url(commit_url: str) -> str:
    url = str(commit_url).strip()
    if not url:
        return ""
    if url.endswith(".patch"):
        return url
    return url.rstrip("/") + ".patch"


def cache_name(url: str) -> str:
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
    tail = re.sub(r"[^a-zA-Z0-9_.-]+", "_", url.rstrip("/").split("/")[-1])[:48]
    return f"{tail}_{digest}.patch"


def fetch_patch(commit_url: str) -> PatchParts:
    CACHE.mkdir(parents=True, exist_ok=True)
    purl = patch_url(commit_url)
    if not purl:
        return PatchParts(commit_url, "", "", "missing_url", 0, "", "", "", "", "missing patch URL")
    path = CACHE / cache_name(purl)
    error = ""
    if path.exists() and path.stat().st_size > 0:
        data = path.read_bytes()
        status = "cached"
    else:
        try:
            req = urllib.request.Request(purl, headers={"User-Agent": "mddc-lxxvii-patch-oracle"})
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
                data = resp.read()
            path.write_bytes(data)
            status = "downloaded"
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            data = b""
            status = "fetch_failed"
            error = f"{type(exc).__name__}: {exc}"
    sha = hashlib.sha256(data).hexdigest() if data else ""
    added, removed, context = split_patch_text(data.decode("utf-8", errors="replace"))
    return PatchParts(
        url=commit_url,
        patch_url=purl,
        cache_path=str(path),
        status=status,
        bytes=len(data),
        sha256=sha,
        added_text=added,
        removed_text=removed,
        context_text=context,
        error=error,
    )


def split_patch_text(text: str) -> tuple[str, str, str]:
    added: list[str] = []
    removed: list[str] = []
    context: list[str] = []
    for line in text.splitlines():
        if not line:
            continue
        if line.startswith(("diff --git", "index ", "@@", "From ", "Date:", "Subject:")):
            continue
        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("+"):
            added.append(line[1:])
        elif line.startswith("-"):
            removed.append(line[1:])
        elif line.startswith(" "):
            context.append(line[1:])
    return "\n".join(added).lower(), "\n".join(removed).lower(), "\n".join(context).lower()


def extract_rule_terms(row: pd.Series, lxii_row: pd.Series) -> dict[str, set[str]]:
    gt_xml = str(lxii_row.get("gt_xml", ""))
    ctx = parse_xml_context(gt_xml)
    api_terms: set[str] = set()
    for key in ["gt_rule_id", "gt_method", "gt_function"]:
        api_terms |= split_identifier(row.get(key, ""))
    for value in ctx.get("function_names", []):
        api_terms |= split_identifier(value)
    api_terms = {t for t in api_terms if len(t) >= 4}

    category_text = normalize_text(row.get("gt_category", ""))
    category_terms: set[str] = set()
    for key, terms in CATEGORY_TERMS.items():
        if key in category_text:
            category_terms |= terms

    protection_terms = set()
    security_text = " ".join(ctx.get("security_comments", []) + ctx.get("protections", []))
    protection_terms |= token_set(security_text) & (SECURITY_LEXICON | category_terms)
    protection_terms |= category_terms

    vuln_terms = set()
    vuln_text = " ".join(ctx.get("vul_comments", []))
    vuln_terms |= token_set(vuln_text) & (SECURITY_LEXICON | category_terms | api_terms)
    vuln_terms |= category_terms

    return {
        "api_terms": api_terms,
        "protection_terms": protection_terms,
        "vuln_terms": vuln_terms,
    }


def score_oracle(row: pd.Series, lxii_row: pd.Series, patch: PatchParts) -> dict[str, Any]:
    terms = extract_rule_terms(row, lxii_row)
    parent_text = "\n".join([patch.removed_text, patch.context_text])
    upstream_text = "\n".join([patch.added_text, patch.context_text])
    removed_text = patch.removed_text
    added_text = patch.added_text

    api_parent_hits = count_hits(terms["api_terms"], parent_text)
    vuln_parent_hits = count_hits(terms["vuln_terms"], parent_text)
    upstream_protection_hits = count_hits(terms["protection_terms"], upstream_text)
    added_protection_hits = count_hits(terms["protection_terms"], added_text)
    removed_protection_hits = count_hits(terms["protection_terms"], removed_text)

    parent_exposure_signal = api_parent_hits > 0 or vuln_parent_hits >= 2
    upstream_protection_signal = upstream_protection_hits > 0 and added_protection_hits > 0
    directional_gain = added_protection_hits > removed_protection_hits
    patch_available = patch.status in {"cached", "downloaded"} and patch.bytes > 0
    oracle_validated = bool(
        patch_available and parent_exposure_signal and upstream_protection_signal and directional_gain
    )
    return {
        "patch_available": patch_available,
        "patch_status": patch.status,
        "patch_url": patch.patch_url,
        "patch_cache_path": patch.cache_path,
        "patch_bytes": patch.bytes,
        "patch_sha256": patch.sha256,
        "patch_error": patch.error,
        "api_terms": ";".join(sorted(terms["api_terms"])),
        "protection_terms": ";".join(sorted(terms["protection_terms"])),
        "vuln_terms": ";".join(sorted(terms["vuln_terms"])),
        "api_parent_hits": api_parent_hits,
        "vuln_parent_hits": vuln_parent_hits,
        "upstream_protection_hits": upstream_protection_hits,
        "added_protection_hits": added_protection_hits,
        "removed_protection_hits": removed_protection_hits,
        "parent_exposure_signal": parent_exposure_signal,
        "upstream_protection_signal": upstream_protection_signal,
        "directional_gain": directional_gain,
        "oracle_validated": oracle_validated,
    }


def wilson(k: int, n: int, z: float = 1.959963984540054) -> list[float]:
    if n <= 0:
        return [float("nan"), float("nan")]
    phat = k / n
    denom = 1 + z * z / n
    centre = phat + z * z / (2 * n)
    margin = z * math.sqrt((phat * (1 - phat) + z * z / (4 * n)) / n)
    return [(centre - margin) / denom, (centre + margin) / denom]


def load_inputs() -> tuple[pd.DataFrame, pd.DataFrame]:
    lxiii = pd.read_csv(LXIII_ROWS)
    lxiii = lxiii[lxiii["pair_type"].astype(str).eq("true_pair")].copy()
    lxii = pd.read_csv(LXII_ROWS)
    lxii = lxii.drop_duplicates(subset=["task_id"]).set_index("task_id", drop=False)
    return lxiii, lxii


def deranged_indices(indices: list[int], rng: random.Random) -> list[int]:
    if len(indices) < 2:
        return indices[:]
    while True:
        shuffled = indices[:]
        rng.shuffle(shuffled)
        if all(a != b for a, b in zip(indices, shuffled)):
            return shuffled


def cross_category_indices(df: pd.DataFrame, rng: random.Random) -> list[int]:
    cats = list(df["gt_category"].astype(str))
    indices = list(range(len(df)))
    out: list[int] = []
    for i, cat in enumerate(cats):
        choices = [j for j in indices if j != i and cats[j] != cat]
        out.append(rng.choice(choices if choices else [j for j in indices if j != i]))
    return out


def run_controls(
    strict: pd.DataFrame,
    lxii: pd.DataFrame,
    patches_by_task: dict[str, PatchParts],
    trials: int,
) -> pd.DataFrame:
    rng = random.Random(RANDOM_SEED)
    records = strict.reset_index(drop=True)
    indices = list(range(len(records)))
    rows: list[dict[str, Any]] = []
    for mode in ["any_deranged", "cross_category"]:
        for trial in range(trials):
            if mode == "any_deranged":
                chosen = deranged_indices(indices, rng)
            else:
                chosen = cross_category_indices(records, rng)
            count = 0
            available = 0
            for i, patch_idx in zip(indices, chosen):
                row = records.iloc[i]
                patch_task = str(records.iloc[patch_idx]["gt_task_id"])
                lxii_row = lxii.loc[str(row["gt_task_id"])]
                score = score_oracle(row, lxii_row, patches_by_task[patch_task])
                count += int(score["oracle_validated"])
                available += int(score["patch_available"])
            rows.append(
                {
                    "mode": mode,
                    "trial": trial,
                    "n": len(records),
                    "patch_available": available,
                    "oracle_validated": count,
                    "false_validation_rate": count / len(records) if len(records) else float("nan"),
                }
            )
    return pd.DataFrame(rows)


def make_figure(row_summary: dict[str, Any], controls: pd.DataFrame, category: pd.DataFrame) -> None:
    FIGURES.mkdir(parents=True, exist_ok=True)
    fig, axes = plt.subplots(1, 3, figsize=(11.5, 3.4))

    true_rate = row_summary["true_oracle_rate"]
    ci_low, ci_high = row_summary["true_oracle_wilson95"]
    axes[0].bar([0], [true_rate], color="#2f5597")
    axes[0].errorbar([0], [true_rate], yerr=[[true_rate - ci_low], [ci_high - true_rate]], fmt="none", color="black", capsize=4)
    axes[0].set_xticks([0], ["strict true pairs"])
    axes[0].set_ylim(0, 1)
    axes[0].set_ylabel("Patch-differential validation rate")
    axes[0].set_title("True-pair oracle")

    ctrl_summary = controls.groupby("mode")["false_validation_rate"].agg(["mean", "max"]).reset_index()
    x = range(len(ctrl_summary))
    axes[1].bar([v - 0.17 for v in x], ctrl_summary["mean"], width=0.34, label="mean", color="#a5a5a5")
    axes[1].bar([v + 0.17 for v in x], ctrl_summary["max"], width=0.34, label="max", color="#c00000")
    axes[1].set_xticks(list(x), ctrl_summary["mode"], rotation=20, ha="right")
    axes[1].set_ylim(0, max(0.12, float(ctrl_summary["max"].max()) * 1.2))
    axes[1].set_title("Negative controls")
    axes[1].legend(frameon=False, fontsize=8)

    category = category.sort_values("oracle_rate")
    axes[2].barh(category["gt_category"], category["oracle_rate"], color="#2f5597")
    axes[2].set_xlim(0, 1)
    axes[2].set_title("By category")
    axes[2].tick_params(axis="y", labelsize=7)

    fig.tight_layout()
    fig.savefig(OUT_FIG_PDF)
    fig.savefig(OUT_FIG_PNG, dpi=220)
    plt.close(fig)


def main() -> int:
    RESULTS.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    lxiii, lxii = load_inputs()
    strict = lxiii[lxiii["strict_admit_to_Hq"].astype(str).str.lower().isin({"true", "1"})].copy()

    patch_tasks = sorted(set(strict["gt_task_id"].astype(str)))
    patches_by_task: dict[str, PatchParts] = {}
    for task_id in patch_tasks:
        commit_url = str(lxii.loc[task_id]["gt_patch_commit"])
        patches_by_task[task_id] = fetch_patch(commit_url)

    out_rows: list[dict[str, Any]] = []
    for _, row in strict.iterrows():
        task_id = str(row["gt_task_id"])
        lxii_row = lxii.loc[task_id]
        score = score_oracle(row, lxii_row, patches_by_task[task_id])
        out_rows.append(
            {
                "task_id": task_id,
                "gt_category": row.get("gt_category", ""),
                "gt_rule_id": row.get("gt_rule_id", ""),
                "gt_function": row.get("gt_function", ""),
                "objective_score": row.get("objective_score", ""),
                "patch_commit": lxii_row.get("gt_patch_commit", ""),
                **score,
            }
        )
    rows_df = pd.DataFrame(out_rows)
    rows_df.to_csv(OUT_ROWS, index=False)

    controls_df = run_controls(strict, lxii, patches_by_task, CONTROL_TRIALS)
    controls_df.to_csv(OUT_CONTROLS, index=False)

    n = len(rows_df)
    k = int(rows_df["oracle_validated"].sum())
    available = int(rows_df["patch_available"].sum())
    category_df = (
        rows_df.groupby("gt_category")
        .agg(n=("task_id", "count"), oracle_validated=("oracle_validated", "sum"), patch_available=("patch_available", "sum"))
        .reset_index()
    )
    category_df["oracle_rate"] = category_df["oracle_validated"] / category_df["n"]
    ctrl = controls_df.groupby("mode").agg(
        trials=("trial", "count"),
        mean_false_validation_rate=("false_validation_rate", "mean"),
        max_false_validation_rate=("false_validation_rate", "max"),
        mean_false_validations=("oracle_validated", "mean"),
        max_false_validations=("oracle_validated", "max"),
    )
    ctrl_summary = ctrl.reset_index().to_dict("records")

    ci = wilson(k, n)
    cross_mean = float(ctrl.loc["cross_category", "mean_false_validation_rate"]) if "cross_category" in ctrl.index else float("nan")
    success = bool(k / n >= 0.60 and ci[0] >= 0.50 and cross_mean <= 0.05)
    stop_failed = bool(k / n < 0.35 and cross_mean > 0.10)
    summary = {
        "experiment": "LXXVII patch-differential oracle cross-check",
        "generated_at": now_cst(),
        "preregistration": str(PREREG),
        "claim_boundary": "Patch-diff surrogate over public commit patches, not full Semgrep execution over checked-out repositories.",
        "random_seed": RANDOM_SEED,
        "control_trials": CONTROL_TRIALS,
        "input_files": {
            "lxiii_rows": str(LXIII_ROWS),
            "lxii_rows": str(LXII_ROWS),
        },
        "n_strict_admissions": n,
        "patch_available": available,
        "patch_available_rate": available / n if n else float("nan"),
        "true_oracle_validated": k,
        "true_oracle_rate": k / n if n else float("nan"),
        "true_oracle_wilson95": ci,
        "success_condition": {
            "true_rate_ge_0_60": (k / n if n else 0) >= 0.60,
            "wilson_lower_ge_0_50": ci[0] >= 0.50,
            "cross_category_mean_false_rate_le_0_05": cross_mean <= 0.05,
            "overall_success": success,
        },
        "stop_condition": {
            "true_rate_lt_0_35_and_negative_gt_0_10": stop_failed,
            "do_not_run_lxxx": not success,
        },
        "negative_controls": ctrl_summary,
        "by_category": category_df.to_dict("records"),
        "outputs": {
            "rows_csv": str(OUT_ROWS),
            "controls_csv": str(OUT_CONTROLS),
            "summary_json": str(OUT_SUMMARY),
            "report_md": str(OUT_REPORT),
            "figure_pdf": str(OUT_FIG_PDF),
            "figure_png": str(OUT_FIG_PNG),
            "patch_cache": str(CACHE),
        },
    }
    OUT_SUMMARY.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    make_figure(summary, controls_df, category_df)

    lines = [
        "# Experiment LXXVII Patch-Differential Oracle Cross-Check",
        "",
        f"Generated: {summary['generated_at']}",
        "",
        "## Material Passport",
        "",
        "- Mode: code experiment / reproducibility validation",
        "- Data access: public ASR XML and public GitHub commit patches",
        "- Pre-registration: `" + str(PREREG) + "`",
        "- Claim boundary: patch-diff surrogate; not full checked-out repository Semgrep execution",
        "",
        "## Result",
        "",
        f"- Strict ASR admissions evaluated: `{n}`",
        f"- Patch available: `{available}/{n}` = `{summary['patch_available_rate']:.6f}`",
        f"- Patch-differential validated: `{k}/{n}` = `{summary['true_oracle_rate']:.6f}`",
        f"- Wilson 95% CI: `{ci[0]:.6f}`-`{ci[1]:.6f}`",
        f"- Pre-registered success: `{success}`",
        f"- LXXX deployment mini-trial allowed by LXXVII: `{success}`",
        "",
        "## Negative Controls",
        "",
        "| Mode | Trials | Mean false rate | Max false rate |",
        "|---|---:|---:|---:|",
    ]
    for row in ctrl_summary:
        lines.append(
            f"| {row['mode']} | {int(row['trials'])} | {row['mean_false_validation_rate']:.6f} | {row['max_false_validation_rate']:.6f} |"
        )
    lines += [
        "",
        "## Interpretation Boundary",
        "",
        "A positive result supports deterministic patch-differential evidence for ASR rule-capital admission. "
        "A negative result would not invalidate the structural gate, but would prevent using it as behavioral semantic validation.",
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
    print(json.dumps({"summary": str(OUT_SUMMARY), "report": str(OUT_REPORT), "success": success, "rate": k / n if n else None}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

