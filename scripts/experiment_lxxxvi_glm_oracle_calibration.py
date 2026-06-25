#!/usr/bin/env python3
"""Experiment LXXXVI: GLM-assisted candidate oracle calibration.

GLM is used only as a candidate oracle generator. The admission decision is made
by objective gates derived from the existing LXXVII patch-differential oracle
signals. This prevents the experiment from becoming another LLM-as-judge table.

Boundary:
- This is a small calibration experiment over patch-differential surrogate
  signals, not a deployment/native/dynamic all-gate experiment.
- GLM output is not ground truth.
"""

from __future__ import annotations

import json
import os
import random
import re
import shutil
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import requests


ROOT = Path(os.environ.get("MDDC_ROOT", "/root/mddc"))
ENV_FILE = Path(os.environ.get("LLM_API_KEYS_FILE", "/mnt/c/Users/PBCDCI/.llm_api_keys.env"))
RESULTS = ROOT / "empirical_validation" / "results"
FIGURES = ROOT / "empirical_validation" / "figures"
REPORTS = ROOT / "review_rounds"
PREVIEW = Path("/mnt/d/lunwen/MDDC_Preview/latest")

IN_ROWS = RESULTS / "experiment_lxxvii_patch_differential_oracle_rows_20260624.csv"

OUT_ROWS = RESULTS / "experiment_lxxxvi_glm_oracle_calibration_rows_20260625.csv"
OUT_CHECKPOINT = RESULTS / "experiment_lxxxvi_glm_oracle_calibration_checkpoint_20260625.csv"
OUT_SUMMARY = RESULTS / "experiment_lxxxvi_glm_oracle_calibration_summary_20260625.json"
OUT_REPORT = REPORTS / "experiment_lxxxvi_glm_oracle_calibration_20260625.md"
OUT_REPRO = REPORTS / "REPRODUCE_LXXXVI_GLM_ORACLE_CALIBRATION_20260625.md"
OUT_FIG_PDF = FIGURES / "fig_experiment_lxxxvi_glm_oracle_calibration.pdf"
OUT_FIG_PNG = FIGURES / "fig_experiment_lxxxvi_glm_oracle_calibration.png"

RANDOM_SEED = 20260625
N_POSITIVE = 20
N_NEGATIVE = 20
GLM_ENDPOINT = "https://open.bigmodel.cn/api/paas/v4/chat/completions"
GLM_MODEL = os.environ.get("GLM_MODEL", "glm-4.7")
REQUEST_TIMEOUT = 120
MAX_PATCH_CHARS = 2200
MAX_OUTPUT_TOKENS = 600

GENERIC_TERMS = {
    "check", "validate", "validation", "sanitize", "sanitization", "input",
    "output", "data", "value", "object", "method", "function", "security",
    "safe", "unsafe", "error", "exception", "return", "true", "false",
    "null", "fix", "fixed", "vulnerability", "vulnerable",
}


def now_cst() -> str:
    return datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S +08:00")


def load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        name, value = stripped.split("=", 1)
        name = name.strip()
        value = value.strip().strip('"').strip("'")
        if name and value and name not in os.environ:
            os.environ[name] = value


def require_glm_key() -> str:
    key = os.environ.get("GLM_API_KEY", "")
    if not key:
        raise RuntimeError("Missing GLM_API_KEY")
    return key


def to_bool(value: Any) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes"}


def split_terms(value: Any) -> set[str]:
    text = str(value or "").lower()
    terms = {t for t in re.split(r"[^a-z0-9_.$<>-]+", text) if len(t) >= 3}
    out = set()
    for term in terms:
        out.add(term)
        for part in re.split(r"[._$<>:-]+", term):
            if len(part) >= 3:
                out.add(part)
    return out


def normalize_list(value: Any) -> list[str]:
    if isinstance(value, list):
        raw = value
    elif isinstance(value, str):
        raw = re.split(r"[,;|\n]+", value)
    else:
        raw = []
    terms: list[str] = []
    seen: set[str] = set()
    for item in raw:
        for term in split_terms(item):
            if term not in seen:
                seen.add(term)
                terms.append(term)
    return terms[:12]


def json_from_text(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?", "", text, flags=re.I).strip()
        text = re.sub(r"```$", "", text).strip()
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return {}
    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return {}


def extract_patch_excerpt(path_value: Any) -> str:
    path = Path(str(path_value or ""))
    if not path.exists():
        return ""
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = []
    for line in text.splitlines():
        if line.startswith(("diff --git", "index ", "@@", "+++", "---")):
            lines.append(line[:180])
        elif line.startswith(("+", "-")) and not line.startswith(("+++", "---")):
            lower = line.lower()
            if any(k in lower for k in [
                "check", "valid", "sanitize", "escape", "encode", "canonical",
                "normalize", "permission", "path", "csrf", "xss", "token",
                "auth", "length", "bound", "overflow", "null", "reject",
                "allow", "deny", "safe", "security",
            ]):
                lines.append(line[:220])
        if sum(len(x) for x in lines) >= MAX_PATCH_CHARS:
            break
    excerpt = "\n".join(lines)
    if not excerpt:
        excerpt = text[:MAX_PATCH_CHARS]
    return excerpt[:MAX_PATCH_CHARS]


def select_sample(df: pd.DataFrame) -> pd.DataFrame:
    df = df[df["patch_available"].map(to_bool) & df["patch_status"].eq("downloaded")].copy()
    df["oracle_validated_bool"] = df["oracle_validated"].map(to_bool)
    df["objective_score_num"] = pd.to_numeric(df["objective_score"], errors="coerce").fillna(0.0)
    pos = df[df["oracle_validated_bool"]].sort_values(["objective_score_num", "task_id"], ascending=[False, True])
    neg = df[~df["oracle_validated_bool"]].sort_values(["objective_score_num", "task_id"], ascending=[False, True])
    rng = random.Random(RANDOM_SEED)
    pos_ids = list(pos.index)
    neg_ids = list(neg.index)
    rng.shuffle(pos_ids)
    rng.shuffle(neg_ids)
    take = pos.loc[pos_ids[:N_POSITIVE]].copy()
    take2 = neg.loc[neg_ids[:N_NEGATIVE]].copy()
    sample = pd.concat([take, take2], ignore_index=True)
    sample["sample_role"] = np.where(sample["oracle_validated_bool"], "objective_positive", "objective_negative")
    return sample.sort_values(["sample_role", "task_id"]).reset_index(drop=True)


def build_prompt(row: pd.Series, patch_excerpt: str) -> str:
    return f"""You generate candidate security oracle predicates from patch context.

Return JSON only. Do not include markdown.

The oracle is a candidate only. It will be checked later by objective gates.

Fields:
{{
  "oracle_kind": "static_predicate|assertion|differential_test|security_rule",
  "target_api_terms": ["..."],
  "vulnerable_condition_terms": ["..."],
  "fixed_condition_terms": ["..."],
  "security_predicate": "one precise checkable sentence",
  "vacuity_risk": "low|medium|high",
  "uses_patch_specific_evidence": true/false
}}

Task metadata:
- task_id: {row.get('task_id', '')}
- category: {row.get('gt_category', '')}
- rule_id: {row.get('gt_rule_id', '')}
- function: {row.get('gt_function', '')}
- API terms: {row.get('api_terms', '')}
- vulnerability terms: {row.get('vuln_terms', '')}
- expected protection terms: {row.get('protection_terms', '')}

Patch excerpt:
<<<PATCH
{patch_excerpt}
PATCH>>>
"""


def call_glm(prompt: str, key: str) -> dict[str, Any]:
    payload = {
        "model": GLM_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
        "max_tokens": MAX_OUTPUT_TOKENS,
        "stream": False,
    }
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    last_text = ""
    session = requests.Session()
    # WSL may inherit an unstable local proxy. API calls should be direct-first
    # and should not depend on browser/Clash/WinHTTP state.
    session.trust_env = False
    for attempt in range(1, 4):
        started = time.time()
        try:
            response = session.post(GLM_ENDPOINT, headers=headers, json=payload, timeout=REQUEST_TIMEOUT)
            elapsed = round(time.time() - started, 2)
            last_text = response.text[:1000]
        except requests.RequestException as exc:
            elapsed = round(time.time() - started, 2)
            last_text = f"{type(exc).__name__}: {str(exc)[:800]}"
            if attempt < 3:
                time.sleep(5 * attempt)
                continue
            return {
                "ok": False,
                "attempt": attempt,
                "wall_seconds": elapsed,
                "text": "",
                "error": last_text,
                "usage": {},
            }
        if response.status_code in {429, 500, 502, 503, 504} and attempt < 3:
            time.sleep(5 * attempt)
            continue
        if not response.ok:
            return {
                "ok": False,
                "attempt": attempt,
                "wall_seconds": elapsed,
                "text": "",
                "error": f"HTTP {response.status_code}: {last_text}",
                "usage": {},
            }
        data = response.json()
        message = ((data.get("choices") or [{}])[0].get("message") or {})
        return {
            "ok": True,
            "attempt": attempt,
            "wall_seconds": elapsed,
            "text": message.get("content") or "",
            "reasoning_preview": (message.get("reasoning_content") or "")[:120],
            "error": "",
            "usage": data.get("usage") or {},
            "api_id": data.get("id", ""),
        }
    return {"ok": False, "attempt": 3, "wall_seconds": 0, "text": "", "error": last_text, "usage": {}}


def evaluate_candidate(row: pd.Series, parsed: dict[str, Any]) -> dict[str, Any]:
    target_terms = set(normalize_list(parsed.get("target_api_terms")))
    vuln_terms = set(normalize_list(parsed.get("vulnerable_condition_terms")))
    fixed_terms = set(normalize_list(parsed.get("fixed_condition_terms")))
    predicate = str(parsed.get("security_predicate") or "")
    predicate_terms = split_terms(predicate)

    row_api = split_terms(row.get("api_terms"))
    row_vuln = split_terms(row.get("vuln_terms"))
    row_protect = split_terms(row.get("protection_terms"))
    function = str(row.get("gt_function") or "").lower()
    function_terms = split_terms(function)

    non_generic_terms = (target_terms | vuln_terms | fixed_terms | predicate_terms) - GENERIC_TERMS
    parsable = bool(parsed)
    non_vacuous = (
        parsable
        and len(predicate) >= 24
        and str(parsed.get("vacuity_risk", "")).lower() != "high"
        and len(non_generic_terms) >= 3
    )
    api_overlap = len((target_terms | predicate_terms) & (row_api | function_terms))
    vuln_overlap = len((vuln_terms | predicate_terms) & row_vuln)
    fixed_overlap = len((fixed_terms | predicate_terms) & row_protect)
    target_aligned = api_overlap > 0 or function.lower() in predicate.lower()
    condition_aligned = vuln_overlap > 0
    protection_aligned = fixed_overlap > 0
    uses_patch_specific = bool(parsed.get("uses_patch_specific_evidence")) or protection_aligned

    glm_candidate_gate = all([parsable, non_vacuous, target_aligned, protection_aligned, uses_patch_specific])
    objective_signals = all([
        to_bool(row.get("parent_exposure_signal")),
        to_bool(row.get("upstream_protection_signal")),
        to_bool(row.get("directional_gain")),
    ])
    qgdca_qualified = glm_candidate_gate and objective_signals
    oracle_validated = to_bool(row.get("oracle_validated"))
    return {
        "parsable_json": parsable,
        "non_vacuous": non_vacuous,
        "target_aligned": target_aligned,
        "condition_aligned": condition_aligned,
        "protection_aligned": protection_aligned,
        "uses_patch_specific_evidence": uses_patch_specific,
        "api_overlap": api_overlap,
        "vuln_overlap": vuln_overlap,
        "fixed_overlap": fixed_overlap,
        "glm_candidate_gate": glm_candidate_gate,
        "objective_signals": objective_signals,
        "qgdca_qualified": qgdca_qualified,
        "oracle_validated": oracle_validated,
        "glm_only_false_candidate": glm_candidate_gate and not oracle_validated,
        "qgdca_false_admission": qgdca_qualified and not oracle_validated,
        "parsed_oracle_kind": parsed.get("oracle_kind", ""),
        "parsed_vacuity_risk": parsed.get("vacuity_risk", ""),
        "parsed_predicate": predicate[:500],
        "parsed_target_terms": ";".join(sorted(target_terms)),
        "parsed_vulnerable_terms": ";".join(sorted(vuln_terms)),
        "parsed_fixed_terms": ";".join(sorted(fixed_terms)),
    }


def summarize(rows: pd.DataFrame) -> dict[str, Any]:
    n = len(rows)
    positives = rows["oracle_validated"].sum()
    negatives = n - positives
    glm_candidate_pos = int((rows["glm_candidate_gate"] & rows["oracle_validated"]).sum())
    glm_candidate_neg = int((rows["glm_candidate_gate"] & ~rows["oracle_validated"]).sum())
    qgdca_pos = int((rows["qgdca_qualified"] & rows["oracle_validated"]).sum())
    qgdca_neg = int((rows["qgdca_qualified"] & ~rows["oracle_validated"]).sum())
    total_prompt = int(rows["prompt_tokens"].sum())
    total_completion = int(rows["completion_tokens"].sum())
    total_tokens = int(rows["total_tokens"].sum())
    return {
        "experiment": "LXXXVI GLM-assisted candidate oracle calibration",
        "generated_at": now_cst(),
        "glm_model": GLM_MODEL,
        "endpoint": GLM_ENDPOINT,
        "sample": {
            "n_total": int(n),
            "objective_positive": int(positives),
            "objective_negative": int(negatives),
            "random_seed": RANDOM_SEED,
        },
        "metrics": {
            "glm_json_parse_rate": float(rows["parsable_json"].mean()),
            "glm_non_vacuous_rate": float(rows["non_vacuous"].mean()),
            "glm_candidate_gate_positive_recall": glm_candidate_pos / positives if positives else 0.0,
            "glm_only_false_candidate_rate_on_negatives": glm_candidate_neg / negatives if negatives else 0.0,
            "qgdca_qualified_positive_recall": qgdca_pos / positives if positives else 0.0,
            "qgdca_false_admission_rate_on_negatives": qgdca_neg / negatives if negatives else 0.0,
            "qgdca_qualified_total": int(rows["qgdca_qualified"].sum()),
            "glm_candidate_total": int(rows["glm_candidate_gate"].sum()),
        },
        "usage": {
            "prompt_tokens": total_prompt,
            "completion_tokens": total_completion,
            "total_tokens": total_tokens,
            "api_calls": int(n),
            "successful_calls": int(rows["glm_ok"].sum()),
        },
        "claim_boundary": (
            "GLM is only a candidate oracle generator. Qualification is decided by "
            "objective patch-differential surrogate gates; this is not deployment, "
            "native/dynamic all-gate, SOTA repair, or human semantic correctness."
        ),
        "outputs": {
            "rows_csv": str(OUT_ROWS),
            "summary_json": str(OUT_SUMMARY),
            "report_md": str(OUT_REPORT),
            "figure_pdf": str(OUT_FIG_PDF),
            "figure_png": str(OUT_FIG_PNG),
        },
    }


def plot(rows: pd.DataFrame, summary: dict[str, Any]) -> None:
    FIGURES.mkdir(parents=True, exist_ok=True)
    metrics = summary["metrics"]
    names = [
        "JSON parse",
        "Non-vacuous",
        "GLM pos recall",
        "GLM neg false",
        "QG-DCA pos recall",
        "QG-DCA neg false",
    ]
    values = [
        metrics["glm_json_parse_rate"],
        metrics["glm_non_vacuous_rate"],
        metrics["glm_candidate_gate_positive_recall"],
        metrics["glm_only_false_candidate_rate_on_negatives"],
        metrics["qgdca_qualified_positive_recall"],
        metrics["qgdca_false_admission_rate_on_negatives"],
    ]
    colors = ["#4C78A8", "#72B7B2", "#F58518", "#E45756", "#54A24B", "#B279A2"]
    fig, ax = plt.subplots(figsize=(9, 4.5))
    ax.bar(np.arange(len(names)), values, color=colors)
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Rate")
    ax.set_xticks(np.arange(len(names)))
    ax.set_xticklabels(names, rotation=25, ha="right")
    ax.grid(True, axis="y", alpha=0.25)
    ax.set_title("LXXXVI GLM candidate-oracle calibration")
    fig.tight_layout()
    fig.savefig(OUT_FIG_PDF, bbox_inches="tight")
    fig.savefig(OUT_FIG_PNG, bbox_inches="tight", dpi=220)
    plt.close(fig)


def write_report(summary: dict[str, Any], rows: pd.DataFrame) -> None:
    m = summary["metrics"]
    lines = [
        "# Experiment LXXXVI GLM-Assisted Candidate Oracle Calibration",
        "",
        f"Generated: {summary['generated_at']}",
        "",
        "## Purpose",
        "",
        "This experiment tests whether GLM can help construct candidate security oracles without making GLM a judge. GLM generates candidate predicates; objective patch-differential gates decide qualification.",
        "",
        "## Fixed Sample",
        "",
        f"- Objective-positive LXXVII tasks: `{summary['sample']['objective_positive']}`.",
        f"- Objective-negative LXXVII tasks: `{summary['sample']['objective_negative']}`.",
        f"- Random seed: `{RANDOM_SEED}`.",
        f"- GLM model: `{GLM_MODEL}`.",
        "",
        "## Main Results",
        "",
        f"- GLM JSON parse rate: `{m['glm_json_parse_rate']:.3f}`.",
        f"- GLM non-vacuous candidate rate: `{m['glm_non_vacuous_rate']:.3f}`.",
        f"- GLM candidate-gate recall on objective positives: `{m['glm_candidate_gate_positive_recall']:.3f}`.",
        f"- GLM-only false candidate rate on objective negatives: `{m['glm_only_false_candidate_rate_on_negatives']:.3f}`.",
        f"- QG-DCA qualified positive recall: `{m['qgdca_qualified_positive_recall']:.3f}`.",
        f"- QG-DCA false-admission rate on objective negatives: `{m['qgdca_false_admission_rate_on_negatives']:.3f}`.",
        "",
        "## Interpretation",
        "",
        "The result should be read as a candidate-oracle calibration, not as an LLM-judge experiment. If GLM produces checkable predicates but the objective gate rejects them on negative rows, the evidence supports the MDDC claim that generation and admission are separate stages.",
        "",
        "## Boundary",
        "",
        summary["claim_boundary"],
        "",
        "## Usage Audit",
        "",
        f"- API calls: `{summary['usage']['api_calls']}`.",
        f"- Successful calls: `{summary['usage']['successful_calls']}`.",
        f"- Prompt tokens: `{summary['usage']['prompt_tokens']}`.",
        f"- Completion tokens: `{summary['usage']['completion_tokens']}`.",
        f"- Total tokens: `{summary['usage']['total_tokens']}`.",
        "",
        "## Outputs",
        "",
        f"- Rows CSV: `{OUT_ROWS}`",
        f"- Summary JSON: `{OUT_SUMMARY}`",
        f"- Figure: `{OUT_FIG_PDF}`",
        "",
        "Document generated: " + now_cst(),
    ]
    OUT_REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_reproduce() -> None:
    lines = [
        "# Reproduce LXXXVI GLM-Assisted Candidate Oracle Calibration",
        "",
        "Run from `/root/mddc`:",
        "",
        "```bash",
        "python3 empirical_validation/experiment_lxxxvi_glm_oracle_calibration.py",
        "```",
        "",
        "Requires:",
        "",
        "- `GLM_API_KEY` in the local environment or `/mnt/c/Users/PBCDCI/.llm_api_keys.env`.",
        "- `/root/mddc/empirical_validation/results/experiment_lxxvii_patch_differential_oracle_rows_20260624.csv`.",
        "- cached patch files referenced by `patch_cache_path`.",
        "",
        f"Random seed: `{RANDOM_SEED}`.",
        f"Model: `{GLM_MODEL}`.",
        "",
        "Boundary: GLM generates candidates only; objective gates decide qualification.",
        "",
        "Document generated: " + now_cst(),
    ]
    OUT_REPRO.write_text("\n".join(lines) + "\n", encoding="utf-8")


def sync_preview() -> None:
    PREVIEW.mkdir(parents=True, exist_ok=True)
    for src, name in [
        (OUT_REPORT, "experiment_lxxxvi_glm_oracle_calibration_20260625.md"),
        (OUT_REPORT, "experiment_lxxxvi_glm_oracle_calibration_20260625.txt"),
        (OUT_REPRO, "REPRODUCE_LXXXVI_GLM_ORACLE_CALIBRATION_20260625.md"),
        (OUT_REPRO, "REPRODUCE_LXXXVI_GLM_ORACLE_CALIBRATION_20260625.txt"),
        (OUT_ROWS, "experiment_lxxxvi_glm_oracle_calibration_rows_20260625.csv"),
        (OUT_SUMMARY, "experiment_lxxxvi_glm_oracle_calibration_summary_20260625.json"),
        (OUT_FIG_PNG, "fig_experiment_lxxxvi_glm_oracle_calibration_20260625.png"),
        (OUT_FIG_PDF, "fig_experiment_lxxxvi_glm_oracle_calibration_20260625.pdf"),
    ]:
        shutil.copy2(src, PREVIEW / name)


def main() -> int:
    RESULTS.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    FIGURES.mkdir(parents=True, exist_ok=True)
    load_env_file(ENV_FILE)
    key = require_glm_key()
    df = pd.read_csv(IN_ROWS)
    sample = select_sample(df)
    out_rows: list[dict[str, Any]] = []
    completed: set[str] = set()
    if OUT_CHECKPOINT.exists():
        ckpt = pd.read_csv(OUT_CHECKPOINT)
        out_rows = ckpt.to_dict(orient="records")
        completed = set(str(x) for x in ckpt.get("task_id", []))
    for idx, row in sample.iterrows():
        if str(row.get("task_id", "")) in completed:
            continue
        patch_excerpt = extract_patch_excerpt(row.get("patch_cache_path"))
        prompt = build_prompt(row, patch_excerpt)
        item = call_glm(prompt, key)
        parsed = json_from_text(item.get("text", ""))
        eval_row = evaluate_candidate(row, parsed)
        usage = item.get("usage") or {}
        out_rows.append({
            "sample_index": idx,
            "task_id": row.get("task_id", ""),
            "sample_role": row.get("sample_role", ""),
            "gt_category": row.get("gt_category", ""),
            "gt_rule_id": row.get("gt_rule_id", ""),
            "gt_function": row.get("gt_function", ""),
            "objective_score": row.get("objective_score", ""),
            "parent_exposure_signal": to_bool(row.get("parent_exposure_signal")),
            "upstream_protection_signal": to_bool(row.get("upstream_protection_signal")),
            "directional_gain": to_bool(row.get("directional_gain")),
            "patch_sha256": row.get("patch_sha256", ""),
            "glm_ok": bool(item.get("ok")),
            "glm_attempt": item.get("attempt", ""),
            "glm_wall_seconds": item.get("wall_seconds", ""),
            "glm_error": item.get("error", ""),
            "prompt_tokens": int(usage.get("prompt_tokens") or 0),
            "completion_tokens": int(usage.get("completion_tokens") or 0),
            "total_tokens": int(usage.get("total_tokens") or 0),
            **eval_row,
        })
        pd.DataFrame(out_rows).to_csv(OUT_CHECKPOINT, index=False)
        time.sleep(0.2)
    rows = pd.DataFrame(out_rows)
    rows.to_csv(OUT_ROWS, index=False)
    summary = summarize(rows)
    OUT_SUMMARY.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    plot(rows, summary)
    write_report(summary, rows)
    write_reproduce()
    sync_preview()
    print(json.dumps({
        "rows": str(OUT_ROWS),
        "summary": str(OUT_SUMMARY),
        "report": str(OUT_REPORT),
        "windows_report": "D:\\lunwen\\MDDC_Preview\\latest\\experiment_lxxxvi_glm_oracle_calibration_20260625.txt",
        "metrics": summary["metrics"],
        "usage": summary["usage"],
    }, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

