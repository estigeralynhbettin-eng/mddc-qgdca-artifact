#!/usr/bin/env python3
"""Experiment LXXXVII: DeepSeek candidate-oracle adversarial calibration.

This is the model-agnostic counterpart to LXXXVI. DeepSeek generates candidate
security predicates. QG-DCA admission is still decided by objective
patch-differential and provenance-consistency gates.
"""

from __future__ import annotations

import json
import os
import shutil
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import pandas as pd
import requests

import experiment_lxxxvi_glm_oracle_calibration as lxxxvi
import experiment_lxxxvii_scaled_glm_oracle_adversarial_calibration as lxxxvii


ROOT = Path(os.environ.get("MDDC_ROOT", "/root/mddc"))
RESULTS = ROOT / "empirical_validation" / "results"
FIGURES = ROOT / "empirical_validation" / "figures"
REPORTS = ROOT / "review_rounds"
PREVIEW = Path("/mnt/d/lunwen/MDDC_Preview/latest")

OUT_ROWS = RESULTS / "experiment_lxxxvii_deepseek_oracle_adversarial_rows_20260625.csv"
OUT_CHECKPOINT = RESULTS / "experiment_lxxxvii_deepseek_oracle_adversarial_checkpoint_20260625.csv"
OUT_SUMMARY = RESULTS / "experiment_lxxxvii_deepseek_oracle_adversarial_summary_20260625.json"
OUT_REPORT = REPORTS / "experiment_lxxxvii_deepseek_oracle_adversarial_20260625.md"
OUT_REPRO = REPORTS / "REPRODUCE_LXXXVII_DEEPSEEK_ORACLE_ADVERSARIAL_20260625.md"
OUT_FIG_PDF = FIGURES / "fig_experiment_lxxxvii_deepseek_oracle_adversarial.pdf"
OUT_FIG_PNG = FIGURES / "fig_experiment_lxxxvii_deepseek_oracle_adversarial.png"

DEEPSEEK_ENDPOINT = "https://api.deepseek.com/chat/completions"
DEEPSEEK_MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-v4-pro")
DEEPSEEK_TIMEOUT = int(os.environ.get("DEEPSEEK_TIMEOUT", "90"))
DEEPSEEK_MAX_TOKENS = int(os.environ.get("DEEPSEEK_MAX_TOKENS", "450"))
DEEPSEEK_TEMPERATURE = float(os.environ.get("DEEPSEEK_TEMPERATURE", "0"))
MAX_CASES = int(os.environ.get("LXXXVII_MAX_CASES", "0") or "0")
SLEEP_SECONDS = float(os.environ.get("DEEPSEEK_SLEEP_SECONDS", "0.1"))

DEEPSEEK_RATES_PER_MTOK = {
    "deepseek-v4-pro": {"cache_hit": 0.003625, "cache_miss": 0.435, "output": 0.87},
    "deepseek-v4-flash": {"cache_hit": 0.0028, "cache_miss": 0.14, "output": 0.28},
    "deepseek-chat": {"cache_hit": 0.0028, "cache_miss": 0.14, "output": 0.28},
}


def now_cst() -> str:
    return datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S +08:00")


def rate_key(model: str) -> str:
    if model in DEEPSEEK_RATES_PER_MTOK:
        return model
    if "flash" in model:
        return "deepseek-v4-flash"
    return "deepseek-v4-pro"


def estimate_deepseek_cost(usage: dict[str, Any]) -> dict[str, Any]:
    rates = DEEPSEEK_RATES_PER_MTOK[rate_key(DEEPSEEK_MODEL)]
    hit = int(usage.get("prompt_cache_hit_tokens", 0) or 0)
    miss = int(usage.get("prompt_cache_miss_tokens", usage.get("prompt_tokens", 0)) or 0)
    out = int(usage.get("completion_tokens", 0) or 0)
    cost = (hit / 1_000_000) * rates["cache_hit"] + (miss / 1_000_000) * rates["cache_miss"] + (out / 1_000_000) * rates["output"]
    return {
        "estimated_cost_usd": round(cost, 6),
        "pricing_profile": rate_key(DEEPSEEK_MODEL),
    }


def require_deepseek_key() -> str:
    key = os.environ.get("DEEPSEEK_API_KEY", "")
    if not key:
        raise RuntimeError("Missing DEEPSEEK_API_KEY")
    return key


def call_deepseek(prompt: str, key: str) -> dict[str, Any]:
    payload = {
        "model": DEEPSEEK_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": DEEPSEEK_TEMPERATURE,
        "max_tokens": DEEPSEEK_MAX_TOKENS,
        "stream": False,
    }
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    session = requests.Session()
    session.trust_env = False
    last_error = ""
    for attempt in range(1, 4):
        started = time.time()
        try:
            response = session.post(DEEPSEEK_ENDPOINT, headers=headers, json=payload, timeout=DEEPSEEK_TIMEOUT)
            elapsed = round(time.time() - started, 2)
        except requests.RequestException as exc:
            last_error = f"{type(exc).__name__}: {str(exc)[:800]}"
            if attempt < 3:
                time.sleep(3 * attempt)
                continue
            return {"ok": False, "text": "", "usage": {}, "cost": {"estimated_cost_usd": 0}, "attempt": attempt, "wall_seconds": elapsed if "elapsed" in locals() else 0, "error": last_error}
        if response.status_code in {429, 500, 502, 503, 504} and attempt < 3:
            last_error = f"HTTP {response.status_code}: {response.text[:500]}"
            time.sleep(3 * attempt)
            continue
        if not response.ok:
            return {"ok": False, "text": "", "usage": {}, "cost": {"estimated_cost_usd": 0}, "attempt": attempt, "wall_seconds": elapsed, "error": f"HTTP {response.status_code}: {response.text[:800]}"}
        data = response.json()
        text = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        usage = data.get("usage", {})
        return {"ok": True, "text": text, "usage": usage, "cost": estimate_deepseek_cost(usage), "attempt": attempt, "wall_seconds": elapsed, "error": ""}
    return {"ok": False, "text": "", "usage": {}, "cost": {"estimated_cost_usd": 0}, "attempt": 3, "wall_seconds": 0, "error": last_error}


def save_checkpoint(rows: list[dict[str, Any]]) -> None:
    if rows:
        pd.DataFrame(rows).to_csv(OUT_CHECKPOINT, index=False)


def run_cases() -> pd.DataFrame:
    lxxxvi.load_env_file(lxxxvi.ENV_FILE)
    key = require_deepseek_key()
    lxxxvi.MAX_PATCH_CHARS = int(os.environ.get("DEEPSEEK_PATCH_CHARS", "1000"))
    cases = lxxxvii.load_cases()
    if MAX_CASES > 0:
        cases = cases[:MAX_CASES]

    done: dict[str, dict[str, Any]] = {}
    if OUT_CHECKPOINT.exists():
        old = pd.read_csv(OUT_CHECKPOINT).fillna("")
        done = {str(row["case_id"]): row.to_dict() for _, row in old.iterrows()}
    rows: list[dict[str, Any]] = list(done.values())

    for idx, case in enumerate(cases, start=1):
        if case["case_id"] in done:
            continue
        patch_excerpt = lxxxvi.extract_patch_excerpt(case["patch_row"].get("patch_cache_path", ""))
        prompt = lxxxvi.build_prompt(case["meta_row"], patch_excerpt)
        item = call_deepseek(prompt, key)
        parsed = lxxxvi.json_from_text(item.get("text", ""))
        eval_row = lxxxvii.evaluate_candidate(parsed, case["meta_row"])
        provenance_consistent = case["patch_task_id"] == case["metadata_task_id"]
        objective_positive = (
            provenance_consistent
            and lxxxvii.row_bool(case["meta_row"], "oracle_validated")
            and lxxxvii.row_bool(case["meta_row"], "parent_exposure_signal")
            and lxxxvii.row_bool(case["meta_row"], "upstream_protection_signal")
            and lxxxvii.row_bool(case["meta_row"], "directional_gain")
        )
        qgdca_qualified = bool(eval_row["candidate_gate"] and objective_positive)
        expected = bool(case["expected_admissible"])
        out = {
            "case_id": case["case_id"],
            "case_kind": case["case_kind"],
            "patch_task_id": case["patch_task_id"],
            "metadata_task_id": case["metadata_task_id"],
            "gt_category": str(case["meta_row"].get("gt_category", "")),
            "expected_admissible": expected,
            "objective_reason": case["objective_reason"],
            "provenance_consistent": provenance_consistent,
            "metadata_oracle_validated": lxxxvii.row_bool(case["meta_row"], "oracle_validated"),
            "objective_positive_after_provenance": objective_positive,
            "deepseek_ok": bool(item.get("ok", False)),
            "deepseek_attempt": item.get("attempt"),
            "deepseek_wall_seconds": item.get("wall_seconds"),
            "deepseek_error": item.get("error", ""),
            "deepseek_prompt_tokens": (item.get("usage") or {}).get("prompt_tokens", 0),
            "deepseek_completion_tokens": (item.get("usage") or {}).get("completion_tokens", 0),
            "deepseek_total_tokens": (item.get("usage") or {}).get("total_tokens", 0),
            "deepseek_cost_usd": (item.get("cost") or {}).get("estimated_cost_usd", 0),
            **eval_row,
            "deepseek_only_false_candidate": bool(eval_row["candidate_gate"] and not expected),
            "qgdca_qualified": qgdca_qualified,
            "qgdca_false_admission": bool(qgdca_qualified and not expected),
            "qgdca_true_admission": bool(qgdca_qualified and expected),
        }
        rows.append(out)
        save_checkpoint(rows)
        print(f"[{idx}/{len(cases)}] {case['case_id']} candidate={out['candidate_gate']} qgdca={qgdca_qualified}")
        if SLEEP_SECONDS > 0:
            time.sleep(SLEEP_SECONDS)

    df = pd.DataFrame(rows)
    order = [case["case_id"] for case in cases]
    df["_order"] = df["case_id"].map({case_id: i for i, case_id in enumerate(order)})
    return df.sort_values("_order").drop(columns=["_order"]).reset_index(drop=True)


def rate(df: pd.DataFrame, mask: pd.Series, column: str) -> dict[str, Any]:
    sub = df[mask]
    n = int(len(sub))
    x = int(sub[column].astype(bool).sum()) if n else 0
    return {"x": x, "n": n, "rate": (x / n if n else 0.0), "wilson95": lxxxvii.wilson(x, n)}


def summarize(df: pd.DataFrame) -> dict[str, Any]:
    expected = df["expected_admissible"].astype(bool)
    negative = ~expected
    base = df["case_kind"].eq("base")
    adversarial = df["case_kind"].eq("adversarial_mismatched_positive_metadata")
    return {
        "experiment": "LXXXVII DeepSeek candidate-oracle adversarial calibration",
        "generated_at": now_cst(),
        "model": DEEPSEEK_MODEL,
        "sample": {
            "n_total": int(len(df)),
            "base_cases": int(base.sum()),
            "adversarial_cases": int(adversarial.sum()),
            "base_expected_positive": int((base & expected).sum()),
            "base_expected_negative": int((base & negative).sum()),
            "max_cases_env": MAX_CASES,
        },
        "metrics": {
            "json_parse": rate(df, df.index == df.index, "parsed_ok"),
            "non_vacuous": rate(df, df.index == df.index, "non_vacuous"),
            "base_deepseek_candidate_positive_recall": rate(df, base & expected, "candidate_gate"),
            "base_qgdca_positive_recall": rate(df, base & expected, "qgdca_qualified"),
            "base_deepseek_only_false_candidate_on_negatives": rate(df, base & negative, "deepseek_only_false_candidate"),
            "base_qgdca_false_admission_on_negatives": rate(df, base & negative, "qgdca_false_admission"),
            "adversarial_deepseek_only_false_candidate": rate(df, adversarial, "deepseek_only_false_candidate"),
            "adversarial_qgdca_false_admission": rate(df, adversarial, "qgdca_false_admission"),
            "all_negative_deepseek_only_false_candidate": rate(df, negative, "deepseek_only_false_candidate"),
            "all_negative_qgdca_false_admission": rate(df, negative, "qgdca_false_admission"),
        },
        "usage": {
            "api_calls": int(len(df)),
            "successful_calls": int(df["deepseek_ok"].astype(bool).sum()),
            "prompt_tokens": int(pd.to_numeric(df["deepseek_prompt_tokens"], errors="coerce").fillna(0).sum()),
            "completion_tokens": int(pd.to_numeric(df["deepseek_completion_tokens"], errors="coerce").fillna(0).sum()),
            "total_tokens": int(pd.to_numeric(df["deepseek_total_tokens"], errors="coerce").fillna(0).sum()),
            "estimated_cost_usd": round(float(pd.to_numeric(df["deepseek_cost_usd"], errors="coerce").fillna(0).sum()), 6),
        },
        "claim_boundary": "DeepSeek is only a candidate generator. Admission is decided by objective patch-differential and provenance-consistency surrogate gates. Adversarial rows are constructed mismatched metadata/patch prompts, not independent real vulnerabilities.",
        "outputs": {
            "rows_csv": str(OUT_ROWS),
            "summary_json": str(OUT_SUMMARY),
            "report_md": str(OUT_REPORT),
            "figure_pdf": str(OUT_FIG_PDF),
        },
    }


def make_figure(summary: dict[str, Any]) -> None:
    labels = ["Base positive\nrecall", "Base negative\nfalse admit", "Adversarial\nfalse admit", "All negative\nfalse admit"]
    m = summary["metrics"]
    model_rates = [
        m["base_deepseek_candidate_positive_recall"]["rate"],
        m["base_deepseek_only_false_candidate_on_negatives"]["rate"],
        m["adversarial_deepseek_only_false_candidate"]["rate"],
        m["all_negative_deepseek_only_false_candidate"]["rate"],
    ]
    qgdca_rates = [
        m["base_qgdca_positive_recall"]["rate"],
        m["base_qgdca_false_admission_on_negatives"]["rate"],
        m["adversarial_qgdca_false_admission"]["rate"],
        m["all_negative_qgdca_false_admission"]["rate"],
    ]
    x = range(len(labels))
    width = 0.36
    fig, ax = plt.subplots(figsize=(7.2, 3.0))
    ax.bar([i - width / 2 for i in x], model_rates, width, label="DeepSeek candidate gate", color="#9bb7d4")
    ax.bar([i + width / 2 for i in x], qgdca_rates, width, label="QG-DCA objective gate", color="#315f52")
    ax.set_ylabel("Rate")
    ax.set_ylim(0, 1.05)
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels)
    ax.legend(frameon=False, ncol=2, loc="upper right")
    ax.set_title("LXXXVII independent generator vs QG-DCA admission")
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    fig.savefig(OUT_FIG_PDF)
    fig.savefig(OUT_FIG_PNG, dpi=240)
    plt.close(fig)


def write_report(summary: dict[str, Any]) -> None:
    m = summary["metrics"]
    def fmt(key: str) -> str:
        item = m[key]
        return f"`{item['x']}/{item['n']}` = `{item['rate']:.3f}`, Wilson 95% CI `{item['wilson95'][0]:.3f}`--`{item['wilson95'][1]:.3f}`"

    lines = [
        "# Experiment LXXXVII DeepSeek Candidate-Oracle Adversarial Calibration",
        "",
        f"Generated: {summary['generated_at']}",
        "",
        "## Purpose",
        "",
        "This experiment tests whether QG-DCA's generator/admission separation holds for a second independent model. DeepSeek generates candidate security predicates; objective gates decide admission.",
        "",
        "## Sample",
        "",
        f"- Total cases: `{summary['sample']['n_total']}`.",
        f"- Base patch cases: `{summary['sample']['base_cases']}`.",
        f"- Adversarial mismatched metadata/patch cases: `{summary['sample']['adversarial_cases']}`.",
        f"- Base expected positives: `{summary['sample']['base_expected_positive']}`.",
        f"- Base expected negatives: `{summary['sample']['base_expected_negative']}`.",
        f"- Model: `{summary['model']}`.",
        "",
        "## Main Results",
        "",
        f"- Base DeepSeek candidate positive recall: {fmt('base_deepseek_candidate_positive_recall')}.",
        f"- Base QG-DCA positive recall: {fmt('base_qgdca_positive_recall')}.",
        f"- Base DeepSeek-only false candidates on negatives: {fmt('base_deepseek_only_false_candidate_on_negatives')}.",
        f"- Base QG-DCA false admissions on negatives: {fmt('base_qgdca_false_admission_on_negatives')}.",
        f"- Adversarial DeepSeek-only false candidates: {fmt('adversarial_deepseek_only_false_candidate')}.",
        f"- Adversarial QG-DCA false admissions: {fmt('adversarial_qgdca_false_admission')}.",
        f"- All-negative DeepSeek-only false candidates: {fmt('all_negative_deepseek_only_false_candidate')}.",
        f"- All-negative QG-DCA false admissions: {fmt('all_negative_qgdca_false_admission')}.",
        "",
        "## Interpretation",
        "",
        "The result is useful only if read as model-agnostic admission accounting. A high candidate rate shows generation ability; false candidates on negatives or adversarial rows show why candidate generation cannot define capital. QG-DCA admits only when objective evidence and provenance are consistent.",
        "",
        "## Boundary",
        "",
        summary["claim_boundary"],
        "",
        "## Usage Audit",
        "",
        f"- API calls: `{summary['usage']['api_calls']}`.",
        f"- Successful calls: `{summary['usage']['successful_calls']}`.",
        f"- Total tokens: `{summary['usage']['total_tokens']}`.",
        f"- Estimated cost USD: `{summary['usage']['estimated_cost_usd']}`.",
        "",
        f"Document generated: {now_cst()}",
    ]
    OUT_REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    OUT_REPRO.write_text(
        "\n".join([
            "# Reproduce LXXXVII DeepSeek Candidate-Oracle Adversarial Calibration",
            "",
            "Requires `DEEPSEEK_API_KEY` in the environment or in `/mnt/c/Users/PBCDCI/.llm_api_keys.env`.",
            "",
            "```bash",
            "cd /root/mddc",
            "python3 empirical_validation/experiment_lxxxvii_deepseek_oracle_adversarial_calibration.py",
            "```",
            "",
            "Set `LXXXVII_MAX_CASES` for a smoke test.",
            "",
            f"Document generated: {now_cst()}",
            "",
        ]),
        encoding="utf-8",
    )


def sync_preview() -> None:
    PREVIEW.mkdir(parents=True, exist_ok=True)
    for src in [OUT_ROWS, OUT_SUMMARY, OUT_REPORT, OUT_REPRO, OUT_FIG_PDF, OUT_FIG_PNG]:
        if not src.exists():
            continue
        shutil.copy2(src, PREVIEW / src.name)
        if src.suffix == ".md":
            shutil.copy2(src, PREVIEW / f"{src.stem}.txt")


def main() -> int:
    RESULTS.mkdir(parents=True, exist_ok=True)
    FIGURES.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    df = run_cases()
    df.to_csv(OUT_ROWS, index=False)
    summary = summarize(df)
    OUT_SUMMARY.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    make_figure(summary)
    write_report(summary)
    sync_preview()
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

