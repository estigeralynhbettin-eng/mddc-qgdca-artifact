#!/usr/bin/env python3
"""Experiment LXXXVIII: executable-oracle anchor audit.

This is a reanalysis of existing dynamic-oracle validation outputs. It adds an
executable semantic anchor to the QG-DCA paper without claiming deployment
repair success: an oracle is counted only when the parent version is unsafe and
the upstream fixed version is safe.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import shutil
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import pandas as pd


ROOT = Path(os.environ.get("MDDC_ROOT", "/root/mddc"))
RESULTS = ROOT / "empirical_validation" / "results"
FIGURES = ROOT / "empirical_validation" / "figures"
REPORTS = ROOT / "review_rounds"
PREVIEW = Path("/mnt/d/lunwen/MDDC_Preview/latest")

IN_VALIDATION = RESULTS / "experiment_lv_dynamic_oracle_backlog_validation.csv"
IN_SUMMARY = RESULTS / "experiment_lv_dynamic_oracle_backlog_summary.json"

OUT_TASKS = RESULTS / "experiment_lxxxviii_executable_oracle_anchor_tasks_20260625.csv"
OUT_SUMMARY = RESULTS / "experiment_lxxxviii_executable_oracle_anchor_summary_20260625.json"
OUT_REPORT = REPORTS / "experiment_lxxxviii_executable_oracle_anchor_audit_20260625.md"
OUT_REPRO = REPORTS / "REPRODUCE_LXXXVIII_EXECUTABLE_ORACLE_ANCHOR_AUDIT_20260625.md"
OUT_FIG_PDF = FIGURES / "fig_experiment_lxxxviii_executable_oracle_anchor.pdf"
OUT_FIG_PNG = FIGURES / "fig_experiment_lxxxviii_executable_oracle_anchor.png"


def now_cst() -> str:
    return datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S +08:00")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def wilson(x: int, n: int) -> list[float]:
    if n <= 0:
        return [0.0, 0.0]
    z = 1.959963984540054
    p = x / n
    den = 1 + z * z / n
    center = (p + z * z / (2 * n)) / den
    half = z * math.sqrt((p * (1 - p) + z * z / (4 * n)) / n) / den
    return [max(0.0, center - half), min(1.0, center + half)]


def load_task_rows() -> pd.DataFrame:
    df = pd.read_csv(IN_VALIDATION)
    required = {"task_id", "label", "dynamic_oracle_executed", "dynamic_security_oracle_safe", "valid_parent_false_upstream_true"}
    missing = sorted(required - set(df.columns))
    if missing:
        raise ValueError(f"missing columns: {missing}")

    rows: list[dict[str, Any]] = []
    for task_id, group in df.groupby("task_id", sort=True):
        parent = group[group["label"].eq("parent")]
        upstream = group[group["label"].eq("upstream")]
        parent_executed = bool(parent["dynamic_oracle_executed"].astype(bool).all()) if not parent.empty else False
        upstream_executed = bool(upstream["dynamic_oracle_executed"].astype(bool).all()) if not upstream.empty else False
        parent_safe = bool(parent["dynamic_security_oracle_safe"].astype(bool).iloc[0]) if not parent.empty else False
        upstream_safe = bool(upstream["dynamic_security_oracle_safe"].astype(bool).iloc[0]) if not upstream.empty else False
        valid_pair = bool(parent_executed and upstream_executed and (not parent_safe) and upstream_safe)
        rows.append({
            "task_id": task_id,
            "parent_executed": parent_executed,
            "upstream_executed": upstream_executed,
            "parent_safe": parent_safe,
            "upstream_safe": upstream_safe,
            "parent_fails_upstream_passes": valid_pair,
            "qgdca_executable_oracle_anchor": valid_pair,
            "parent_seconds": float(pd.to_numeric(parent["oracle_seconds"], errors="coerce").fillna(0).sum()) if not parent.empty else 0.0,
            "upstream_seconds": float(pd.to_numeric(upstream["oracle_seconds"], errors="coerce").fillna(0).sum()) if not upstream.empty else 0.0,
        })
    return pd.DataFrame(rows)


def summarize(tasks: pd.DataFrame) -> dict[str, Any]:
    n = int(len(tasks))
    valid = int(tasks["parent_fails_upstream_passes"].astype(bool).sum())
    parent_fail = int((~tasks["parent_safe"].astype(bool)).sum())
    upstream_pass = int(tasks["upstream_safe"].astype(bool).sum())
    both_executed = int((tasks["parent_executed"].astype(bool) & tasks["upstream_executed"].astype(bool)).sum())
    return {
        "experiment": "LXXXVIII executable-oracle anchor audit",
        "generated_at": now_cst(),
        "source": {
            "validation_csv": str(IN_VALIDATION),
            "validation_sha256": sha256(IN_VALIDATION),
            "summary_json": str(IN_SUMMARY),
            "summary_sha256": sha256(IN_SUMMARY),
        },
        "sample": {
            "task_pairs": n,
            "rows": int(n * 2),
            "definition": "A task is an executable oracle anchor only if the parent run is unsafe and the upstream fixed run is safe.",
        },
        "metrics": {
            "both_runs_executed": {"x": both_executed, "n": n, "rate": both_executed / n if n else 0.0, "wilson95": wilson(both_executed, n)},
            "parent_unsafe": {"x": parent_fail, "n": n, "rate": parent_fail / n if n else 0.0, "wilson95": wilson(parent_fail, n)},
            "upstream_safe": {"x": upstream_pass, "n": n, "rate": upstream_pass / n if n else 0.0, "wilson95": wilson(upstream_pass, n)},
            "parent_fails_upstream_passes": {"x": valid, "n": n, "rate": valid / n if n else 0.0, "wilson95": wilson(valid, n)},
        },
        "claim_boundary": "This is executable oracle validation for parent/upstream contrast, not AI repair success, production deployment, or human semantic labeling.",
        "outputs": {
            "tasks_csv": str(OUT_TASKS),
            "summary_json": str(OUT_SUMMARY),
            "report_md": str(OUT_REPORT),
            "figure_pdf": str(OUT_FIG_PDF),
            "figure_png": str(OUT_FIG_PNG),
        },
    }


def make_figure(summary: dict[str, Any]) -> None:
    FIGURES.mkdir(parents=True, exist_ok=True)
    metrics = summary["metrics"]
    labels = ["Both runs\nexecuted", "Parent\nunsafe", "Upstream\nsafe", "Executable\nanchor"]
    keys = ["both_runs_executed", "parent_unsafe", "upstream_safe", "parent_fails_upstream_passes"]
    values = [metrics[k]["rate"] for k in keys]
    lows = [metrics[k]["rate"] - metrics[k]["wilson95"][0] for k in keys]
    highs = [metrics[k]["wilson95"][1] - metrics[k]["rate"] for k in keys]
    fig, ax = plt.subplots(figsize=(6.2, 3.1))
    ax.bar(labels, values, yerr=[lows, highs], capsize=4, color=["#86b6f6", "#f28e8e", "#8fd19e", "#5aa469"])
    ax.set_ylim(0, 1.08)
    ax.set_ylabel("Rate with Wilson 95% CI")
    ax.set_title("Executable oracle anchor: parent fails and upstream passes")
    for i, key in enumerate(keys):
        m = metrics[key]
        ax.text(i, min(1.04, values[i] + 0.035), f"{m['x']}/{m['n']}", ha="center", va="bottom", fontsize=8)
    fig.tight_layout()
    fig.savefig(OUT_FIG_PDF)
    fig.savefig(OUT_FIG_PNG, dpi=240)
    plt.close(fig)


def write_report(summary: dict[str, Any]) -> None:
    REPORTS.mkdir(parents=True, exist_ok=True)
    PREVIEW.mkdir(parents=True, exist_ok=True)
    m = summary["metrics"]
    lines = [
        "# Experiment LXXXVIII Executable-Oracle Anchor Audit",
        "",
        f"Generated: {summary['generated_at']}",
        "",
        "## Purpose",
        "",
        "This audit adds an executable semantic anchor to the QG-DCA evidence chain. It reuses existing dynamic-oracle validation outputs and counts an oracle only when the parent version is unsafe and the upstream fixed version is safe.",
        "",
        "## Result",
        "",
        f"- Task pairs: `{summary['sample']['task_pairs']}`; validation rows: `{summary['sample']['rows']}`.",
        f"- Both parent and upstream runs executed: `{m['both_runs_executed']['x']}/{m['both_runs_executed']['n']}` = `{m['both_runs_executed']['rate']:.3f}`, Wilson 95% CI `{m['both_runs_executed']['wilson95'][0]:.3f}`--`{m['both_runs_executed']['wilson95'][1]:.3f}`.",
        f"- Parent unsafe: `{m['parent_unsafe']['x']}/{m['parent_unsafe']['n']}` = `{m['parent_unsafe']['rate']:.3f}`, CI `{m['parent_unsafe']['wilson95'][0]:.3f}`--`{m['parent_unsafe']['wilson95'][1]:.3f}`.",
        f"- Upstream safe: `{m['upstream_safe']['x']}/{m['upstream_safe']['n']}` = `{m['upstream_safe']['rate']:.3f}`, CI `{m['upstream_safe']['wilson95'][0]:.3f}`--`{m['upstream_safe']['wilson95'][1]:.3f}`.",
        f"- Executable anchor, parent-fails/upstream-passes: `{m['parent_fails_upstream_passes']['x']}/{m['parent_fails_upstream_passes']['n']}` = `{m['parent_fails_upstream_passes']['rate']:.3f}`, CI `{m['parent_fails_upstream_passes']['wilson95'][0]:.3f}`--`{m['parent_fails_upstream_passes']['wilson95'][1]:.3f}`.",
        "",
        "## Boundary",
        "",
        summary["claim_boundary"],
        "",
        "The audit strengthens construct validity for the validation gate, but it does not convert the repair experiments into deployment-rate evidence.",
        "",
        "## Source Integrity",
        "",
        f"- Validation CSV SHA256: `{summary['source']['validation_sha256']}`.",
        f"- Summary JSON SHA256: `{summary['source']['summary_sha256']}`.",
        "",
        "Document generated: 2026-06-25 13:05 +08:00",
    ]
    OUT_REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    OUT_REPRO.write_text(
        "\n".join([
            "# Reproduce LXXXVIII",
            "",
            "```bash",
            "cd /root/mddc",
            "python3 empirical_validation/experiment_lxxxviii_executable_oracle_anchor_audit.py",
            "```",
            "",
            "No paid model API is used. The script reanalyzes existing dynamic-oracle validation outputs.",
            "",
            "Document generated: 2026-06-25 13:05 +08:00",
        ])
        + "\n",
        encoding="utf-8",
    )
    for src in [OUT_REPORT, OUT_REPRO, OUT_SUMMARY, OUT_TASKS, OUT_FIG_PDF, OUT_FIG_PNG]:
        if src.exists():
            suffix = ".txt" if src.suffix == ".md" else src.suffix
            shutil.copy2(src, PREVIEW / f"{src.stem}{suffix}")


def main() -> int:
    tasks = load_task_rows()
    RESULTS.mkdir(parents=True, exist_ok=True)
    tasks.to_csv(OUT_TASKS, index=False)
    summary = summarize(tasks)
    OUT_SUMMARY.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    make_figure(summary)
    write_report(summary)
    print(json.dumps({
        "summary": str(OUT_SUMMARY),
        "tasks": str(OUT_TASKS),
        "report": str(OUT_REPORT),
        "figure": str(OUT_FIG_PNG),
        "metrics": summary["metrics"],
        "windows_report": "D:\\lunwen\\MDDC_Preview\\latest\\experiment_lxxxviii_executable_oracle_anchor_audit_20260625.txt",
    }, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
