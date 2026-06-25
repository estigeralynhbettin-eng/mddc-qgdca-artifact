#!/usr/bin/env python3
"""LXXXIX: align frozen admission-list dynamic-oracle prerequisites with executable anchors."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(os.environ.get("MDDC_ROOT", "/root/mddc"))
RESULTS = ROOT / "empirical_validation" / "results"
FIGURES = ROOT / "empirical_validation" / "figures"
REPORTS = ROOT / "review_rounds"
PREVIEW = Path("/mnt/d/lunwen/MDDC_Preview/latest")


def str_bool(value: str | bool | None) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"true", "1", "yes", "y"}


def wilson(x: int, n: int, z: float = 1.959963984540054) -> list[float]:
    if n <= 0:
        return [0.0, 0.0]
    phat = x / n
    denom = 1 + z * z / n
    centre = phat + z * z / (2 * n)
    margin = z * math.sqrt((phat * (1 - phat) + z * z / (4 * n)) / n)
    return [max(0.0, (centre - margin) / denom), min(1.0, (centre + margin) / denom)]


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8", errors="replace") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fields})


def make_figure(summary: dict[str, Any], figure_pdf: Path, figure_png: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    groups = summary["by_dynamic_source"]
    labels = list(groups)
    anchored = [groups[k]["anchored"] for k in labels]
    debt = [groups[k]["total"] - groups[k]["anchored"] for k in labels]
    fig, ax = plt.subplots(figsize=(6.4, 3.2))
    x = range(len(labels))
    ax.bar(x, anchored, label="executable anchored", color="#2b6cb0")
    ax.bar(x, debt, bottom=anchored, label="validation debt", color="#cbd5e0")
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, rotation=15, ha="right")
    ax.set_ylabel("Frozen admission-list tasks")
    ax.set_title("LXXXIX: admission-list oracle-prerequisite alignment")
    ax.legend(frameon=False, loc="upper right")
    for idx, (a, d) in enumerate(zip(anchored, debt)):
        ax.text(idx, a + d + 0.2, f"{a}/{a+d}", ha="center", va="bottom", fontsize=8)
    fig.tight_layout()
    figure_pdf.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(figure_pdf)
    fig.savefig(figure_png, dpi=220)
    plt.close(fig)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--outdir", type=Path, default=RESULTS)
    parser.add_argument("--figure-dir", type=Path, default=FIGURES)
    parser.add_argument("--report", type=Path, default=REPORTS / "experiment_lxxxix_admission_oracle_alignment_20260625.md")
    args = parser.parse_args()

    root = args.root
    results = root / "empirical_validation" / "results"
    flat_results = root / "results"
    admission_path = results / "experiment_lx_n30_allgate_admission.csv"
    anchor_path = results / "experiment_lxxxviii_executable_oracle_anchor_tasks_20260625.csv"
    if not admission_path.exists():
        admission_path = flat_results / "experiment_lx_n30_allgate_admission.csv"
    if not anchor_path.exists():
        anchor_path = flat_results / "experiment_lxxxviii_executable_oracle_anchor_tasks_20260625.csv"

    admissions = read_csv(admission_path)
    anchors = {r["task_id"]: r for r in read_csv(anchor_path)}

    rows: list[dict[str, Any]] = []
    source_counts: dict[str, Counter[str]] = defaultdict(Counter)
    anchored_parent_upstream = 0
    anchored_total = 0

    for item in admissions:
        task_id = item["task_id"]
        source = item.get("dynamic_oracle_source", "")
        anchor = anchors.get(task_id)
        has_anchor = anchor is not None and str_bool(anchor.get("qgdca_executable_oracle_anchor"))
        parent_upstream = bool(anchor) and str_bool(anchor.get("parent_fails_upstream_passes"))
        status = "executable_calibrated" if has_anchor and parent_upstream else "validation_debt_unanchored"
        policy = "behavior_anchored_prerequisite_admit" if status == "executable_calibrated" else "abstain_or_escalate"
        source_counts[source]["total"] += 1
        if has_anchor:
            source_counts[source]["anchored"] += 1
            anchored_total += 1
        if parent_upstream:
            source_counts[source]["parent_fails_upstream_passes"] += 1
            anchored_parent_upstream += 1
        rows.append({
            "task_id": task_id,
            "cve_id": item.get("cve_id", ""),
            "cwe_id": item.get("cwe_id", ""),
            "language": item.get("language", ""),
            "dynamic_oracle_source": source,
            "primary_security_endpoint": item.get("primary_security_endpoint", ""),
            "secondary_deployment_endpoint": item.get("secondary_deployment_endpoint", ""),
            "executable_anchor_present": has_anchor,
            "parent_fails_upstream_passes": parent_upstream,
            "admission_prerequisite_status": status,
            "qgdca_behavioral_policy": policy,
        })

    total = len(rows)
    by_source: dict[str, dict[str, Any]] = {}
    for source, cnt in sorted(source_counts.items()):
        n = cnt["total"]
        a = cnt["anchored"]
        pfu = cnt["parent_fails_upstream_passes"]
        by_source[source] = {
            "total": n,
            "anchored": a,
            "anchored_rate": a / n if n else 0,
            "anchored_wilson95": wilson(a, n),
            "parent_fails_upstream_passes": pfu,
            "parent_fails_upstream_passes_rate": pfu / a if a else 0,
            "parent_fails_upstream_passes_wilson95": wilson(pfu, a) if a else [0.0, 0.0],
        }

    experiment_lv = by_source.get("experiment_lv_validated", {"total": 0, "anchored": 0})
    summary = {
        "experiment": "LXXXIX_admission_oracle_alignment",
        "date": "2026-06-25",
        "input_files": {
            str(admission_path): file_sha256(admission_path),
            str(anchor_path): file_sha256(anchor_path),
        },
        "frozen_admission_tasks": total,
        "executable_anchored_tasks": anchored_total,
        "executable_anchor_rate": anchored_total / total if total else 0,
        "executable_anchor_wilson95": wilson(anchored_total, total),
        "unanchored_validation_debt_tasks": total - anchored_total,
        "parent_fails_upstream_passes_among_anchored": anchored_parent_upstream,
        "parent_fails_upstream_passes_among_anchored_rate": anchored_parent_upstream / anchored_total if anchored_total else 0,
        "parent_fails_upstream_passes_among_anchored_wilson95": wilson(anchored_parent_upstream, anchored_total),
        "experiment_lv_validated_subset": {
            "total": experiment_lv.get("total", 0),
            "anchored": experiment_lv.get("anchored", 0),
            "anchored_rate": experiment_lv.get("anchored_rate", 0),
            "anchored_wilson95": experiment_lv.get("anchored_wilson95", [0.0, 0.0]),
        },
        "by_dynamic_source": by_source,
        "claim_boundary": [
            "Calibrates dynamic-oracle prerequisites for a frozen admission list.",
            "Does not prove AI repair success or deployment success.",
            "Does not validate ASR/CVEfixes/BigVul patch-differential headline rates.",
            "Unanchored tasks are counted as validation debt under strict behavioral accounting.",
        ],
    }

    outdir = args.outdir
    outdir.mkdir(parents=True, exist_ok=True)
    rows_path = outdir / "experiment_lxxxix_admission_oracle_alignment_rows_20260625.csv"
    summary_path = outdir / "experiment_lxxxix_admission_oracle_alignment_summary_20260625.json"
    fields = [
        "task_id",
        "cve_id",
        "cwe_id",
        "language",
        "dynamic_oracle_source",
        "primary_security_endpoint",
        "secondary_deployment_endpoint",
        "executable_anchor_present",
        "parent_fails_upstream_passes",
        "admission_prerequisite_status",
        "qgdca_behavioral_policy",
    ]
    write_csv(rows_path, rows, fields)
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    figure_pdf = args.figure_dir / "fig_experiment_lxxxix_admission_oracle_alignment.pdf"
    figure_png = args.figure_dir / "fig_experiment_lxxxix_admission_oracle_alignment.png"
    make_figure(summary, figure_pdf, figure_png)

    report = [
        "# Experiment LXXXIX: Admission-Oracle Alignment",
        "",
        "## Purpose",
        "",
        "This audit answers a narrower construct-validity question raised by the LXXXVIII review: whether the executable oracle anchor is only adjacent to MDDC/QG-DCA, or whether it calibrates any frozen admission-list prerequisite.",
        "",
        "## Result",
        "",
        f"- Frozen all-gate admission-list tasks: `{total}`.",
        f"- Tasks with executable parent-fails/upstream-passes anchor: `{anchored_total}/{total}`; Wilson 95% CI `{summary['executable_anchor_wilson95'][0]:.3f}--{summary['executable_anchor_wilson95'][1]:.3f}`.",
        f"- Among anchored tasks, parent-fails/upstream-passes holds for `{anchored_parent_upstream}/{anchored_total}`; Wilson 95% CI `{summary['parent_fails_upstream_passes_among_anchored_wilson95'][0]:.3f}--{summary['parent_fails_upstream_passes_among_anchored_wilson95'][1]:.3f}`.",
        f"- The `experiment_lv_validated` admission-prerequisite subset is covered by executable anchors for `{experiment_lv.get('anchored', 0)}/{experiment_lv.get('total', 0)}` tasks; Wilson 95% CI `{experiment_lv.get('anchored_wilson95', [0.0, 0.0])[0]:.3f}--{experiment_lv.get('anchored_wilson95', [0.0, 0.0])[1]:.3f}`.",
        f"- Remaining unanchored tasks are counted as validation debt: `{total - anchored_total}`.",
        "",
        "## Interpretation",
        "",
        "LXXXIX partially closes the LXXXVIII gap. The executable oracle is no longer merely adjacent to the admission layer: it calibrates the dynamic-oracle prerequisite for the `experiment_lv_validated` subset of the frozen admission list. Under strict behavioral accounting, tasks without an executable anchor are not promoted to behavioral capital; they remain validation debt or require escalation.",
        "",
        "## Boundary",
        "",
        "- This is prerequisite calibration, not end-to-end repair success.",
        "- It does not validate ASRDataset, CVEfixes, or BigVul patch-differential headline rates.",
        "- It does not change the frozen repair deployment result: 1/30 primary security-qualified and 0/30 original deployment-qualified.",
        "- It makes QG-DCA more defensible as an accounting protocol because it identifies exactly which admission-list prerequisites are behaviorally anchored and which must be abstained/escalated.",
        "",
        "## Outputs",
        "",
        f"- Rows: `{rows_path}`",
        f"- Summary: `{summary_path}`",
        f"- Figure PDF: `{figure_pdf}`",
        f"- Figure PNG: `{figure_png}`",
        "",
        "Document generated: 2026-06-25 13:35 +08:00",
    ]
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text("\n".join(report) + "\n", encoding="utf-8")
    PREVIEW.mkdir(parents=True, exist_ok=True)
    (PREVIEW / "experiment_lxxxix_admission_oracle_alignment_20260625.txt").write_text("\n".join(report) + "\n", encoding="utf-8")

    print(json.dumps({
        "rows": str(rows_path),
        "summary": str(summary_path),
        "report": str(args.report),
        "figure_pdf": str(figure_pdf),
        "figure_png": str(figure_png),
        "windows_report": "D:\\lunwen\\MDDC_Preview\\latest\\experiment_lxxxix_admission_oracle_alignment_20260625.txt",
        "metrics": {
            "executable_anchored_tasks": f"{anchored_total}/{total}",
            "experiment_lv_validated_subset": f"{experiment_lv.get('anchored', 0)}/{experiment_lv.get('total', 0)}",
            "parent_fails_upstream_passes_among_anchored": f"{anchored_parent_upstream}/{anchored_total}",
        },
    }, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
