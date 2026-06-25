#!/usr/bin/env python3
"""Shared case/evaluation helpers for Experiment LXXXVII.

This module intentionally contains no model calls. It only builds the base and
metadata/patch-mismatch cases and evaluates whether a generated predicate passes
the candidate gate used by the DeepSeek LXXXVII replay.
"""

from __future__ import annotations

import math
import os
import random
from pathlib import Path
from typing import Any

import pandas as pd

import experiment_lxxxvi_glm_oracle_calibration as lxxxvi


ROOT = Path(os.environ.get("MDDC_ROOT", "/root/mddc"))
RESULTS = ROOT / "empirical_validation" / "results"
ARTIFACT_ROOT = Path(__file__).resolve().parents[1]
PACKAGED_IN_ROWS = ARTIFACT_ROOT / "results" / "experiment_lxxvii_patch_differential_oracle_rows_20260624.csv"
IN_ROWS = Path(os.environ.get(
    "LXXXVII_INPUT_ROWS",
    str(PACKAGED_IN_ROWS if PACKAGED_IN_ROWS.exists() else RESULTS / "experiment_lxxvii_patch_differential_oracle_rows_20260624.csv"),
))
RANDOM_SEED = 20260625
MAX_CASES = int(os.environ.get("LXXXVII_MAX_CASES", "0") or "0")


def to_bool(value: Any) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes"}


def wilson(x: int, n: int) -> list[float]:
    if n <= 0:
        return [0.0, 0.0]
    z = 1.959963984540054
    p = x / n
    den = 1 + z * z / n
    center = (p + z * z / (2 * n)) / den
    half = z * math.sqrt((p * (1 - p) + z * z / (4 * n)) / n) / den
    return [max(0.0, center - half), min(1.0, center + half)]


def row_bool(row: pd.Series, column: str) -> bool:
    return to_bool(row.get(column, False))


def choose_positive_metadata(row: pd.Series, positives: pd.DataFrame) -> pd.Series:
    same_category = positives[
        (positives["gt_category"].astype(str) == str(row.get("gt_category", "")))
        & (positives["task_id"].astype(str) != str(row.get("task_id", "")))
    ].sort_values(["objective_score_num", "task_id"], ascending=[False, True])
    if not same_category.empty:
        return same_category.iloc[0]
    other = positives[positives["task_id"].astype(str) != str(row.get("task_id", ""))]
    if other.empty:
        return positives.iloc[0]
    return other.sort_values(["objective_score_num", "task_id"], ascending=[False, True]).iloc[0]


def load_cases() -> list[dict[str, Any]]:
    df = pd.read_csv(IN_ROWS)
    df = df[df["patch_available"].map(to_bool) & df["patch_status"].eq("downloaded")].copy()
    df["objective_score_num"] = pd.to_numeric(df["objective_score"], errors="coerce").fillna(0.0)
    df["oracle_validated_bool"] = df["oracle_validated"].map(to_bool)
    df = df.sort_values(["gt_category", "task_id"]).reset_index(drop=True)
    positives = df[df["oracle_validated_bool"]].copy()

    cases: list[dict[str, Any]] = []
    for _, row in df.iterrows():
        cases.append({
            "case_id": f"base::{row['task_id']}",
            "case_kind": "base",
            "patch_task_id": str(row["task_id"]),
            "metadata_task_id": str(row["task_id"]),
            "patch_row": row,
            "meta_row": row,
            "expected_admissible": bool(row["oracle_validated_bool"]),
            "objective_reason": "base_true_patch_diff" if row["oracle_validated_bool"] else "base_failed_patch_diff",
        })
        meta = choose_positive_metadata(row, positives)
        cases.append({
            "case_id": f"adversarial::{row['task_id']}::meta::{meta['task_id']}",
            "case_kind": "adversarial_mismatched_positive_metadata",
            "patch_task_id": str(row["task_id"]),
            "metadata_task_id": str(meta["task_id"]),
            "patch_row": row,
            "meta_row": meta,
            "expected_admissible": False,
            "objective_reason": "mismatched_patch_metadata_provenance",
        })

    rng = random.Random(RANDOM_SEED)
    rng.shuffle(cases)
    if MAX_CASES > 0:
        cases = cases[:MAX_CASES]
    return cases


def evaluate_candidate(parsed: dict[str, Any], meta_row: pd.Series) -> dict[str, Any]:
    target_terms = (
        lxxxvi.split_terms(meta_row.get("api_terms", ""))
        | lxxxvi.split_terms(meta_row.get("gt_function", ""))
        | lxxxvi.split_terms(meta_row.get("gt_rule_id", ""))
    ) - lxxxvi.GENERIC_TERMS
    protection_terms = (
        lxxxvi.split_terms(meta_row.get("protection_terms", ""))
        | lxxxvi.split_terms(meta_row.get("vuln_terms", ""))
        | lxxxvi.split_terms(meta_row.get("gt_category", ""))
    ) - lxxxvi.GENERIC_TERMS
    candidate_terms = (
        set(lxxxvi.normalize_list(parsed.get("target_api_terms", [])))
        | set(lxxxvi.normalize_list(parsed.get("vulnerable_condition_terms", [])))
        | set(lxxxvi.normalize_list(parsed.get("fixed_condition_terms", [])))
        | lxxxvi.split_terms(parsed.get("security_predicate", ""))
    ) - lxxxvi.GENERIC_TERMS
    predicate_terms = lxxxvi.split_terms(parsed.get("security_predicate", "")) - lxxxvi.GENERIC_TERMS
    target_overlap = sorted(target_terms & candidate_terms)
    protection_overlap = sorted(protection_terms & candidate_terms)
    parsed_ok = bool(parsed)
    non_vacuous = len(predicate_terms) >= 5 and str(parsed.get("vacuity_risk", "")).lower() != "high"
    uses_patch = bool(parsed.get("uses_patch_specific_evidence", False))
    candidate_gate = bool(parsed_ok and non_vacuous and target_overlap and protection_overlap and uses_patch)
    return {
        "parsed_ok": parsed_ok,
        "non_vacuous": non_vacuous,
        "uses_patch_specific_evidence": uses_patch,
        "target_overlap": ";".join(target_overlap[:8]),
        "protection_overlap": ";".join(protection_overlap[:8]),
        "candidate_gate": candidate_gate,
        "security_predicate": str(parsed.get("security_predicate", ""))[:500],
        "oracle_kind": str(parsed.get("oracle_kind", ""))[:80],
        "vacuity_risk": str(parsed.get("vacuity_risk", ""))[:40],
    }
