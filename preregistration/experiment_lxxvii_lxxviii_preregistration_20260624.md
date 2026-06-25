# Experiments LXXVII-LXXVIII Pre-Registration

Generated: 2026-06-24 14:50:00 +08:00

## Purpose

This pre-registration freezes the next two MDDC experiments before execution.
The goal is to replace acceptance-critical human semantic calibration with
objective, reproducible evidence while preserving strict claim boundaries.

## LXXVII: Patch-Differential Oracle Cross-Check

### Research Question

Do the `99/131` strict ASR objective-gate admissions have reproducible
parent/upstream behavioral support, or are they only benchmark-agreement
admissions?

### Data

- ASR rule rows:
  - `empirical_validation/results/experiment_lxiii_objective_semantic_qualification_expanded_rows_20260623.csv`
  - `empirical_validation/results/experiment_lxii_asr_full_rule_capital_audit_rows.csv`
- GitHub patch URLs derived from each ASR `PatchCommit`.
- Cached patches are stored under:
  - `artifacts/patch_cache/lxxvii_asr_patch_differential/`

### Gate Definition

Because ASRDataset provides XML rules and patch commit URLs, but not full
before/after repository snapshots, LXXVII uses a deterministic patch-diff
surrogate:

- Deleted/context lines approximate vulnerable-parent evidence.
- Added lines approximate upstream-fixed evidence.
- A rule is patch-differential validated only if:
  1. its patch is available;
  2. the parent side contains API or vulnerability-context evidence;
  3. the upstream side adds security/protection evidence; and
  4. the added protection evidence is stronger than removed protection evidence.

This is not claimed to be full Semgrep execution over checked-out repositories.
It is a reproducible behavioral proxy over public commit patches.

### Negative Controls

Two negative controls are frozen:

- `cross_category`: match each admitted rule to a patch from a different ASR
  vulnerability category.
- `any_deranged`: derange admitted rules against other patches without preserving
  category.

Both controls use a fixed random seed `20260624` and `1000` trials.

### Success Criteria

LXXVII is considered strong positive evidence only if:

- true strict admissions patch-differential validation rate `>= 0.60`;
- Wilson lower bound `>= 0.50`;
- cross-category false validation mean rate `<= 0.05`.

If true validation is `< 0.35` and negative false validation is `> 0.10`, the
behavioral validity route is considered failed and `LXXX` must not run.

## LXXVIII: External Baseline/System Comparison

### Research Question

Does MDDC strict qualification reduce false admission and validation debt against
external or naive operational baselines?

### Data

- ASR objective gate rows and LXXVII oracle rows.
- CVEfixes raw parquet and LXXIV gate logic.
- Existing gate-utility rows if available:
  - `empirical_validation/results/experiment_xlviii_gate_utility_rows.csv`

### Baselines

The following baselines are frozen:

- ASR:
  - score-only high threshold;
  - balanced gate;
  - lenient gate;
  - MDDC strict gate.
- CVEfixes:
  - `CVSS >= 7.0`;
  - structural-only;
  - category gate;
  - MDDC strict gate;
  - CVSS plus MDDC strict gate.
- Utility pool if available:
  - Qwen confidence-only;
  - DeepSeek score-only;
  - Claude score-only;
  - structural core;
  - MDDC utility gate.

### Primary Metrics

- true-pair admission rate;
- negative-control false admission rate;
- false-admission reduction versus baseline;
- validation debt proxy: false admissions per 100 candidates;
- Wilson confidence intervals where denominators are fixed row counts.

### Success Criteria

LXXVIII is considered positive comparison evidence if:

- MDDC strict reduces false admissions by at least `50%` versus CVSS-only and
  structural/score-only baselines on at least two independent pools; and
- no MDDC comparison table uses hidden post-hoc threshold tuning.

If MDDC strict does not outperform one baseline, that result must be reported as
a boundary condition rather than removed.

## Claim Boundary

These experiments support objective qualification and false-capital accounting.
They do not establish human semantic truth, deployment-rate superiority, or
general LLM patch-repair superiority.

