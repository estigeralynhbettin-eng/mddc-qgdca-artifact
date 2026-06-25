# Experiment LXXVII Patch-Differential Oracle Cross-Check

Generated: 2026-06-24 14:56:33 +08:00

## Material Passport

- Mode: code experiment / reproducibility validation
- Data access: public ASR XML and public GitHub commit patches
- Pre-registration: `/root/mddc/empirical_validation/experiment_lxxvii_lxxviii_preregistration_20260624.md`
- Claim boundary: patch-diff surrogate; not full checked-out repository Semgrep execution

## Result

- Strict ASR admissions evaluated: `99`
- Patch available: `90/99` = `0.909091`
- Patch-differential validated: `55/99` = `0.555556`
- Wilson 95% CI: `0.457421`-`0.649539`
- Pre-registered success: `False`
- LXXX deployment mini-trial allowed by LXXVII: `False`

## Negative Controls

| Mode | Trials | Mean false rate | Max false rate |
|---|---:|---:|---:|
| any_deranged | 1000 | 0.217434 | 0.333333 |
| cross_category | 1000 | 0.151081 | 0.292929 |

## Interpretation Boundary

A positive result supports deterministic patch-differential evidence for ASR rule-capital admission. A negative result would not invalidate the structural gate, but would prevent using it as behavioral semantic validation.

## Outputs

- Rows: `/root/mddc/empirical_validation/results/experiment_lxxvii_patch_differential_oracle_rows_20260624.csv`
- Controls: `/root/mddc/empirical_validation/results/experiment_lxxvii_patch_differential_oracle_controls_20260624.csv`
- Summary: `/root/mddc/empirical_validation/results/experiment_lxxvii_patch_differential_oracle_summary_20260624.json`
- Figure PDF: `/root/mddc/empirical_validation/figures/fig_experiment_lxxvii_patch_differential_oracle.pdf`

Document generated: 2026-06-24 14:56:33 +08:00
