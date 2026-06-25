# Experiment LXXIV: CVEfixes Independent Gate Replication

Generated: 2026-06-24 11:49:28 +08:00

## Purpose

This experiment applies the MDDC qualification-gate pattern to CVEfixes, a second public dataset independent of ASRDataset. CVEfixes has CVE/CWE descriptions, commits, and patch diffs, but not ASR rule XML. The result is therefore patch-context benchmark agreement, not rule-semantic correctness.

## Main Result

- Evaluated CVEfixes true pairs: `12668`.
- Structural-only baseline admits `10302/12668` = `0.813` true pairs.
- Strict MDDC gate admits `6240/12668` = `0.493`, Wilson 95% CI `[0.484, 0.501]`.
- On same-category different-CVE controls, structural-only admits `0.822` while strict MDDC admits `0.138`.
- False-admission reduction versus structural-only baseline on same-category controls: `83.2%`.

## Control Summary

| Control | Structural mean rate | Category mean rate | Strict mean rate | Strict max admits |
|---|---:|---:|---:|---:|
| any_deranged | 0.813 | 0.364 | 0.066 | 129 |
| cross_category | 0.798 | 0.337 | 0.061 | 115 |
| same_category_different_cve | 0.822 | 0.652 | 0.138 | 247 |

## Interpretation

The independent CVEfixes replication supports the gate-accounting claim against a simpler baseline: structural presence alone admits nearly every deranged control, while the strict gate substantially reduces false admissions. This does not prove deployment success. It shows that the MDDC admission idea is not limited to ASRDataset XML.

## Boundary

The strict CVEfixes gate is a benchmark-agreement gate over public CVE/CWE and patch-context fields. It should not be described as a human semantic label or as executable security validation.

## Artifacts

- Rows: `/root/mddc/empirical_validation/results/experiment_lxxiv_cvefixes_independent_gate_rows_20260624.csv`
- Controls: `/root/mddc/empirical_validation/results/experiment_lxxiv_cvefixes_independent_gate_controls_20260624.csv`
- Summary: `/root/mddc/empirical_validation/results/experiment_lxxiv_cvefixes_independent_gate_summary_20260624.json`
- Figure: `/root/mddc/empirical_validation/figures/fig_experiment_lxxiv_cvefixes_independent_gate_replication.pdf`

Document generated: 2026-06-24 11:49:28 +08:00
