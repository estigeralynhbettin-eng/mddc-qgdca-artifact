# Experiment LXXXIX: Admission-Oracle Alignment

## Purpose

This audit answers a narrower construct-validity question raised by the LXXXVIII review: whether the executable oracle anchor is only adjacent to MDDC/QG-DCA, or whether it calibrates any frozen admission-list prerequisite.

## Result

- Frozen all-gate admission-list tasks: `30`.
- Tasks with executable parent-fails/upstream-passes anchor: `23/30`; Wilson 95% CI `0.591--0.882`.
- Among anchored tasks, parent-fails/upstream-passes holds for `23/23`; Wilson 95% CI `0.857--1.000`.
- The `experiment_lv_validated` admission-prerequisite subset is covered by executable anchors for `20/20` tasks; Wilson 95% CI `0.839--1.000`.
- Remaining unanchored tasks are counted as validation debt: `7`.

## Interpretation

LXXXIX partially closes the LXXXVIII gap. The executable oracle is no longer merely adjacent to the admission layer: it calibrates the dynamic-oracle prerequisite for the `experiment_lv_validated` subset of the frozen admission list. Under strict behavioral accounting, tasks without an executable anchor are not promoted to behavioral capital; they remain validation debt or require escalation.

## Boundary

- This is prerequisite calibration, not end-to-end repair success.
- It does not validate ASRDataset, CVEfixes, or BigVul patch-differential headline rates.
- It does not change the frozen repair deployment result: 1/30 primary security-qualified and 0/30 original deployment-qualified.
- It makes QG-DCA more defensible as an accounting protocol because it identifies exactly which admission-list prerequisites are behaviorally anchored and which must be abstained/escalated.

## Outputs

- Rows: `/root/mddc/empirical_validation/results/experiment_lxxxix_admission_oracle_alignment_rows_20260625.csv`
- Summary: `/root/mddc/empirical_validation/results/experiment_lxxxix_admission_oracle_alignment_summary_20260625.json`
- Figure PDF: `/root/mddc/empirical_validation/figures/fig_experiment_lxxxix_admission_oracle_alignment.pdf`
- Figure PNG: `/root/mddc/empirical_validation/figures/fig_experiment_lxxxix_admission_oracle_alignment.png`

Document generated: 2026-06-25 13:35 +08:00
