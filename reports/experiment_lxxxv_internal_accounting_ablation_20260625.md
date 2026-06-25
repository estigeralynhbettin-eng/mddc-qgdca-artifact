# Experiment LXXXV Internal Accounting-Component Ablation

Generated: 2026-06-25 09:03:45 +08:00

## Purpose

This experiment tests whether QG-DCA is more than a single threshold by turning off internal accounting components.

## Component Results

| Component | Stress case | Component off | Full QG-DCA | Failure/debt off | Failure/debt full | Utility off | Utility full | Interpretation |
|---|---|---|---|---:|---:|---:|---:|---|
| Provenance verification | 10% spoofed same-CWE negative provenance | Trust claimed provenance | Verify provenance before admission | 0.100 | 0.000 | 0.701 | 1.000 | Verification rejects spoofed provenance instead of admitting it as capital. |
| Abstention / capital-debt separation | 50% missing positive provenance | Admit coverage-supported missing-provenance artifacts | Record missing provenance as validation debt | 0.249 | 0.000 | 0.994 | 0.349 | Without the debt ledger, missing-evidence candidates are silently counted as capital. |
| Verification + abstention combined | 50% missing positive provenance + 10% spoofed negative provenance | Claimed provenance OR coverage | Verified provenance plus abstention | 0.349 | 0.000 | 0.693 | 0.350 | The full gate avoids both spoofed false capital and missing-evidence hidden debt, at the cost of lower recall. |
| Operating-point recalibration (CVEfixes) | CVEfixes operating curve under declared debt cost | Fixed strict gate | QG-DCA selected operating point | 0.133 | 0.060 | -0.063 | 0.193 | Recalibration prevents the paper from defending a dominated fixed gate. |
| Operating-point recalibration (BigVul) | BigVul operating curve under declared debt cost | Fixed strict gate | QG-DCA selected operating point | 0.142 | 0.032 | -0.057 | 0.365 | Recalibration prevents the paper from defending a dominated fixed gate. |

## Main Result

The ablation supports three narrow claims. First, provenance verification is necessary under spoofing: trusting claimed provenance creates false capital, while verified QG-DCA rejects spoofed claims. Second, abstention and capital-debt separation are necessary under missing provenance: otherwise missing-evidence artifacts are silently counted as capital. Third, recalibration is necessary because the fixed strict gate is dominated on CVEfixes and BigVul under the declared validation-debt cost.

The result should not be written as deployment superiority. It is evidence that QG-DCA's accounting components each remove a measurable failure mode.

## Boundary

Internal accounting ablation over existing proxy-label outputs; not deployment repair, not SOTA repair, and not human semantic correctness.

## Outputs

- Table CSV: `/root/mddc/empirical_validation/results/experiment_lxxxv_internal_accounting_ablation_table_20260625.csv`
- Summary JSON: `/root/mddc/empirical_validation/results/experiment_lxxxv_internal_accounting_ablation_summary_20260625.json`
- Figure: `/root/mddc/empirical_validation/figures/fig_experiment_lxxxv_internal_accounting_ablation.pdf`

Document generated: 2026-06-25 09:03:45 +08:00
