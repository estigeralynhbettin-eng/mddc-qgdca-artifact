# Experiment LXXXI Operating-Curve and Debt-Adjusted Selection

Generated: 2026-06-24 19:46:06 +08:00

## Purpose

LXXX showed that a fixed strict gate is not Pareto-optimal at one matched-recall point. LXXXI therefore evaluates complete operating curves and treats QG-DCA as an accounting protocol that selects and audits an operating point under validation-debt costs.

## Cost Model

- False-admission cost: `3.0`
- Missed-admission cost: `0.25`
- Review-load cost: `0.05`
- False-admission constraint: `0.15`

## Selected Operating Points

| Dataset | Selection | Policy | Threshold | Recall | False rate | Precision | Utility |
|---|---|---|---:|---:|---:|---:|---:|
| BigVul | qgdca_best_overall | coverage_only | 0.1795 | 0.579 | 0.032 | 0.908 | 0.365 |
| BigVul | qgdca_best_under_false_constraint | coverage_only | 0.1795 | 0.579 | 0.032 | 0.908 | 0.365 |
| BigVul | fixed_strict_0_10 | category_plus_coverage | 0.0976 | 0.507 | 0.142 | 0.663 | -0.057 |
| CVEfixes | qgdca_best_overall | coverage_only | 0.1452 | 0.513 | 0.060 | 0.931 | 0.193 |
| CVEfixes | qgdca_best_under_false_constraint | coverage_only | 0.1452 | 0.513 | 0.060 | 0.931 | 0.193 |
| CVEfixes | fixed_strict_0_10 | category_plus_coverage | 0.1008 | 0.483 | 0.133 | 0.852 | -0.063 |

## Interpretation

The result resolves the coverage-only boundary by changing the claim: QG-DCA is not a fixed strict gate. It is the protocol that exposes the curve, records the debt model, and selects an operating point. If a simpler coverage-only point dominates under the declared cost model, QG-DCA should select or report that point instead of defending the fixed strict gate.

## Boundary

The labels remain benchmark-reference and proxy labels. This experiment improves operating-point validity but does not provide human semantic truth or deployment-rate evidence.

## Outputs

- Curve points: `/root/mddc/empirical_validation/results/experiment_lxxxi_operating_curve_points_20260624.csv`
- Selected points: `/root/mddc/empirical_validation/results/experiment_lxxxi_operating_curve_selected_points_20260624.csv`
- Summary: `/root/mddc/empirical_validation/results/experiment_lxxxi_operating_curve_selection_summary_20260624.json`
- Figure PDF: `/root/mddc/empirical_validation/figures/fig_experiment_lxxxi_operating_curve_selection.pdf`

Document generated: 2026-06-24 19:46:06 +08:00
