# Experiment LXXXII Cost-Model Sensitivity

Generated: 2026-06-24 20:01:31 +08:00

## Purpose

LXXXI selected coverage-only operating points under one declared cost model. LXXXII tests whether that conclusion depends on arbitrary constants by sweeping false-admission cost, missed-admission cost, review-load cost, and the false-admission constraint.

## Grid

- False-admission cost: `[0.5, 1.0, 2.0, 3.0, 5.0, 8.0, 13.0]`
- Missed-admission cost: `[0.0, 0.1, 0.25, 0.5, 1.0]`
- Review-load cost: `[0.0, 0.02, 0.05, 0.1, 0.2]`
- False-admission alpha: `[0.05, 0.1, 0.15, 0.2, 0.3]`
- Total cost models per dataset: `875`

## Policy Winner Shares

| Dataset | Policy | Wins | Share |
|---|---|---:|---:|
| BigVul | Risk score | 0 | 0.000 |
| BigVul | Coverage only | 875 | 1.000 |
| BigVul | Category+coverage | 0 | 0.000 |
| CVEfixes | Risk score | 0 | 0.000 |
| CVEfixes | Coverage only | 875 | 1.000 |
| CVEfixes | Category+coverage | 0 | 0.000 |

## Base Cost-Model Selection

| Dataset | Policy | Threshold | Recall | False rate | Precision | Utility |
|---|---|---:|---:|---:|---:|---:|
| BigVul | Coverage only | 0.1795 | 0.579 | 0.032 | 0.908 | 0.365 |
| CVEfixes | Coverage only | 0.1452 | 0.513 | 0.060 | 0.931 | 0.193 |

## Interpretation

Coverage-only wins most of the tested cost space. This reinforces the LXXXI revision: QG-DCA should not be defended as the original fixed strict gate. Its defensible contribution is the auditable accounting protocol that exposes policy frontiers, reports the selected operating point, and makes cost dependence explicit.

The remaining unique contribution over a naive threshold sweep is not gate optimality. It is the defense-capital accounting object: admitted capital, false capital, abstention, validation debt, and recalibration under explicit constraints.

## Boundary

The sensitivity analysis is still based on proxy labels from public datasets. It improves cost-model transparency but does not provide human semantic truth or deployment evidence.

## Outputs

- Grid CSV: `/root/mddc/empirical_validation/results/experiment_lxxxii_cost_model_sensitivity_grid_20260624.csv`
- Summary CSV: `/root/mddc/empirical_validation/results/experiment_lxxxii_cost_model_sensitivity_summary_20260624.csv`
- Summary JSON: `/root/mddc/empirical_validation/results/experiment_lxxxii_cost_model_sensitivity_summary_20260624.json`
- Figure PDF: `/root/mddc/empirical_validation/figures/fig_experiment_lxxxii_cost_model_sensitivity.pdf`

Document generated: 2026-06-24 20:01:31 +08:00
