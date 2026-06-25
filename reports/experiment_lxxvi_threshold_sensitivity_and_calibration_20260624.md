# Experiment LXXVI: Threshold Sensitivity and Calibration Audit

Generated: 2026-06-24 12:14:22 +0800

## Purpose

This audit checks that the `0.275` and `0.325` thresholds are reproducible from the current replay data and documents how they should be recalibrated in other deployments. They are current-dataset calibration outputs, not universal constants.

## Reproduction Check

- Test first-positive frontier from XXIV: `0.275`.
- Test interpolated zero crossing from XXIV: `0.253541`.
- Validation first-positive frontier from XXV: `0.325`.
- Validation interpolated zero crossing from XXV: `0.316673`.

The paper uses the first-positive grid values because they are conservative and directly reproducible from the pre-declared gain grid.

## Sensitivity Summary

- Rolling-origin validation range: `0.275`--`0.575`.
- Rolling-origin test range: `0.250`--`0.325`.
- Budget validation range: `0.275`--`0.375`.
- Budget test range: `0.250`--`0.325`.
- Attack-regime validation range: `0.325`--`0.350`.
- Attack-regime test range: `0.275`--`0.275`.

## q_capital Perturbation

| q multiplier | property q_capital | required s for 0.275 | required s for 0.325 |
|---:|---:|---:|---:|
| 0.8 | 0.3560 | 0.773 | 0.913 |
| 1.0 | 0.4450 | 0.618 | 0.730 |
| 1.2 | 0.5340 | 0.515 | 0.609 |

Observed patch reuse remains below the test frontier even with a +20% q_capital perturbation. Repository applicability also remains below the test frontier under +20%. This supports the fallback decision for current low-yield CEC paths.

## Calibration Protocol

1. Fix training, validation, and test windows before evaluating a new deployment setting.
2. Estimate AEC-only and MDDC debt under identical public-task arrivals, budget, seeds, and policy definitions.
3. Sweep effective CEC gain on a pre-declared grid and record both the first-positive frontier and the interpolated zero crossing.
4. Use the validation frontier, not the test frontier, for activation; periodically recalibrate when threat pressure, resources, or gate quality shifts.
5. Treat 0.275 and 0.325 as current-dataset calibrated frontiers, not universal constants.

## Boundary

These thresholds are reproducible for the current public replay, but they are not transferable constants. A production or different-dataset use of MDDC must recalibrate the frontier under its own threat pressure, budget, validation gates, and policy definitions.

## Artifacts

- Summary: `/root/mddc/empirical_validation/results/experiment_lxxvi_threshold_sensitivity_and_calibration_summary_20260624.json`
- Threshold table: `/root/mddc/empirical_validation/results/experiment_lxxvi_threshold_sensitivity_and_calibration_table_20260624.csv`
- q perturbation table: `/root/mddc/empirical_validation/results/experiment_lxxvi_q_perturbation_sensitivity_20260624.csv`
- Figure: `/root/mddc/empirical_validation/figures/fig_experiment_lxxvi_threshold_sensitivity_and_calibration.pdf`

Document generated: 2026-06-24 12:14:22 +0800
