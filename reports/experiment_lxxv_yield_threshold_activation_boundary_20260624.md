# Experiment LXXV: Yield-Threshold Activation Boundary

Generated: 2026-06-24 11:51:39 +0800

## Purpose

This experiment formalizes the KEV/replay negative result as a controller boundary. MDDC does not activate CEC-derived knowledge just because it exists; it activates only when qualified effective gain crosses a data-derived threshold.

## Rule

`effective_gain = q_capital * s_quality`

- Held-out test frontier: `0.275`.
- Conservative validation frontier: `0.325`.

## Main Findings

- Observed patch-reuse gain is `0.0392`, so the controller selects `AEC-only`.
- Always-on MDDC would be `-10.70%` worse in the observed replay, and gating prevents `24.626` mean-debt penalty.
- Property capital requires `s_quality >= 0.618` for the test frontier and `s_quality >= 0.730` for the conservative validation frontier.

## Activation Table

| Scenario | q_capital | s_quality | effective_gain | Decision |
|---|---:|---:|---:|---|
| observed_patch_reuse_gain | 0.0392 | 1.0000 | 0.0392 | fallback_aec_only |
| current_all_static_qualified | 0.0315 | 1.0000 | 0.0315 | fallback_aec_only |
| current_knowledge_static_qualified | 0.0360 | 1.0000 | 0.0360 | fallback_aec_only |
| repo_applicability_upper_bound | 0.1396 | 1.0000 | 0.1396 | fallback_aec_only |
| measured_property_delivery_proxy | 0.4450 | 0.0333 | 0.0148 | fallback_aec_only |
| property_test_threshold | 0.4450 | 0.6180 | 0.2750 | borderline_test_only |
| property_validation_threshold | 0.4450 | 0.7304 | 0.3250 | activate_mddc_validation_conservative |
| property_full_quality_upper_bound | 0.4450 | 1.0000 | 0.4450 | activate_mddc_validation_conservative |

## Interpretation

The negative replay is not discarded. It becomes the empirical reason for a qualification gate: below the frontier, MDDC should abstain from CEC activation and fall back to AEC-only. Above the frontier, qualified property capital becomes a plausible activation path.

## Boundary

This is a threshold/accounting experiment. It does not prove deployment-grade repair and does not claim that CEC is universally better than AEC.

## Artifacts

- Table: `/root/mddc/empirical_validation/results/experiment_lxxv_yield_threshold_activation_boundary_table_20260624.csv`
- Summary: `/root/mddc/empirical_validation/results/experiment_lxxv_yield_threshold_activation_boundary_summary_20260624.json`
- Figure: `/root/mddc/empirical_validation/figures/fig_experiment_lxxv_yield_threshold_activation_boundary.pdf`

Document generated: 2026-06-24 11:51:39 +0800
