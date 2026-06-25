# Experiment LXXX Matched-Recall and Cost-Aware Baseline Comparison

Generated: 2026-06-24 19:13:12 +08:00

## Purpose

This experiment addresses the recall-confounding critique. It tunes score-only, coverage-only, and random baselines to the MDDC strict gate's true-pair recall, then compares same-category false admissions. It also reports a unit-review utility comparison in the XLVIII pool.

## Headline

- CVEfixes matched recall: `0.493`.
- CVEfixes same-category false rates at matched recall: risk-score `0.491`, coverage-only `0.051`, random `0.493`, MDDC strict `0.138`.
- BigVul matched recall: `0.507`.
- BigVul same-category false rates at matched recall: risk-score `0.537`, coverage-only `0.020`, random `0.508`, MDDC strict `0.142`.
- Utility pool MDDC: `33` true positives, `0` false admissions, review load per TP `1.000`.
- Best non-MDDC utility baseline by false admissions: `structural_core_gate` with `34` true positives and `0` false admissions.

## Boundary

This is a fairness and cost-accounting check. The target labels remain benchmark-reference or utility-proxy labels. The experiment does not establish human semantic correctness or deployment-rate superiority.

## Outputs

- Dataset policy table: `/root/mddc/empirical_validation/results/experiment_lxxx_matched_recall_dataset_policies_20260624.csv`
- Control trials: `/root/mddc/empirical_validation/results/experiment_lxxx_matched_recall_control_trials_20260624.csv`
- Control aggregate: `/root/mddc/empirical_validation/results/experiment_lxxx_matched_recall_control_aggregate_20260624.csv`
- Utility table: `/root/mddc/empirical_validation/results/experiment_lxxx_matched_recall_utility_policy_table_20260624.csv`
- Summary: `/root/mddc/empirical_validation/results/experiment_lxxx_matched_recall_cost_baseline_summary_20260624.json`
- Figure PDF: `/root/mddc/empirical_validation/figures/fig_experiment_lxxx_matched_recall_cost_baseline.pdf`

Document generated: 2026-06-24 19:13:12 +08:00
