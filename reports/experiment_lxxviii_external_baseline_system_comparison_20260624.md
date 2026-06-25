# Experiment LXXVIII External Baseline/System Comparison

Generated: 2026-06-24 15:14:38 +08:00

## Material Passport

- Mode: code experiment / reproducibility validation
- Data access: existing public datasets and frozen prior experiment rows
- Pre-registration: `/root/mddc/empirical_validation/experiment_lxxvii_lxxviii_preregistration_20260624.md`
- Claim boundary: false-admission accounting, not deployment-rate superiority

## Headline

- ASR strict same-category false rate: `0.000000`
- ASR balanced same-category false rate: `0.174497`
- CVEfixes CVSS-only same-category false rate: `0.479423`
- CVEfixes structural-only same-category false rate: `0.822220`
- CVEfixes MDDC-strict same-category false rate: `0.138007`
- MDDC false-admission reduction vs CVSS-only: `0.712140`
- MDDC false-admission reduction vs structural-only: `0.832154`

## Interpretation

This experiment tests whether qualification-gated admission reduces false capital admission against external or naive baselines. It should be read together with LXXVII: LXXVII did not clear the behavioral-oracle threshold, so LXXVIII supports false-admission accounting rather than behavioral semantic truth.

## Outputs

- ASR policies: `/root/mddc/empirical_validation/results/experiment_lxxviii_external_baseline_asr_policies_20260624.csv`
- CVEfixes policies: `/root/mddc/empirical_validation/results/experiment_lxxviii_external_baseline_cvefixes_policies_20260624.csv`
- CVEfixes controls: `/root/mddc/empirical_validation/results/experiment_lxxviii_external_baseline_cvefixes_controls_20260624.csv`
- Utility policies: `/root/mddc/empirical_validation/results/experiment_lxxviii_external_baseline_utility_policies_20260624.csv`
- Summary: `/root/mddc/empirical_validation/results/experiment_lxxviii_external_baseline_system_comparison_summary_20260624.json`
- Figure PDF: `/root/mddc/empirical_validation/figures/fig_experiment_lxxviii_external_baseline_system_comparison.pdf`

Document generated: 2026-06-24 15:14:38 +08:00
