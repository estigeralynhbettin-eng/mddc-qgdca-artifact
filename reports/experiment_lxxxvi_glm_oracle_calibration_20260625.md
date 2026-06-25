# Experiment LXXXVI GLM-Assisted Candidate Oracle Calibration

Generated: 2026-06-25 10:25:47 +08:00

## Purpose

This experiment tests whether GLM can help construct candidate security oracles without making GLM a judge. GLM generates candidate predicates; objective patch-differential gates decide qualification.

## Fixed Sample

- Objective-positive LXXVII tasks: `20`.
- Objective-negative LXXVII tasks: `20`.
- Random seed: `20260625`.
- GLM model: `glm-4.7`.

## Main Results

- GLM JSON parse rate: `1.000`.
- GLM non-vacuous candidate rate: `1.000`.
- GLM candidate-gate recall on objective positives: `0.950`.
- GLM-only false candidate rate on objective negatives: `0.500`.
- QG-DCA qualified positive recall: `0.950`.
- QG-DCA false-admission rate on objective negatives: `0.000`.

## Interpretation

The result should be read as a candidate-oracle calibration, not as an LLM-judge experiment. If GLM produces checkable predicates but the objective gate rejects them on negative rows, the evidence supports the MDDC claim that generation and admission are separate stages.

## Boundary

GLM is only a candidate oracle generator. Qualification is decided by objective patch-differential surrogate gates; this is not deployment, native/dynamic all-gate, SOTA repair, or human semantic correctness.

## Usage Audit

- API calls: `40`.
- Successful calls: `40`.
- Prompt tokens: `28409`.
- Completion tokens: `77506`.
- Total tokens: `105915`.

## Outputs

- Rows CSV: `/root/mddc/empirical_validation/results/experiment_lxxxvi_glm_oracle_calibration_rows_20260625.csv`
- Summary JSON: `/root/mddc/empirical_validation/results/experiment_lxxxvi_glm_oracle_calibration_summary_20260625.json`
- Figure: `/root/mddc/empirical_validation/figures/fig_experiment_lxxxvi_glm_oracle_calibration.pdf`

Document generated: 2026-06-25 10:25:48 +08:00
