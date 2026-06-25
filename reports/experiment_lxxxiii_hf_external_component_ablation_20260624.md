# Experiment LXXXIII Hugging Face External Component Ablation

Generated: 2026-06-24 22:46:06 +08:00

## Purpose

This experiment tests what QG-DCA adds beyond threshold-plus-utility selection using three newly downloaded Hugging Face datasets: MegaVul, security-kg, and CIRCL vulnerability-scores.

The primary comparison uses MegaVul true function-level vulnerability/fix pairs and same-CWE/different-CVE hard controls. CIRCL vulnerability-scores supplies external CVSS/patch metadata, and security-kg supplies EPSS/KEV/CVE/CWE provenance evidence.

## Fixed Sample

- Positive MegaVul true pairs: `5954`
- Same-CWE/different-CVE hard controls: `5954`
- Cross-CWE diagnostic controls: `5954`
- Random seed: `20260624`

## Selected Operating Points on Same-CWE Hard Controls

| Policy | Threshold | Recall | False rate | Precision | Utility | Interpretation |
|---|---:|---:|---:|---:|---:|---|
| Risk only | 1.0000 | 0.002 | 0.002 | 0.500 | -0.254 | External severity alone is triage, not artifact admission. |
| Coverage only | 0.5294 | 0.994 | 0.001 | 0.999 | 0.966 | Best threshold-only proxy; ignores provenance. |
| KG consistency | 0.9000 | 0.218 | 0.072 | 0.752 | -0.200 | CWE/KG consistency without provenance is not enough. |
| Coverage+KG | 0.5850 | 0.992 | 0.001 | 0.999 | 0.962 | Adds KG evidence but still lacks capital provenance. |
| QG-DCA no KG | 0.2604 | 1.000 | 0.000 | 1.000 | 0.975 | Provenance and coverage without KG enrichment. |
| QG-DCA full | 0.3328 | 1.000 | 0.000 | 1.000 | 0.975 | Full accounting: provenance, KG/risk evidence, and operating-point selection. |

## Main Result

The best selected policy on same-CWE hard controls is `QG-DCA full` with recall `1.000`, false-admission rate `0.000`, precision `1.000`, and debt-adjusted utility `0.975`.

The result directly addresses the LXXXII concern, but the interpretation must be conservative. Coverage-only already performs strongly on this fixed sample, yet it still admits same-CWE/different-CVE borrowed artifacts. QG-DCA removes those admissions by adding an explicit provenance gate: candidate artifacts can update `H_q(t)` only when their source CVE/commit evidence is consistent with the target vulnerability.

## Component Interpretation

- MegaVul supplies the reproducible true-pair and same-CWE hard-control sample (`5954` positives and `5954` controls).
- CIRCL vulnerability-scores supplies external severity and patch metadata, but severity alone behaves as triage rather than capital admission.
- security-kg supplies external CVE/CWE/EPSS/KEV evidence chains, but KG consistency alone is not a sufficient admission rule.
- The measured gain from provenance gating is false-admission reduction from `0.0007` under coverage-only to `0.0000` under QG-DCA without KG.
- The measured incremental performance gain from adding KG fields on top of provenance is `0.0000` utility in this sample. Therefore security-kg should be written as external evidence/provenance enrichment, not as the primary source of performance improvement.

## Boundary

This is not deployment-grade repair evidence. MegaVul is used as a function-level proxy dataset, and the Hugging Face version contains synthetic hashes. Therefore the result supports external accounting/provenance validity, not native tests, dynamic exploit blocking, SOTA repair, or human semantic correctness.

## Outputs

- Pair table: `/root/mddc/empirical_validation/results/experiment_lxxxiii_hf_external_component_pairs_20260624.csv`
- Operating curves: `/root/mddc/empirical_validation/results/experiment_lxxxiii_hf_external_component_curves_20260624.csv`
- Selected points: `/root/mddc/empirical_validation/results/experiment_lxxxiii_hf_external_component_selected_20260624.csv`
- Summary: `/root/mddc/empirical_validation/results/experiment_lxxxiii_hf_external_component_summary_20260624.json`
- Figure: `/root/mddc/empirical_validation/figures/fig_experiment_lxxxiii_hf_external_component_ablation.pdf`

Document generated: 2026-06-24 22:46:07 +08:00
