# Experiment LXXXIV Provenance Stress Test

Generated: 2026-06-25 09:01:05 +08:00

## Purpose

LXXXIII showed that provenance gating removes same-CWE borrowed artifacts, but exact provenance can look definitional. LXXXIV tests whether the admission layer remains useful when provenance is missing, partial, or spoofed.

## Fixed Design

- True MegaVul pairs: `5954`.
- Same-CWE/different-CVE controls: `5954`.
- Replicates per scenario: `200`.
- Random seed: `20260625`.
- Coverage threshold: `0.529412` from LXXXIII.
- QG-DCA score threshold: `0.332827` from LXXXIII.

Perturbations:

- `dropout_x`: remove exact provenance claims from x% of true pairs.
- `spoof_x`: add false exact-provenance claims to x% of same-CWE controls.
- `combined_x_y`: apply both positive dropout and negative spoofing.

QG-DCA verified + abstain admits only verified provenance with a passing QG-DCA score. Spoofed provenance is rejected. Missing but promising provenance becomes validation debt, not admitted capital.

## Focus Results

| Scenario | Policy | Recall | False rate | Precision | Abstain | Utility |
|---|---|---:|---:|---:|---:|---:|
| clean | Coverage only | 0.994 | 0.001 | 0.999 | 0.000 | 0.990 |
| clean | Claimed provenance only | 1.000 | 0.000 | 1.000 | 0.000 | 1.000 |
| clean | Claimed provenance OR coverage | 1.000 | 0.001 | 0.999 | 0.000 | 0.998 |
| clean | QG-DCA verified + abstain | 1.000 | 0.000 | 1.000 | 0.000 | 1.000 |
| dropout_50 | Coverage only | 0.994 | 0.001 | 0.999 | 0.000 | 0.990 |
| dropout_50 | Claimed provenance only | 0.499 | 0.000 | 1.000 | 0.000 | 0.374 |
| dropout_50 | Claimed provenance OR coverage | 0.997 | 0.001 | 0.999 | 0.000 | 0.994 |
| dropout_50 | QG-DCA verified + abstain | 0.499 | 0.000 | 1.000 | 0.249 | 0.349 |
| spoof_10 | Coverage only | 0.994 | 0.001 | 0.999 | 0.000 | 0.990 |
| spoof_10 | Claimed provenance only | 1.000 | 0.100 | 0.909 | 0.000 | 0.701 |
| spoof_10 | Claimed provenance OR coverage | 1.000 | 0.100 | 0.909 | 0.000 | 0.699 |
| spoof_10 | QG-DCA verified + abstain | 1.000 | 0.000 | 1.000 | 0.000 | 1.000 |
| combined_50_10 | Coverage only | 0.994 | 0.001 | 0.999 | 0.000 | 0.990 |
| combined_50_10 | Claimed provenance only | 0.500 | 0.100 | 0.833 | 0.000 | 0.074 |
| combined_50_10 | Claimed provenance OR coverage | 0.997 | 0.101 | 0.908 | 0.000 | 0.693 |
| combined_50_10 | QG-DCA verified + abstain | 0.500 | 0.000 | 1.000 | 0.249 | 0.350 |

## Main Result

Under 10% spoofed negative provenance, `claimed_provenance_only` admits spoofed controls with mean false-admission rate `0.100`, while QG-DCA verified + abstain keeps false admission at `0.000`.

Under 50% positive provenance dropout, QG-DCA does not turn missing provenance into capital. Its recall falls to `0.499` and abstain/validation-debt rate rises to `0.249`.

Under the combined 50% dropout + 10% spoof setting, `claimed_or_coverage` has false-admission rate `0.101`. QG-DCA verified + abstain keeps false admission at `0.000` while explicitly recording abstention debt `0.249`.

This turns the exact-provenance result into a falsifiable operating rule: unverifiable provenance is not admitted, and spoofed provenance is rejected rather than counted as knowledge capital.

## Boundary

Noisy/spoofed provenance stress over proxy-label pairs; not deployment repair, not SOTA repair, and not human semantic correctness.

The experiment still relies on proxy labels from MegaVul-derived pairs. It strengthens provenance/accounting validity, not deployment repair or semantic correctness.

## Outputs

- Replicate CSV: `/root/mddc/empirical_validation/results/experiment_lxxxiv_provenance_stress_replicates_20260625.csv`
- Summary CSV: `/root/mddc/empirical_validation/results/experiment_lxxxiv_provenance_stress_summary_20260625.csv`
- Summary JSON: `/root/mddc/empirical_validation/results/experiment_lxxxiv_provenance_stress_summary_20260625.json`
- Figure: `/root/mddc/empirical_validation/figures/fig_experiment_lxxxiv_provenance_stress_test.pdf`

Document generated: 2026-06-25 09:01:05 +08:00
