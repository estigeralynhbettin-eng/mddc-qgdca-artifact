# Reproduce LXXXIV Provenance Stress Test

Run from `/root/mddc`:

```bash
python3 empirical_validation/experiment_lxxxiv_provenance_stress_test.py
```

Required input files:

- `/root/mddc/empirical_validation/results/experiment_lxxxiii_hf_external_component_pairs_20260624.csv`
- `/root/mddc/empirical_validation/results/experiment_lxxxiii_hf_external_component_selected_20260624.csv`

Random seed: `20260625`.
Replicates per scenario: `200`.

Boundary: this is a noisy/spoofed provenance accounting stress test over proxy-label data. It does not establish deployment repair or semantic correctness.

Document generated: 2026-06-25 09:01:05 +08:00
