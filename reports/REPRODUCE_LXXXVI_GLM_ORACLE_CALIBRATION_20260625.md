# Reproduce LXXXVI GLM-Assisted Candidate Oracle Calibration

Run from `/root/mddc`:

```bash
python3 empirical_validation/experiment_lxxxvi_glm_oracle_calibration.py
```

Requires:

- `GLM_API_KEY` in the local environment or `/mnt/c/Users/PBCDCI/.llm_api_keys.env`.
- `/root/mddc/empirical_validation/results/experiment_lxxvii_patch_differential_oracle_rows_20260624.csv`.
- cached patch files referenced by `patch_cache_path`.

Random seed: `20260625`.
Model: `glm-4.7`.

Boundary: GLM generates candidates only; objective gates decide qualification.

Document generated: 2026-06-25 10:25:48 +08:00
