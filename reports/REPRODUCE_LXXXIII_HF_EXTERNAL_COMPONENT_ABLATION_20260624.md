# Reproduce LXXXIII Hugging Face External Component Ablation

Run from `/root/mddc`:

```bash
python3 empirical_validation/experiment_lxxxiii_hf_external_component_ablation.py
```

Required local datasets:

- `/mnt/d/lunwen/datasets/huggingface_security/mddc/security-kg`
- `/mnt/d/lunwen/datasets/huggingface_security/mddc/megavul`
- `/mnt/d/lunwen/datasets/huggingface_security/mddc/vulnerability-scores`

Random seed: `20260624`.

The experiment writes CSV/JSON outputs under `/root/mddc/empirical_validation/results`, figures under `/root/mddc/empirical_validation/figures`, and a report under `/root/mddc/review_rounds`.

Boundary: this experiment measures proxy-label provenance/accounting behavior. It does not establish deployment repair or human semantic correctness.

Document generated: 2026-06-24 22:46:07 +08:00
