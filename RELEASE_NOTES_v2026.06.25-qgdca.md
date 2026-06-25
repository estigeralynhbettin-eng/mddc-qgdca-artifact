# v2026.06.25-qgdca

This release archives the MDDC QG-DCA reproducibility artifact for the measurement-paper evidence chain.

## Contents

- Replay scripts for Experiments LXXIV-LXXXVI and the main QG-DCA figures.
- Result tables and summaries used by the manuscript snapshot.
- Figures, reports, preregistration notes, dataset metadata, and version-control guardrails.
- `MANIFEST.sha256` for file integrity verification.
- `CITATION.cff` and `.zenodo.json` for GitHub/Zenodo metadata.

## Reproducibility

Default replay does not require paid API calls:

```bash
bash run_reproduce.sh
```

If the original MDDC workspace is not at `/root/mddc`, set:

```bash
MDDC_ROOT=/path/to/mddc bash run_reproduce.sh
```

The GLM-assisted oracle-calibration replay is optional and requires a local `GLM_API_KEY`:

```bash
RUN_PAID_GLM=1 GLM_API_KEY=... bash run_reproduce.sh
```

## Claim Boundary

The artifact supports qualification-gated admission/accounting, false security-capital admission, validation-debt, matched-recall baseline, operating-curve, cost-sensitivity, provenance-stress, internal accounting-ablation, GLM candidate-oracle calibration, and activation-frontier analyses.

It does not claim human semantic ground truth, SOTA repair, production deployment, or deployment-rate superiority.
