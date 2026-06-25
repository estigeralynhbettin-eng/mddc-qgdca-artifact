# MDDC QG-DCA Main Reproducibility Package

Generated: 2026-06-25 11:45 +08:00

Archived release DOI: [10.5281/zenodo.20838869](https://doi.org/10.5281/zenodo.20838869)

All-version concept DOI: [10.5281/zenodo.20838868](https://doi.org/10.5281/zenodo.20838868)

This package supports the measurement-paper claim:

> MDDC/QG-DCA is a qualification-gated admission and accounting method for context-qualified AI security artifacts. It measures false security-capital admission and validation debt. It does not claim automatic AI repair or deployment-rate superiority.

## Contents

- `scripts/`: replay and figure scripts for LXXIV--LXXXVI and the main QG-DCA figures.
- `results/`: CSV/JSON result tables used by the main manuscript.
- `figures/`: PDF figures generated from the result tables.
- `reports/`: human-readable experiment reports.
- `preregistration/`: pre-registration documents for the late-stage experiments where available.
- `data_metadata/`: public dataset metadata and checksums where available.
- `manuscript/`: manuscript source/text snapshot associated with this package.
- `version_control/`: file-based version-control guardrails for the LXXXIII stable baseline, promoted LXXXIV/LXXXV revision, and LXXXVI GLM-oracle candidate revision.

## One-Command Reproduction

From this repository root, run:

```bash
bash run_reproduce.sh
```

The script defaults to the original project layout at `/root/mddc`. If the MDDC
project is elsewhere, set `MDDC_ROOT`:

```bash
MDDC_ROOT=/path/to/mddc bash run_reproduce.sh
```

The script regenerates the late-stage tables and figures used for the QG-DCA evidence chain:

- CVEfixes independent gate replication.
- CEC activation-frontier and threshold-sensitivity tables.
- Patch-differential oracle boundary check.
- External baseline comparison.
- BigVul cross-dataset replication.
- Matched-recall and cost-aware baseline comparison.
- Operating-curve and debt-adjusted selection.
- Cost-model sensitivity for operating-point selection.
- Hugging Face external component ablation.
- Noisy/partial/spoofed provenance stress test.
- Internal QG-DCA accounting-component ablation.
- Main QG-DCA schematic and evidence atlas.

The LXXXVI GLM-assisted oracle-calibration experiment is included as a paid/API-dependent optional replay. To rerun it, load `GLM_API_KEY` into the environment and execute:

```bash
RUN_PAID_GLM=1 GLM_API_KEY=... bash run_reproduce.sh
```

The saved rows, summary, report, and figure from the paper run are included in this package so that default reproduction does not require a paid model call.

## Integrity Check

The repository includes `MANIFEST.sha256`. To verify the archived files:

```bash
sha256sum -c MANIFEST.sha256
```

## Data Requirements

The package expects the public raw data to be available in the project layout used by the experiments:

- CVEfixes parquet files under `/root/mddc/empirical_validation/data/raw/cvefixes/`.
- BigVul CSV under `/root/mddc/empirical_validation/data/raw/bigvul/all_c_cpp_release2.0.csv`.
- Hugging Face security datasets under `/mnt/d/lunwen/datasets/huggingface_security/mddc/`:
  - `security-kg`
  - `megavul`
  - `vulnerability-scores`
- Existing ASR/VulGenie-derived and repair-audit result tables under `/root/mddc/empirical_validation/results/`.

Raw third-party datasets are not duplicated here when they are already public. Checksums and source metadata are recorded where available.

## Reproducibility Boundary

This package reproduces benchmark-agreement, false-admission, threshold-calibration, matched-recall, operating-curve, cost-sensitivity, provenance-stress, GLM candidate-oracle calibration outputs, and utility-accounting evidence. It does not provide human semantic ground truth and does not reproduce a production deployment. Deployment superiority is not claimed.

The LXXXIV/LXXXV additions are proxy-label accounting stress tests. They support provenance verification, abstention, capital/debt separation, and recalibration claims. They do not establish deployment repair, SOTA repair, or human semantic correctness.

The LXXXVI addition uses GLM only as a candidate security-predicate generator. Qualification remains controlled by objective patch-differential surrogate gates; it is not an LLM-as-judge experiment.

## Public Archive Status

This artifact is publicly archived on Zenodo. For manuscript citation, use the
version DOI `10.5281/zenodo.20838869` unless intentionally citing all future
artifact versions through the concept DOI `10.5281/zenodo.20838868`.
