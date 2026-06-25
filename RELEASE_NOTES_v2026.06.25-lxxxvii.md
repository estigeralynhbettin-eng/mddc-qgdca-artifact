# v2026.06.25-lxxxvii

This release updates the MDDC QG-DCA reproducibility artifact with the LXXXVII
DeepSeek candidate-oracle adversarial calibration and the DOI-aware manuscript
availability text.

## Changes Since v2026.06.25-qgdca

- Adds Experiment LXXXVII DeepSeek-chat candidate-oracle adversarial
  calibration.
- Adds LXXXVII rows, summary JSON, report, figure, and reproduction note.
- Updates the manuscript snapshot to cite the public Zenodo artifact DOI.
- Updates metadata to state that GLM and DeepSeek are candidate predicate
  generators only; objective qualification gates decide admission.
- Removes the failed GLM timeout/flash scratch script from the formal artifact.

## Existing Public DOI

The first archived version is available at:

- Version DOI: https://doi.org/10.5281/zenodo.20838869
- Concept DOI: https://doi.org/10.5281/zenodo.20838868

If Zenodo mints a new version DOI for this release, cite that newer version DOI
for manuscripts that rely on Experiment LXXXVII.

## Boundary

This release supports model-agnostic candidate/admission separation. It does not
claim human semantic ground truth, SOTA repair, production deployment, or
deployment-rate superiority.
