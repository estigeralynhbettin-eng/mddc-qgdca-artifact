# v2026.06.25-lxxxvii.1

This maintenance release supersedes `v2026.06.25-lxxxvii`.

## Fix

- Adds `scripts/experiment_lxxxvii_case_helpers.py`, a model-free helper module
  used by the optional DeepSeek LXXXVII replay.
- Updates the DeepSeek LXXXVII replay script to depend on the helper module
  rather than the exploratory scaled-GLM script.
- Freezes the optional LXXXVII replay input to the artifact-packaged LXXVII rows
  so that it reproduces the paper run sample: 85 base rows plus 85 constructed
  metadata/patch mismatch rows.

## Boundary

The fix does not change the paper-run LXXXVII result tables. It only repairs the
optional paid replay path and keeps failed/exploratory GLM scaling code out of
the formal artifact.
