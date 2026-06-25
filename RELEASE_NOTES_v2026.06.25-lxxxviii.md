# v2026.06.25-lxxxviii

This release updates the MDDC QG-DCA reproducibility artifact with Experiment
LXXXVIII, the executable-oracle anchor audit.

## Changes Since v2026.06.25-lxxxvii.1

- Adds `experiment_lxxxviii_executable_oracle_anchor_audit.py`.
- Adds LXXXVIII task-level CSV, summary JSON, report, reproduction note, and
  figure.
- Updates the manuscript snapshot to include the 23-task executable-oracle
  anchor.
- Keeps the LXXXVII.1 replay helper fix: optional DeepSeek replay uses a
  model-free helper module and the frozen 85 base + 85 adversarial sample.

## LXXXVIII Boundary

The executable-oracle audit validates 23/23 parent-fails/upstream-passes dynamic
oracle tasks. It anchors the validation gate in behavior, but it is not AI repair
success, production deployment, or deployment-rate evidence.
