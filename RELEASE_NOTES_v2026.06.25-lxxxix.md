# Release v2026.06.25-lxxxix

This release updates the QG-DCA/MDDC reproducibility artifact to the LXXXIX stable candidate.

## Added

- LXXXIX admission-oracle alignment audit.
- Frozen all-gate admission-list alignment rows and summary.
- LXXXIX figure and report.
- Updated manuscript snapshot with LXXXIX evidence.

## Key Result

- LXXXVIII executable-oracle anchor: 23/23 parent-fails/upstream-passes tasks, Wilson lower bound 0.857.
- LXXXIX admission-oracle alignment: 23/30 frozen all-gate admission-list tasks have executable anchors, Wilson lower bound 0.591.
- The `experiment_lv_validated` dynamic-oracle prerequisite subset is covered for 20/20 tasks, Wilson lower bound 0.839.
- `heldout_dynamic` and `quality_dynamic` remain partial at 2/5 and 1/5, respectively.
- Seven unanchored tasks are recorded as validation debt.

## Boundary

This release supports admission-prerequisite calibration for QG-DCA. It does not claim deployment repair success, repair SOTA, or executable validation of the ASRDataset/CVEfixes/BigVul patch-differential headline rates. The frozen repair boundary remains 1/30 primary security-qualified and 0/30 original deployment-qualified.

Generated: 2026-06-25 14:00 +08:00
