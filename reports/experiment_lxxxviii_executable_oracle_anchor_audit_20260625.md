# Experiment LXXXVIII Executable-Oracle Anchor Audit

Generated: 2026-06-25 13:02:21 +08:00

## Purpose

This audit adds an executable semantic anchor to the QG-DCA evidence chain. It reuses existing dynamic-oracle validation outputs and counts an oracle only when the parent version is unsafe and the upstream fixed version is safe.

## Result

- Task pairs: `23`; validation rows: `46`.
- Both parent and upstream runs executed: `23/23` = `1.000`, Wilson 95% CI `0.857`--`1.000`.
- Parent unsafe: `23/23` = `1.000`, CI `0.857`--`1.000`.
- Upstream safe: `23/23` = `1.000`, CI `0.857`--`1.000`.
- Executable anchor, parent-fails/upstream-passes: `23/23` = `1.000`, CI `0.857`--`1.000`.

## Boundary

This is executable oracle validation for parent/upstream contrast, not AI repair success, production deployment, or human semantic labeling.

The audit strengthens construct validity for the validation gate, but it does not convert the repair experiments into deployment-rate evidence.

## Source Integrity

- Validation CSV SHA256: `eda3602c519d36d063d68ce1015ff751ca2681b2a61fa90b4144513303405af2`.
- Summary JSON SHA256: `82aa80c85e40b10e69e93cc81441e20733c8060d2fd501724c2102a89250ed2f`.

Document generated: 2026-06-25 13:05 +08:00
