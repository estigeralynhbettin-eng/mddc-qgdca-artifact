# LXXXVII DeepSeek Guardrail Manifest

Generated: 2026-06-25 +08:00

## Files

- PROMOTED_CANDIDATE_LXXXVII_MDDC-MEASUREMENT.pdf
  - SHA256: 85B727EE487CF903BD10D857174E9D4FDE1FDDED8FF3D7F8254C0A8A0705DA85
- PROMOTED_CANDIDATE_LXXXVII_MDDC-MEASUREMENT.tex
  - SHA256: EA2D4DEB70C53C5BDA1090B1649BB1E790464671E439D96FDC01D683FFAB45BF

## Experiment

- LXXXVII DeepSeek candidate-oracle adversarial calibration.
- DeepSeek-chat candidate recall: 43/51.
- DeepSeek all-negative candidate marks: 62/119.
- QG-DCA all-negative false admissions: 0/119.
- Cost: USD 0.018062.

## Claude Review

- Opus 4.8 review after LXXXVII: direct SCI 31%, major-revision-or-better 78%, post-revision SCI 61%, top journal 9%.
- Required edits applied: explicit denominators, surrogate/provenance boundary, prompt/sample dependency warning.

## Boundary

DeepSeek is only a candidate generator. QG-DCA admission remains controlled by objective patch-differential and provenance-consistency surrogate gates. Adversarial rows are constructed mismatched metadata/patch prompts, not independent real vulnerabilities.

