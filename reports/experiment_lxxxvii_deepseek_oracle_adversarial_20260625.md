# Experiment LXXXVII DeepSeek Candidate-Oracle Adversarial Calibration

Generated: 2026-06-25 11:06:29 +08:00

## Purpose

This experiment tests whether QG-DCA's generator/admission separation holds for a second independent model. DeepSeek generates candidate security predicates; objective gates decide admission.

## Sample

- Total cases: `170`.
- Base patch cases: `85`.
- Adversarial mismatched metadata/patch cases: `85`.
- Base expected positives: `51`.
- Base expected negatives: `34`.
- Model: `deepseek-chat`.

## Main Results

- Base DeepSeek candidate positive recall: `43/51` = `0.843`, Wilson 95% CI `0.720`--`0.918`.
- Base QG-DCA positive recall: `43/51` = `0.843`, Wilson 95% CI `0.720`--`0.918`.
- Base DeepSeek-only false candidates on negatives: `23/34` = `0.676`, Wilson 95% CI `0.508`--`0.809`.
- Base QG-DCA false admissions on negatives: `0/34` = `0.000`, Wilson 95% CI `0.000`--`0.102`.
- Adversarial DeepSeek-only false candidates: `39/85` = `0.459`, Wilson 95% CI `0.357`--`0.564`.
- Adversarial QG-DCA false admissions: `0/85` = `0.000`, Wilson 95% CI `0.000`--`0.043`.
- All-negative DeepSeek-only false candidates: `62/119` = `0.521`, Wilson 95% CI `0.432`--`0.609`.
- All-negative QG-DCA false admissions: `0/119` = `0.000`, Wilson 95% CI `0.000`--`0.031`.

## Interpretation

The result is useful only if read as model-agnostic admission accounting. A high candidate rate shows generation ability; false candidates on negatives or adversarial rows show why candidate generation cannot define capital. QG-DCA admits only when objective evidence and provenance are consistent.

## Boundary

DeepSeek is only a candidate generator. Admission is decided by objective patch-differential and provenance-consistency surrogate gates. Adversarial rows are constructed mismatched metadata/patch prompts, not independent real vulnerabilities.

## Usage Audit

- API calls: `170`.
- Successful calls: `170`.
- Total tokens: `122397`.
- Estimated cost USD: `0.018062`.

Document generated: 2026-06-25 11:06:30 +08:00
