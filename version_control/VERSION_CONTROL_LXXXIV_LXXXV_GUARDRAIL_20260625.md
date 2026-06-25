# MDDC LXXXIV/LXXXV Version-Control Guardrail

Generated: 2026-06-25 09:08:00 +08:00

## Purpose

This folder freezes the last stable manuscript before the new LXXXIV/LXXXV experiments and the current candidate manuscript after integrating them.

The project is not currently a Git repository, so the version-control mechanism is:

1. freeze stable manuscript artifacts;
2. freeze candidate manuscript artifacts;
3. record SHA256 hashes;
4. promote candidate to stable only after review;
5. keep failed or weakening experiments as separate reports, not as main-paper claims.

## Stable Baseline

This is the last stable manuscript before the LXXXIV/LXXXV changes.

- PDF: `STABLE_LXXXIII_MDDC-MEASUREMENT.pdf`
- TeX: `STABLE_LXXXIII_MDDC-MEASUREMENT.tex`
- PDF SHA256: `386040674a02a594a3f41657bff9ecc6c6f0132f57e3fca006a70e04b4a17aaa`
- TeX SHA256: `7d9ebe852f89cb6920e1300772f226bfa17b7805b512bc443df7183f007356db`

Stable claim set:

- QG-DCA is a qualification-gated defense-capital accounting method.
- LXXXIII resolves the external component-ablation gap only modestly.
- security-kg is evidence-chain/provenance enrichment, not standalone performance gain.
- No deployment superiority, no SOTA repair, no human semantic gold-standard claim.

## Candidate Revision

This is the current candidate manuscript with LXXXIV and LXXXV integrated.

- PDF: `CANDIDATE_LXXXIV_LXXXV_MDDC-MEASUREMENT.pdf`
- TeX: `CANDIDATE_LXXXIV_LXXXV_MDDC-MEASUREMENT.tex`
- PDF SHA256: `42303639902085108ef17e253be9d8d7fd289ee5e9d2ba812e4449846dddeadd`
- TeX SHA256: `b017ee1437a0be3ba289a98834b31792e223c8f4002d95f60bc498d058cc8ddd`

Candidate additions:

- LXXXIV noisy/partial/spoofed provenance stress test.
- LXXXV internal QG-DCA accounting-component ablation.

Promotion rule:

- Promote this candidate to the stable manuscript only if the Opus 4.8 review says it improves or at least does not weaken the SCI submission path.
- If Opus says the additions overcomplicate or weaken the paper, revert the main manuscript to the stable LXXXIII version and keep LXXXIV/LXXXV as supplementary evidence only.

## Experiment Reports

- LXXXIV report: `experiment_lxxxiv_provenance_stress_test_20260625.md`
  - SHA256: `4f9767e9c4eb8fc24e98cd9c00bbf18fb3c6c82e9336732a738fcab9bb088646`
- LXXXV report: `experiment_lxxxv_internal_accounting_ablation_20260625.md`
  - SHA256: `11b8c0c1fea3d2a74aabf74bb5f9c620a7b2ababbc6dcb26aa66d9cdab325ff6`

## Contamination Rules

- Do not overwrite the stable LXXXIII artifacts.
- Do not state LXXXIV/LXXXV as deployment repair evidence.
- Do not state LXXXIV/LXXXV as SOTA repair evidence.
- Do not claim semantic correctness from LXXXIV/LXXXV; they are proxy-label accounting stress tests.
- If any later experiment fails, record it in `LATEST_OUTPUTS.md` and a separate report, but do not merge it into `MDDC-MEASUREMENT.tex` unless it strengthens or clarifies the paper's central claim.

## Rollback

To rollback the main manuscript to LXXXIII stable:

```bash
cd /root/mddc
cp review_rounds/version_control/20260625_lxxxiv_lxxxv_guardrail/STABLE_LXXXIII_MDDC-MEASUREMENT.tex mddc_latex/MDDC-MEASUREMENT.tex
cp review_rounds/version_control/20260625_lxxxiv_lxxxv_guardrail/STABLE_LXXXIII_MDDC-MEASUREMENT.pdf mddc_latex/MDDC-MEASUREMENT.pdf
```

Then resync the Windows preview path.

## Promotion Decision

Updated: 2026-06-25 09:13:00 +08:00

Claude Opus 4.8 reviewed the LXXXIV/LXXXV candidate and recommended promotion to stable.

Review result:

- `should_promote_candidate_to_stable`: `true`
- Direct SCI acceptance probability: `27%`
- SCI major-revision-or-better probability: `74%`
- Post-revision SCI acceptance probability: `57%`
- TIFS/top-journal probability: `9%`
- Still below 50% direct SCI acceptance.

Required edits were applied before promotion:

- LXXXIV is now explicitly described as a verification-predicate stress test, not a discovered classifier capability.
- LXXXV recalibration rows are explicitly described as a re-expression of LXXXI operating-curve selection, not a second independent dataset result.
- The 0.249 abstention/validation-debt rate under 50% provenance dropout is carried into Discussion and Threats to Validity.

Promoted stable files:

- PDF: `PROMOTED_STABLE_LXXXIV_LXXXV_MDDC-MEASUREMENT.pdf`
- TeX: `PROMOTED_STABLE_LXXXIV_LXXXV_MDDC-MEASUREMENT.tex`
- PDF SHA256: `f6aeb40bca755157381a1aec0b2c8d3bf0df51a9b172bdd6a42ef285542fb3cb`
- TeX SHA256: `03b7fb0e8ac42303f686014fa052d482ac4757e32f898db5d4840557dd297c45`

Windows promoted stable preview:

- `D:\lunwen\MDDC_Preview\latest\MDDC-MEASUREMENT-STABLE-lxxxiv-lxxxv-promoted-20260625.pdf`
- Current alias: `D:\lunwen\MDDC_Preview\latest\MDDC-MEASUREMENT.pdf`
