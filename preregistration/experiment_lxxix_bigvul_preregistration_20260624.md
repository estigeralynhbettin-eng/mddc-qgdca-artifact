# Experiment LXXIX BigVul Cross-Dataset Replication Pre-Registration

Generated: 2026-06-24 15:25:00 +08:00

## Purpose

LXXIX tests whether the MDDC gate-accounting pattern observed on ASRDataset and
CVEfixes replicates on a third public dataset, BigVul.

## Data

- Dataset: BigVul / MSR 2020 C/C++ vulnerability CSV.
- Source URL:
  - `https://raw.githubusercontent.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset/master/all_c_cpp_release2.0.csv`
- Local path:
  - `/root/mddc/empirical_validation/data/raw/bigvul/all_c_cpp_release2.0.csv`
- SHA256:
  - `02970f6d07f22dcff4f03983a89b1fd68bebb63289eaa98f4c7e11d6218d907c`

## Frozen Gate

The gate follows the LXXIV CVEfixes-style patch-context protocol:

- reference side: `cve_id`, `cwe_id`, `summary`, `vulnerability_classification`;
- candidate side: `commit_message`, `files_changed.patch`;
- `structural_only_gate`: CVE, commit id, and patch text are available;
- `category_gate`: structural gate plus inferred vulnerability category appears
  in patch/commit context;
- `strict_mddc_gate`: category gate plus token coverage `>= 0.10`.

The `0.10` token coverage threshold is inherited from LXXIV and is not tuned
after inspecting BigVul results.

## Negative Controls

Controls use fixed random seed `20260624`, `200` trials, and up to `1500` pairs
per trial:

- `any_deranged`;
- `cross_category`;
- `same_category_different_cve`.

## Success Criteria

The BigVul replication is considered positive only if both hold:

- same-category false-admission reduction of strict MDDC gate versus
  structural-only baseline is `>= 60%`;
- strict true-pair admission Wilson lower bound is `>= 0.45`.

## Boundary

This is a patch-context replication. It does not prove ASR rule semantic
correctness, human expert correctness, or deployment success.

