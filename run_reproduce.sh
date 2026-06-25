#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MDDC_ROOT="${MDDC_ROOT:-/root/mddc}"
export MDDC_ROOT
cd "$MDDC_ROOT"

python3 "$SCRIPT_DIR/scripts/experiment_lxxiv_cvefixes_independent_gate_replication.py"
python3 "$SCRIPT_DIR/scripts/experiment_lxxv_yield_threshold_activation_boundary.py"
python3 "$SCRIPT_DIR/scripts/experiment_lxxvi_threshold_sensitivity_and_calibration.py"
python3 "$SCRIPT_DIR/scripts/experiment_lxxvii_patch_differential_oracle.py"
python3 "$SCRIPT_DIR/scripts/experiment_lxxviii_external_baseline_system_comparison.py"
python3 "$SCRIPT_DIR/scripts/experiment_lxxix_bigvul_cross_dataset_replication.py"
python3 "$SCRIPT_DIR/scripts/experiment_lxxx_matched_recall_cost_baseline.py"
python3 "$SCRIPT_DIR/scripts/experiment_lxxxi_operating_curve_selection.py"
python3 "$SCRIPT_DIR/scripts/experiment_lxxxii_cost_model_sensitivity.py"
python3 "$SCRIPT_DIR/scripts/experiment_lxxxiii_hf_external_component_ablation.py"
python3 "$SCRIPT_DIR/scripts/experiment_lxxxiv_provenance_stress_test.py"
python3 "$SCRIPT_DIR/scripts/experiment_lxxxv_internal_accounting_ablation.py"
if [[ "${RUN_PAID_GLM:-0}" == "1" ]]; then
  python3 "$SCRIPT_DIR/scripts/experiment_lxxxvi_glm_oracle_calibration.py"
else
  echo "Skipping LXXXVI paid GLM replay. Set RUN_PAID_GLM=1 with GLM_API_KEY to rerun it."
fi
python3 "$SCRIPT_DIR/scripts/make_mainline_qgdca_figures.py"

echo "QG-DCA reproducibility run completed."
