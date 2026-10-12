#!/usr/bin/env bash
# Runs dbt with the settings from .env, from anywhere:
#   ./run_dbt.sh deps      (once: installs dbt_utils)
#   ./run_dbt.sh seed      (loads the CWE -> OWASP/ATLAS mapping)
#   ./run_dbt.sh run       (builds staging + marts)
#   ./run_dbt.sh test      (data-quality checks)
set -euo pipefail
cd "$(dirname "$0")"
if [ -f .env ]; then
  set -a; source .env; set +a
fi
: "${GCP_PROJECT_ID:?GCP_PROJECT_ID is not set (put it in .env)}"
: "${GOOGLE_APPLICATION_CREDENTIALS:?GOOGLE_APPLICATION_CREDENTIALS is not set (put it in .env)}"
export GOOGLE_APPLICATION_CREDENTIALS="$(realpath "$GOOGLE_APPLICATION_CREDENTIALS")"
export BQ_RAW_DATASET="${BQ_RAW_DATASET:-${BQ_DATASET:-cve_raw}}"
export BQ_DBT_DATASET="${BQ_DBT_DATASET:-cve_dbt}"
cd dbt_cve
dbt "$@" --profiles-dir .
