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
# If .env did not name the key, it came from the shell and may be left over from
# unrelated work: such a key authenticates fine and only fails later as a 403 on
# this project. Stop now, with a message that says which key and why.
if ! grep -q '^GOOGLE_APPLICATION_CREDENTIALS=' .env 2>/dev/null; then
  key_project="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("project_id",""))' \
    "$GOOGLE_APPLICATION_CREDENTIALS" 2>/dev/null || true)"
  if [ -n "$key_project" ] && [ "$key_project" != "$GCP_PROJECT_ID" ]; then
    echo "Refusing $GOOGLE_APPLICATION_CREDENTIALS: it is a key for project $key_project," >&2
    echo "not $GCP_PROJECT_ID. Set GOOGLE_APPLICATION_CREDENTIALS in .env to use it anyway." >&2
    exit 1
  fi
fi
export BQ_RAW_DATASET="${BQ_RAW_DATASET:-${BQ_DATASET:-cve_raw}}"
export BQ_DBT_DATASET="${BQ_DBT_DATASET:-cve_dbt}"
cd dbt_cve
dbt "$@" --profiles-dir .
