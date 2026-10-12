"""
cve_pipeline_dag.py
---------------------
Daily batch pipeline (the "batch lane" of the architecture):

    fetch_recent_cves -> load_to_bigquery -> prepare_dbt -> dbt_seed -> dbt_run -> dbt_test

1. fetch_recent_cves  asks NVD for CVEs created/modified in the last few days
                      and writes them to a temporary CSV.
2. load_to_bigquery   MERGEs that CSV into the raw table by cve_id (inserts new
                      CVEs, updates changed ones, never duplicates).
3. prepare_dbt        copies the dbt project to /tmp (the mounted folder is not
                      writable inside the container) and installs dbt packages.
4. dbt_seed/run/test  loads the CWE -> OWASP/ATLAS mapping, rebuilds staging +
                      marts, then checks data quality. If a test fails the DAG
                      turns red instead of silently shipping bad data.

The big historical load (2023 -> today) is done ONCE by hand, see the README.
This DAG only keeps the warehouse fresh afterwards.

Settings come from environment variables set in docker/docker-compose.yml
(from docker/.env): GCP_PROJECT_ID, BQ_RAW_DATASET, BQ_DBT_DATASET, NVD_API_KEY.
"""

import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

from airflow import DAG
from airflow.operators.bash import BashOperator
from airflow.operators.python import PythonOperator

# the ingestion/ folder is mounted into the containers (see docker-compose.yml)
sys.path.append("/opt/airflow/ingestion")

from fetch_nvd import fetch_modified, write_csv  # noqa: E402
from load_to_bigquery import load_csv_to_bigquery  # noqa: E402

GCP_PROJECT_ID = os.environ["GCP_PROJECT_ID"]
BQ_RAW_DATASET = os.environ.get("BQ_RAW_DATASET", "cve_raw")
LOOKBACK_DAYS = int(os.environ.get("CVE_LOOKBACK_DAYS", "3"))  # overlap makes missed days harmless

INCOMING_CSV = Path("/tmp/cve_incoming.csv")
DBT = "/home/airflow/dbt_venv/bin/dbt"  # dbt lives in its own virtualenv (see docker/Dockerfile)
DBT_DIR = "/tmp/dbt_cve"

default_args = {
    "owner": "cve-intel-team",
    "retries": 2,
    "retry_delay": timedelta(minutes=5),
}


def _fetch_recent_cves(**_):
    rows = fetch_modified(days=LOOKBACK_DAYS)
    write_csv(rows, INCOMING_CSV)
    print(f"Fetched {len(rows)} CVEs created/modified in the last {LOOKBACK_DAYS} days")


def _load_to_bigquery(**_):
    load_csv_to_bigquery(INCOMING_CSV, GCP_PROJECT_ID, BQ_RAW_DATASET, "raw_cves", mode="merge")


with DAG(
    dag_id="cve_pipeline_batch",
    description="Daily: NVD -> BigQuery (merge) -> dbt seed/run/test",
    default_args=default_args,
    schedule="@daily",
    start_date=datetime(2026, 1, 1),
    catchup=False,
    max_active_runs=1,
    tags=["cve", "batch"],
) as dag:

    fetch_recent_cves = PythonOperator(task_id="fetch_recent_cves", python_callable=_fetch_recent_cves)

    load_to_bigquery = PythonOperator(task_id="load_to_bigquery", python_callable=_load_to_bigquery)

    prepare_dbt = BashOperator(
        task_id="prepare_dbt",
        bash_command=f"rm -rf {DBT_DIR} && cp -r /opt/airflow/dbt_cve {DBT_DIR} && cd {DBT_DIR} && {DBT} deps --profiles-dir .",
    )

    dbt_seed = BashOperator(task_id="dbt_seed", bash_command=f"cd {DBT_DIR} && {DBT} seed --profiles-dir .")
    dbt_run = BashOperator(task_id="dbt_run", bash_command=f"cd {DBT_DIR} && {DBT} run --profiles-dir .")
    dbt_test = BashOperator(task_id="dbt_test", bash_command=f"cd {DBT_DIR} && {DBT} test --profiles-dir .")

    fetch_recent_cves >> load_to_bigquery >> prepare_dbt >> dbt_seed >> dbt_run >> dbt_test
