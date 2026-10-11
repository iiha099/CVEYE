"""
config.py
----------
One place that reads settings (from the repo-root `.env` file or from real
environment variables) so every script agrees on names.

Settings (all optional except GCP_PROJECT_ID when you talk to BigQuery):
    NVD_API_KEY                      free key from nvd.nist.gov (much faster pulls)
    GCP_PROJECT_ID                   your Google Cloud *Project ID* (not the name)
    GOOGLE_APPLICATION_CREDENTIALS   path to the service-account JSON key
    BQ_RAW_DATASET                   dataset for the raw table      (default: cve_raw)
    BQ_DBT_DATASET                   dataset dbt builds into         (default: cve_dbt)
    BQ_LOCATION                      dataset location                (default: US)
"""

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

try:  # python-dotenv is optional (it is not needed inside Airflow)
    from dotenv import load_dotenv

    load_dotenv(ROOT / ".env")
except ImportError:
    pass

NVD_API_KEY = os.getenv("NVD_API_KEY") or None
GCP_PROJECT_ID = os.getenv("GCP_PROJECT_ID")
# BQ_DATASET is accepted as an older name for the raw dataset.
BQ_RAW_DATASET = os.getenv("BQ_RAW_DATASET") or os.getenv("BQ_DATASET") or "cve_raw"
BQ_DBT_DATASET = os.getenv("BQ_DBT_DATASET") or "cve_dbt"
BQ_LOCATION = os.getenv("BQ_LOCATION") or "US"

# A relative key path in .env is resolved from the repo root, so scripts work
# no matter which folder you run them from.
_creds = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
if _creds and not os.path.isabs(_creds):
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = str((ROOT / _creds).resolve())
