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

import json
import os
import sys
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
    _creds = str((ROOT / _creds).resolve())
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = _creds


def _names_key() -> bool:
    """True if .env set the key path itself, rather than it coming from the shell."""
    try:
        from dotenv import dotenv_values
    except ImportError:
        return False
    return bool((dotenv_values(ROOT / ".env").get("GOOGLE_APPLICATION_CREDENTIALS") or "").strip())


# A key left over in the shell for an unrelated project authenticates fine and
# only fails later, as a 403 on this project. Drop it unless .env named it
# deliberately - in which case cross-project access may well have been granted.
if _creds and GCP_PROJECT_ID and not _names_key() and os.path.exists(_creds):
    try:
        _key_project = json.loads(Path(_creds).read_text()).get("project_id")
    except (OSError, ValueError):
        _key_project = None
    if _key_project and _key_project != GCP_PROJECT_ID:
        print(
            f"Ignoring GOOGLE_APPLICATION_CREDENTIALS={_creds}: it is a key for "
            f"project {_key_project}, not {GCP_PROJECT_ID}. Set it in .env to force it.",
            file=sys.stderr,
        )
        os.environ.pop("GOOGLE_APPLICATION_CREDENTIALS", None)
