# CVE Threat Intelligence Dashboard

Streamlit dashboard for CVE analytics and patch prioritization.

## Features

- Live BigQuery analytics for CVEs published from 2023 onward
- Severity, vendor, CWE, AI/LLM, and OWASP/ATLAS views
- Patch Priority Queue (P1-P4)
- Local synthetic CSV fallback if BigQuery is unavailable

## Local setup

From the repository root:

1. Install dashboard dependencies:
   python -m pip install -r dashboard/requirements.txt

2. Authenticate using Google Cloud Application Default Credentials:
   gcloud auth application-default login

3. Configure the root .env file:
   GCP_PROJECT_ID=cve-threat-intelligence-de
   BQ_DBT_DATASET=cve_dbt

4. Run:
   python -m streamlit run dashboard/app.py

## Docker setup

Authenticate with Google Cloud first.

Set CVE_ADC_PATH to the absolute path of your local
application_default_credentials.json file.

Windows PowerShell:
    $env:CVE_ADC_PATH = Join-Path $env:APPDATA "gcloud\application_default_credentials.json"

Linux:
    export CVE_ADC_PATH="$HOME/.config/gcloud/application_default_credentials.json"

Run from the repository root:
    docker compose -f docker/compose.dashboard.yml up --build -d

Open:
    http://localhost:8503

The credentials file is mounted read-only at runtime.
Do not commit credentials, .env files, or service-account keys.

## Risk Mart integration

The Patch Priorities tab expects:
    cve_dbt.fct_cve_daily_risk

Expected columns:
    snapshot_date
    cve_id
    severity_score
    epss_score
    in_kev
    affects_our_assets
    priority_tier

The Risk Mart is now available in BigQuery. The Patch Priorities tab reads the latest snapshot.

## Current limitations

- KEV and EPSS use real public vulnerability data.
- Asset exposure is simulated, not actual company data.
- P1-P4 thresholds are project-defined, not an official standard.
- Feed loading is currently manual; scheduled refresh is not implemented.
- The risk table is replaced on each dbt run; historical snapshots are not preserved.
- BigQuery access requires appropriate IAM permissions.
