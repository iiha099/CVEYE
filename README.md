
# CVEYE — CVE Threat Intelligence Pipeline

A daily data pipeline that collects vulnerabilities (CVEs) from **NVD**, enriches them with real exploitation signals from **CISA KEV** and **FIRST EPSS**, and shows the results in an interactive **Streamlit** dashboard. It answers five questions:

1. Which **vendors** are most affected, and how severe are their vulnerabilities?
2. How do **severity trends** change over time?
3. Which **weakness types (CWE)** keep coming back?
4. How are **AI / LLM** vulnerabilities growing, and how do they map to the **OWASP Top 10 for LLM Applications** and **MITRE ATLAS**?
5. Which CVEs should be **patched first** (P1–P4)?

**Stack:** Python · NVD API 2.0 · CISA KEV · FIRST EPSS · Google BigQuery · dbt · Apache Airflow (Docker) · Streamlit


---

## Architecture
<img width="3465" height="1185" alt="cve_pipeline_dfd" src="https://github.com/user-attachments/assets/f5f37e3b-9dd4-4592-8ef9-512822e6ce98" />

| Stage | What happens |
|---|---|
| **Data sources** | NVD API 2.0, CISA KEV, FIRST EPSS — all refreshed daily |
| **Ingestion** | `fetch_nvd.py` saves raw JSON to `data/bronze`, then `load_to_bigquery.py` loads it. `load_risk_feeds.py` (`load_kev()`, `load_epss()`) loads the two risk feeds |
| **Raw storage** | BigQuery dataset `cve_raw`: `raw_cves`, `raw_kev`, `raw_epss` |
| **Transformation** | dbt: `stg_cves` (view) + seeds (reference tables) → marts |
| **Analytics marts** | BigQuery dataset `cve_dbt`: 6 marts + `fct_cve_daily_risk` |
| **Presentation** | Streamlit dashboard reads the marts directly from BigQuery |

Airflow orchestrates the whole chain once a day.

**Load behaviour:** `raw_cves` is upserted with `MERGE` (no duplicates). `raw_kev` and `raw_epss` are full snapshots and are replaced on every run.

---

## Data model

`stg_cves` keeps one row per CVE (latest modification), published **2023-01-01 or later**. **Rejected** CVEs are removed; **unscored** CVEs are kept as `UNSCORED`. It also adds the `is_ai_related` flag.

| Mart | Grain |
|---|---|
| `mart_severity_trends` | year × severity |
| `mart_vendor_severity` | vendor × year |
| `mart_cwe_trends` | year × CWE |
| `mart_owasp_atlas` | year × OWASP LLM category × ATLAS technique |
| `mart_ai_trends` | year |
| `mart_ai_cve_list` | the 500 most recent AI-related CVEs |
| `fct_cve_daily_risk` | one row per CVE (NVD + KEV + EPSS + simulated assets) → priority tier |

**Patch priority (P1–P4)** is a transparent project rule, not an official standard (see `dbt_cve/models/marts/fct_cve_daily_risk.sql`):

| Tier | Rule |
|---|---|
| **P1** | affects our (simulated) assets **and** (in KEV **or** EPSS ≥ 0.50) |
| **P2** | in KEV, **or** affects our assets with (EPSS ≥ 0.10 **or** CVSS ≥ 9) |
| **P3** | EPSS ≥ 0.05 **or** CVSS ≥ 7 |
| **P4** | everything else |

`fct_cve_daily_risk` is rebuilt on every dbt run with `snapshot_date` = the run date; previous snapshots are not kept.

**Data quality:** dbt tests on staging and marts, enforced dbt contracts on all 7 mart tables, and a test that no CVE has a future publish date.

---

## Repository layout

```
├── ingestion/    fetch_nvd.py · load_to_bigquery.py · load_risk_feeds.py · config.py · generate_mock_data.py
├── dbt_cve/      models/{staging,marts} · seeds/ · macros/ai_regex.sql · tests/
├── dags/         cve_pipeline_dag.py (Airflow)
├── docker/       Dockerfile · docker-compose.yml (Airflow) · Dockerfile.dashboard · compose.dashboard.yml
├── dashboard/    app.py · risk_queue.py · theme.py · gcp_auth.py · build_sample_marts.py
├── data/sample/  small SYNTHETIC CSVs so the dashboard runs without cloud access
├── docs/         architecture diagram
├── keys/         put your service-account JSON here (git-ignored)
├── pitch.md      speaker script for the final presentation
├── run_dbt.sh    runs dbt with the settings from .env
├── .env.example  template for .env
└── requirements.txt
```

---

## Quick demo (no cloud account)

The CSVs in `data/sample/` are **synthetic**, not real findings.

```bash
python -m venv venv-dashboard
source venv-dashboard/bin/activate        # Windows: venv-dashboard\Scripts\activate
pip install -r dashboard/requirements.txt
streamlit run dashboard/app.py
```

The page caption shows **"Local sample data (synthetic)"**. The *Patch priorities* tab needs live BigQuery data and is not available in this mode.

---

## Full setup (real data + BigQuery)

**Prerequisites:** Python 3.10+, Git, a free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key), a Google Cloud project with BigQuery enabled, and a service-account JSON key with BigQuery access (e.g. *BigQuery Admin*, or *Data Editor* + *Job User*).

### 1. Configure
```bash
cp .env.example .env     # set NVD_API_KEY, GCP_PROJECT_ID, GOOGLE_APPLICATION_CREDENTIALS
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```
Datasets `cve_raw` and `cve_dbt` are used (default location `US`, set with `BQ_LOCATION`).

### 2. Load history (once)
```bash
python ingestion/fetch_nvd.py --start-year 2023
python ingestion/load_to_bigquery.py --mode replace
```
An interrupted download resumes when you run the same command again.

### 3. Load KEV + EPSS
```bash
python ingestion/load_risk_feeds.py
```
Downloads both feeds and replaces `raw_kev` / `raw_epss`. After this, Airflow keeps them fresh.

### 4. Build the marts
```bash
./run_dbt.sh deps && ./run_dbt.sh seed && ./run_dbt.sh run && ./run_dbt.sh test
```

### 5. Run the dashboard
```bash
streamlit run dashboard/app.py          # caption shows "BigQuery (live)"
```
If BigQuery fails, the app shows a warning and falls back to the synthetic sample.

Docker alternative: set `CVE_ADC_PATH` to your local Google application-default-credentials file, then
`docker compose -f docker/compose.dashboard.yml up --build -d` → <http://localhost:8503>.

### 6. Automate with Airflow
```bash
cd docker
cp .env.bak .env          # fill in GCP_PROJECT_ID, NVD_API_KEY and the three secrets
mkdir -p ../keys && cp /path/to/key.json ../keys/service-account.json
chmod 644 ../keys/service-account.json
docker compose build
docker compose up airflow-init
docker compose up -d
```
Open <http://localhost:8080> — user `airflow`, password = `AIRFLOW_ADMIN_PASSWORD` from `docker/.env`. Enable the **`cve_pipeline_batch`** DAG.

**DAG (`@daily`, `max_active_runs=1`, 2 retries):**
```
fetch_recent_cves → load_to_bigquery ─┐
load_kev ─────────────────────────────┼→ prepare_dbt → dbt_seed → dbt_run → dbt_test
load_epss ────────────────────────────┘
```

Each run fetches CVEs created/modified in the last 3 days, merges them into `raw_cves`, refreshes KEV and EPSS, then rebuilds and tests the dbt models. Run steps 2 and 3 first so the raw tables exist.

---

## Design decisions and limitations

- **Unscored CVEs are kept.** NVD has a scoring backlog; dropping them would make recent years look milder than they are.
- **Vendor = first CPE entry.** A CVE affecting several vendors is counted once; CVEs without CPE data are `unknown` and excluded from the vendor mart.
- **"AI-related" is a keyword heuristic** on the description (`dbt_cve/macros/ai_regex.sql`), not ground truth.
- **CWE → OWASP LLM / MITRE ATLAS mapping is an analytical choice** (`dbt_cve/seeds/cwe_owasp_atlas.csv`, 11 CWEs). It links a CVE's weakness type to the closest framework category; it does not claim the CVE is an LLM attack.
- **Asset exposure is simulated** (`dbt_cve/seeds/simulated_assets.csv`, 5 demo assets), not a real inventory.
- **P1–P4 thresholds are a judgment call**, not an official standard.
- **The current year is partial** — compare it carefully with earlier years.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| NVD fetch is very slow | Add `NVD_API_KEY` to `.env` |
| `GCP_PROJECT_ID is not set` | Set the project **ID** (not the name) in `.env` |
| BigQuery `403 Access Denied` | Give the service account *BigQuery Admin* (or *Data Editor* + *Job User*) |
| `dbt: command not found` / missing env var | Activate the venv and run dbt through `./run_dbt.sh` |
| Dashboard says "Local sample data" | `GCP_PROJECT_ID` missing or BigQuery error — read the warning at the top of the page |
| Patch priorities tab unavailable | Run steps 3 and 4 so `fct_cve_daily_risk` exists |
| Airflow DAG fails when loading to BigQuery | `chmod 644 keys/service-account.json`, then restart |

---
