# CVE Threat Intelligence Pipeline

A data pipeline that collects security vulnerabilities (CVEs) from NIST's official **NVD** database and answers four questions on an interactive dashboard:

1. Which **vendors** are most affected, and how severe are their vulnerabilities?
2. How do **severity trends** change over time?
3. Which **weakness types (CWE)** keep coming back?
4. How is the threat landscape shifting toward **AI / LLM systems**, and how do these CVEs map to the **OWASP Top 10 for LLM Applications** and **MITRE ATLAS**?

Final project - Le Wagon Data Engineering bootcamp.

**Stack:** Python · NVD API 2.0 · Google BigQuery · dbt · Apache Airflow (Docker) · Streamlit

---

## 1. Architecture

```mermaid
flowchart LR
    NVD[(NVD API 2.0)] -->|fetch_nvd.py| B[data/bronze<br/>raw JSON pages]
    B -->|flatten| C[data/cves_raw.csv]
    C -->|load_to_bigquery.py| R[(BigQuery<br/>cve_raw.raw_cves)]
    R -->|dbt| S[stg_cves]
    S -->|dbt| M[(6 marts in cve_dbt)]
    M --> D[Streamlit dashboard]
    A{{Airflow - daily}} -. incremental fetch + MERGE .-> R
    A -. dbt seed / run / test .-> M
```

| Layer | Where | What it holds |
|---|---|---|
| Bronze | `data/bronze/*.json` | Raw API pages, untouched (lets you re-process without re-calling NVD) |
| Raw | BigQuery `cve_raw.raw_cves` | One flat row per CVE (10 columns, see below) |
| Staging | dbt view `stg_cves` | De-duplicated, cleaned, `is_ai_related` flag |
| Marts | dbt tables in `cve_dbt` | Analysis-ready tables the dashboard reads |

### The data contract (columns of `raw_cves`)

`cve_id, published_date, last_modified_date, vuln_status, severity, cvss_score, vendor, product, cwe_id, description`

If you add a column, update it everywhere: `ingestion/fetch_nvd.py` (`COLUMNS`, `flatten_cve`) → `ingestion/load_to_bigquery.py` (`SCHEMA`) → `dbt_cve/models/staging/sources.yml` → `stg_cves.sql`.

### dbt marts

| Mart | Grain | Used for |
|---|---|---|
| `mart_severity_trends` | year × severity | severity over time |
| `mart_vendor_severity` | vendor × year | top vendors |
| `mart_cwe_trends` | year × CWE | most common weaknesses |
| `mart_ai_trends` | year | AI/LLM-related count and share |
| `mart_ai_cve_list` | CVE (latest 500) | detail table |
| `mart_owasp_atlas` | year × OWASP category × ATLAS technique | threat-framework mapping |

---

## 2. Repository layout

```
├── ingestion/        fetch_nvd.py · load_to_bigquery.py · config.py · generate_mock_data.py
├── dbt_cve/          models/{staging,marts} · seeds/cwe_owasp_atlas.csv · macros/ai_regex.sql · tests/
├── dags/             cve_pipeline_dag.py   (Airflow)
├── docker/           Dockerfile · docker-compose.yml · .env.sample
├── dashboard/        app.py · build_sample_marts.py
├── data/sample/      small SYNTHETIC CSVs so the dashboard runs with no cloud
├── docs/             ARCHITECTURE.md
├── run_dbt.sh        runs dbt with the settings from .env
├── .env.example      copy to .env
└── requirements.txt
```

---

## 3. Quick demo (no cloud account, 2 minutes)

The CSVs in `data/sample/` are **synthetic** (generated, not real findings). They exist so the dashboard always runs, e.g. as a safety net before the presentation.

```bash
python -m venv venv-dashboard
source venv-dashboard/bin/activate        # Windows: venv-dashboard\Scripts\activate
pip install -r dashboard/requirements.txt
streamlit run dashboard/app.py
```

The caption at the top says **"Local sample data (synthetic)"**. Regenerate the samples any time with
`python ingestion/generate_mock_data.py` then `python dashboard/build_sample_marts.py`.

---

## 4. Full setup - real NVD data + BigQuery

### 4.1 Prerequisites
- Python 3.10+ and Git.
- A free **NVD API key**: <https://nvd.nist.gov/developers/request-an-api-key> (click the activation link in the email!).
- A Google Cloud project with BigQuery enabled, two datasets in the **same location** (e.g. `US`): `cve_raw` and `cve_dbt`.
- A **service account** with role *BigQuery Admin* (or *Data Editor* + *Job User*) and a JSON key downloaded.

### 4.2 Configure
```bash
cp .env.example .env        # then edit it: NVD key, project ID, key path
python -m venv venv
source venv/bin/activate    # Windows: venv\Scripts\activate
pip install -r requirements.txt
```
Put the key file in the repo root (e.g. `gcp-key.json`) or in `keys/`, and set `GOOGLE_APPLICATION_CREDENTIALS` in `.env` to its path. Both are gitignored.

### 4.3 Load the history (run once)
```bash
python ingestion/fetch_nvd.py --start-year 2023     # downloads to data/bronze, then writes data/cves_raw.csv
python ingestion/load_to_bigquery.py --mode replace  # creates cve_raw.raw_cves
```
- The download resumes where it stopped if interrupted - just run the same command again.
- Already have JSON files in `data/bronze`? Skip the download: `python ingestion/fetch_nvd.py --flatten-only --start-year 2023`.
- Row counts depend on the start year (about 199k CVEs from 2023, 168k from 2024, 127k from 2025 as of October 2026).

### 4.4 Transform with dbt
```bash
./run_dbt.sh deps     # installs dbt_utils (once)
./run_dbt.sh seed     # loads the CWE -> OWASP/ATLAS mapping
./run_dbt.sh run      # builds stg_cves + 6 marts in cve_dbt
./run_dbt.sh test     # data-quality checks
```

### 4.5 Dashboard on live data
Make sure `.env` has `GCP_PROJECT_ID`, then:
```bash
streamlit run dashboard/app.py
```
The caption changes to **"BigQuery (live)"**. If BigQuery fails, the app shows a warning and falls back to the synthetic sample.

> Tip: install the dashboard in its own virtualenv (`venv-dashboard`), as in section 3, to avoid package conflicts with dbt.

### 4.6 Automate with Airflow (daily incremental)
```bash
cd docker
cp .env.sample .env                                  # set GCP_PROJECT_ID (+ NVD_API_KEY)
mkdir -p ../keys && cp /path/to/key.json ../keys/service-account.json
chmod 644 ../keys/service-account.json               # the container user must be able to read it
docker compose build                                 # first time, ~3-5 min (installs dbt)
docker compose up airflow-init                       # first time only
docker compose up -d
```
Open <http://localhost:8080> (user `airflow`, password `airflow`), switch the **`cve_pipeline_batch`** DAG on, or press *Trigger DAG*.

Each run: fetch CVEs created/modified in the last 3 days → **MERGE** into `raw_cves` (no duplicates) → `dbt seed` → `dbt run` → `dbt test`. Run section 4.3 first so the table already holds the history.

---

## 5. Design decisions and limitations (good to mention in the presentation)

- **Unscored CVEs are kept.** NVD has a large scoring backlog, so many recent CVEs have no CVSS score yet. Dropping them would make 2024-2026 look milder than reality, so they appear as `UNSCORED`.
- **Vendor = first CPE entry.** Simple and good enough for ranking, but a CVE affecting several vendors is counted once, and CVEs without CPE data are `unknown` (excluded from the vendor chart).
- **"AI-related" is a keyword heuristic** on the description (`dbt_cve/macros/ai_regex.sql`). It is transparent and tunable, but not ground truth; expect some false positives and misses.
- **CWE → OWASP LLM / ATLAS mapping is an analytical choice** (`dbt_cve/seeds/cwe_owasp_atlas.csv`). It links the *weakness type* of a CVE to the closest framework category; it does not claim the CVE is an LLM attack. Review and refine it against the official OWASP and MITRE ATLAS pages.
- **The current year is partial**, so compare it with earlier years carefully.
- **Rejected CVEs** are removed in staging.

---

## 6. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Fetch is very slow | No `NVD_API_KEY` | Add the key to `.env` (the script warns at startup) |
| `403`/`429` from NVD | Rate limit | The script retries automatically; wait or add an API key |
| `GCP_PROJECT_ID is not set` | Missing `.env` value | Edit `.env` (project **ID**, not the name) |
| `Dataset ... not found` / location error | Dataset in another location | Create `cve_raw` and `cve_dbt` in the same location as `BQ_LOCATION` |
| `403 Access Denied` in BigQuery | Service account lacks a role | Grant *BigQuery Admin* (or Data Editor + Job User) |
| `dbt: command not found` | venv not active | `source venv/bin/activate` and `pip install -r requirements.txt` |
| dbt "Env var required but not provided" | Not using the helper | Run dbt through `./run_dbt.sh ...` |
| Dashboard says "Local sample data" | `GCP_PROJECT_ID` missing, or BigQuery error | Read the yellow warning at the top of the page |
| Airflow DAG fails at `load_to_bigquery` | Key not readable in container | `chmod 644 keys/service-account.json`, restart |
| Airflow DAG import error | Image not rebuilt | `docker compose build` then `docker compose up -d` |

---

## 7. Future extension

A real-time lane with Google Pub/Sub (publisher pushes new CVEs, a subscriber writes them to `raw_cves`) can sit next to the batch lane. It is **not implemented**; the batch pipeline above is complete on its own.
