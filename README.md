# CVEYE — CVE Threat Intelligence Pipeline

A daily data pipeline that collects security vulnerabilities (CVEs) from NIST's **NVD**, enriches them with **CISA KEV** and **FIRST EPSS** exploitation signals, models them with **dbt** in **BigQuery**, and serves them in a **Streamlit** dashboard that answers six questions:

1. Which **vendors** are most affected, and how severe are their vulnerabilities?
2. How do **severity trends** change over time?
3. Which **weakness types (CWE)** keep coming back, and how is that mix shifting year to year?
4. How is the threat landscape shifting toward **AI / LLM systems**?
5. How do CVE weaknesses map to the **OWASP Top 10 for LLM Applications** and **MITRE ATLAS**?
6. Given real exploitation signals (KEV, EPSS) and a *simulated* asset inventory, which CVEs should be **patched first** (P1–P4)?

Final project — Le Wagon Data Engineering bootcamp.

**Stack:** Python · NVD API 2.0 · CISA KEV · FIRST EPSS · Google BigQuery · dbt · Apache Airflow (Docker) · Streamlit

---

## 1. Architecture

![CVE pipeline architecture](docs/cve_pipeline_dfd.png)

Apache Airflow orchestrates the daily run. Data flows left to right through six stages:

| # | Stage | What happens |
|---|---|---|
| 01 | **Data sources** | NVD API 2.0, CISA KEV and FIRST EPSS, all pulled daily |
| 02 | **Ingestion** | `fetch_nvd.py` + `load_to_bigquery.py` for NVD; `load_risk_feeds.py` (`load_kev()`, `load_epss()`) for KEV and EPSS |
| 03 | **Raw storage** | BigQuery dataset `cve_raw`: `raw_cves`, `raw_kev`, `raw_epss` |
| 04 | **Transformation** | dbt: `stg_cves` (view), two seeds, then `dbt run` builds the marts |
| 05 | **Analytics marts** | BigQuery dataset `cve_dbt`: six analytics marts + the risk fact `fct_cve_daily_risk` |
| 06 | **Presentation** | Streamlit dashboard reads the marts directly from BigQuery |

**About the Bronze layer.** The `data/bronze/` folder (raw NVD JSON pages) is used by the **one-time historical load** (section 4.3), where it makes the download resumable and re-processable without calling NVD again. The **daily Airflow run** is incremental: it fetches only recently modified CVEs, writes them to a temporary CSV, and `MERGE`s them into `raw_cves`, so it does not write to `data/bronze/`.

---

## 2. Data

### 2.1 Sources

| Source | Format | Loaded by | Refresh in the DAG |
|---|---|---|---|
| [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) | Paginated JSON API | `fetch_nvd.py` → `load_to_bigquery.py` | Daily, incremental: CVEs created/modified in the last 3 days, `MERGE` into `raw_cves` |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | JSON catalog of CVEs confirmed exploited in the wild | `load_risk_feeds.py` → `load_kev()` | Daily, full snapshot, table replaced (`WRITE_TRUNCATE`) |
| [FIRST EPSS](https://www.first.org/epss/) | Gzipped CSV, one exploit-probability score per CVE | `load_risk_feeds.py` → `load_epss()` | Daily, full snapshot, table replaced (`WRITE_TRUNCATE`) |

Only CVEs **published from 2023-01-01 onward** are kept (`stg_cves` filters on this date).

### 2.2 Raw tables (`cve_raw`)

| Table | Columns |
|---|---|
| `raw_cves` | `cve_id, published_date, last_modified_date, vuln_status, severity, cvss_score, vendor, product, cwe_id, description` |
| `raw_kev` | `cve_id, date_added, vendor_project, product` |
| `raw_epss` | `cve_id, epss_score, percentile, score_date` |

If you add a column to `raw_cves`, update it everywhere: `ingestion/fetch_nvd.py` (`COLUMNS`, `flatten_cve`) → `ingestion/load_to_bigquery.py` (`SCHEMA`) → `dbt_cve/models/staging/sources.yml` → `stg_cves.sql`.

### 2.3 dbt models (`cve_dbt`)

| Model | Type | Grain | Purpose |
|---|---|---|---|
| `stg_cves` | view | one row per CVE | Latest version of each CVE, rejected CVEs removed, `is_ai_related` flag added |
| `mart_severity_trends` | table | year × severity | Severity mix over time |
| `mart_vendor_severity` | table | vendor × year | Most affected vendors (excludes `unknown`) |
| `mart_cwe_trends` | table | year × CWE | Most common weakness types over time |
| `mart_ai_trends` | table | year | Count and share of AI/LLM-related CVEs |
| `mart_ai_cve_list` | table | CVE (latest 500) | Detail table of recent AI/LLM-related CVEs |
| `mart_owasp_atlas` | table | year × OWASP LLM category × ATLAS technique | Threat-framework mapping via CWE |
| `fct_cve_daily_risk` | table | one row per CVE | Patch-priority tier P1–P4 (see 2.4) |

**Seeds** (reference tables loaded by `dbt seed`):

| Seed | Used by | Content |
|---|---|---|
| `cwe_owasp_atlas.csv` | `mart_cwe_trends`, `mart_owasp_atlas` | CWE → OWASP LLM / MITRE ATLAS mapping (11 CWEs) |
| `simulated_assets.csv` | `fct_cve_daily_risk` | A **simulated** asset inventory (5 demo assets) |

### 2.4 Patch priority rule (`fct_cve_daily_risk`)

The tier is a transparent, rule-based score evaluated top to bottom (first match wins). It is **a project-defined rule, not an official standard or a vendor risk score**:

| Tier | Rule |
|---|---|
| **P1** | Affects our (simulated) assets **and** (in KEV **or** EPSS ≥ 0.50) |
| **P2** | In KEV, **or** (affects our assets **and** (EPSS ≥ 0.10 **or** CVSS ≥ 9)) |
| **P3** | EPSS ≥ 0.05 **or** CVSS ≥ 7 |
| **P4** | Everything else |

Missing EPSS or CVSS values are treated as 0. The thresholds are a judgment call, defined in `dbt_cve/models/marts/fct_cve_daily_risk.sql`.

> The table is **rebuilt from scratch on every dbt run** with `snapshot_date = CURRENT_DATE()`. Only the latest snapshot exists; history is not preserved.

---

## 3. Repository layout

```
├── dags/             cve_pipeline_dag.py            Airflow DAG (cve_pipeline_batch)
├── ingestion/        fetch_nvd.py · load_to_bigquery.py · load_risk_feeds.py · config.py · generate_mock_data.py
├── dbt_cve/          models/{staging,marts} · seeds/ · macros/ai_regex.sql · tests/
├── dashboard/        app.py (main UI) · observatory.py (alternative UI) · risk_queue.py · gcp_auth.py · theme.py · build_sample_marts.py
├── docker/           Dockerfile · docker-compose.yml (Airflow) · Dockerfile.dashboard · compose.dashboard.yml
├── data/sample/      small SYNTHETIC CSVs so the dashboard runs with no cloud account
├── docs/             ARCHITECTURE.md · cve_pipeline_dfd.png
├── run_dbt.sh        runs dbt with the settings from .env
├── .env.example      template for the root .env
└── requirements.txt  ingestion + dbt dependencies (the dashboard has its own, see below)
```

---

## 4. Getting started

### 4.1 Quick demo (no cloud account, ~2 minutes)

The CSVs in `data/sample/` are **synthetic** (generated, not real findings). They are the dashboard's automatic fallback.

```bash
python -m venv venv-dashboard
source venv-dashboard/bin/activate        # Windows: venv-dashboard\Scripts\activate
pip install -r dashboard/requirements.txt
streamlit run dashboard/app.py
```

The page shows **"Local sample data (synthetic)"**. The Patch Priorities tab needs live BigQuery data and shows an info message on sample data, because a priority queue on synthetic numbers would not mean anything.

Regenerate the samples with:
```bash
python ingestion/generate_mock_data.py --rows 1200 --out data/sample/cves_raw.csv
python dashboard/build_sample_marts.py
```

### 4.2 Prerequisites for the full setup

- Python 3.10+ and Git. Docker (with Compose) for Airflow.
- A free **NVD API key**: <https://nvd.nist.gov/developers/request-an-api-key> (click the activation link in the email). Without a key the fetch is roughly 7× slower.
- A Google Cloud project with BigQuery enabled and a **service account** with the roles *BigQuery Data Editor* + *BigQuery Job User* (or *BigQuery Admin*), plus its JSON key.
- The datasets `cve_raw` and `cve_dbt` in the **same location** (default `US`). The ingestion scripts and dbt try to create them if the service account has permission; otherwise create them manually.

### 4.3 Configure and load the history (run once)

```bash
cp .env.example .env        # then edit it: NVD key, project ID, key path
python -m venv venv
source venv/bin/activate    # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Put your key file in `keys/` (for example `keys/service-account.json`) and set `GOOGLE_APPLICATION_CREDENTIALS=keys/service-account.json` in `.env`. Key files and `.env` are gitignored. **Never commit them.**

Then load the history once, and the risk feeds once, so the tables exist before the first Airflow run:

```bash
python ingestion/fetch_nvd.py --start-year 2023       # raw JSON -> data/bronze, then flat data/cves_raw.csv
python ingestion/load_to_bigquery.py --mode replace   # creates cve_raw.raw_cves
python ingestion/load_risk_feeds.py                   # creates cve_raw.raw_kev and cve_raw.raw_epss
```

- The download resumes where it stopped if interrupted: run the same command again.
- Already have JSON files in `data/bronze`? Skip the download with `python ingestion/fetch_nvd.py --flatten-only --start-year 2023`.
- `load_risk_feeds.py` downloads KEV and EPSS itself and replaces both tables each time it runs, so it is safe to re-run.

### 4.4 Transform with dbt

```bash
./run_dbt.sh deps     # installs dbt_utils (once)
./run_dbt.sh seed     # loads cwe_owasp_atlas and simulated_assets
./run_dbt.sh run      # builds stg_cves, the 6 marts and fct_cve_daily_risk
./run_dbt.sh test     # data-quality checks
```

### 4.5 Dashboard on live data

With `GCP_PROJECT_ID` set in `.env`:

```bash
streamlit run dashboard/app.py
```

The page shows **"BigQuery (live)"**. If BigQuery cannot be read, the app shows a warning naming the identity it used and falls back to the synthetic sample.

Credentials are resolved in this order: the key named in the repo-root `.env`, then an already-exported `GOOGLE_APPLICATION_CREDENTIALS` (this is how the container supplies its mounted key), then gcloud application-default credentials (`gcloud auth application-default login`).

> Tip: install the dashboard in its own virtualenv (`venv-dashboard`), as in 4.1, to avoid package conflicts with dbt.

### 4.6 Automate with Airflow (daily)

Complete 4.3 first so the raw tables already hold data.

```bash
cd docker
cp .env.example .env     # then fill in every value (see below)
mkdir -p ../keys && cp /path/to/key.json ../keys/service-account.json
chmod 644 ../keys/service-account.json    # the container user must be able to read it
docker compose build                      # first time, ~3-5 minutes (installs dbt)
docker compose up airflow-init            # first time only
docker compose up -d
```

`docker/.env` must define (Compose refuses to start without the four marked **required**):

| Variable | Notes |
|---|---|
| `GCP_PROJECT_ID` | **required**: your project **ID**, not its name |
| `POSTGRES_PASSWORD` | **required**: password of Airflow's metadata database |
| `AIRFLOW_SECRET_KEY` | **required**: random string for the webserver |
| `AIRFLOW_ADMIN_PASSWORD` | **required**: password of the Airflow `airflow` admin user (used by `airflow-init`) |
| `NVD_API_KEY` | strongly recommended |
| `BQ_RAW_DATASET`, `BQ_DBT_DATASET`, `BQ_LOCATION` | default to `cve_raw`, `cve_dbt`, `US` |

Generate strong random values, for example with `openssl rand -hex 24`.

Open <http://localhost:8080>, sign in as **`airflow`** with the `AIRFLOW_ADMIN_PASSWORD` you set, then switch the **`cve_pipeline_batch`** DAG on or press *Trigger DAG*.

### 4.7 Dashboard in Docker (optional)

```bash
export CVE_ADC_PATH="$HOME/.config/gcloud/application_default_credentials.json"   # Windows: see dashboard/README.md
docker compose -f docker/compose.dashboard.yml up --build -d
```

Open <http://localhost:8503>. The credentials file is mounted read-only. `docker/compose.dashboard.yml` sets `GCP_PROJECT_ID` to `cve-threat-intelligence-de`: edit it if you use another project.

---

## 5. The Airflow DAG

`cve_pipeline_batch` — schedule `@daily`, `catchup=False`, `max_active_runs=1`, 2 retries with a 5-minute delay.

```
fetch_recent_cves ──► load_to_bigquery ──┐
load_kev ────────────────────────────────┼──► prepare_dbt ──► dbt_seed ──► dbt_run ──► dbt_test
load_epss ───────────────────────────────┘
```

| Task | What it does |
|---|---|
| `fetch_recent_cves` | Asks NVD for CVEs created/modified in the last `CVE_LOOKBACK_DAYS` days (default 3) and writes a temporary CSV |
| `load_to_bigquery` | Loads the CSV into `raw_cves_incoming`, then `MERGE`s into `raw_cves` by `cve_id` (inserts new, updates changed, never duplicates) |
| `load_kev` / `load_epss` | Download the full feeds and replace `raw_kev` / `raw_epss`. They run in parallel with the NVD tasks |
| `prepare_dbt` | Copies the dbt project to `/tmp` and restores `dbt_packages` from a persistent Docker volume (runs `dbt deps` only on the first run) |
| `dbt_seed` → `dbt_run` → `dbt_test` | Loads seeds, rebuilds staging + marts + risk fact, then runs the tests. A failing test turns the DAG red instead of silently shipping bad data |

dbt runs in its own virtualenv inside the Airflow image (`dbt-bigquery==1.8.2`) to avoid dependency conflicts with Airflow. If you change `dbt_cve/packages.yml`, remove the `dbt_packages_cache` volume once (`docker compose down -v`) so the packages are downloaded again.

---

## 6. Data quality

- **dbt tests** on staging and marts: `unique`, `not_null`, `accepted_values` (severity, priority tier) and `dbt_utils.unique_combination_of_columns` on mart grains.
- **Singular test** `assert_no_future_published_dates`: fails if any CVE has a publication date in the future.
- **Enforced dbt contracts** on all marts and on `fct_cve_daily_risk`: a column rename or type change fails the build instead of silently breaking the dashboard.
- **Feed validation**: `load_kev` and `load_epss` raise an error if a feed is empty or has unexpected columns. A BigQuery load job is atomic, so a failed load leaves the previous table untouched.

---

## 7. Dashboard

Two Streamlit front ends read the same BigQuery tables:

| Command | Description |
|---|---|
| `streamlit run dashboard/app.py` | **Main UI.** Sidebar filters (years, severity, Top N), a "latest critical & high CVEs" table (last 30 days), and five tabs: Vendors · Severity trends · Weaknesses (CWE) · AI & OWASP/ATLAS · Patch priorities (P1–P4) |
| `streamlit run dashboard/observatory.py` | **Alternative UI** with light/dark mode and sidebar workspaces: Overview · Threat Watch · Vendors · Severity Trends · Weaknesses · AI Intelligence · Patch Priorities (with CSV export). Needs the same `dashboard/requirements.txt` |

Both cache query results for 10 minutes. The Patch Priorities view reads only the latest `snapshot_date`, shows up to 200 rows (tier totals are computed over all rows), and caps each query at 1 GB billed.

---

## 8. Design decisions and limitations

- **Unscored CVEs are kept.** NVD has a large scoring backlog, so many recent CVEs have no CVSS score yet. Dropping them would make recent years look milder than reality, so they appear as `UNSCORED`.
- **Severity uses the newest CVSS version available** (v4.0 → v3.1 → v3.0 → v2), preferring NVD's own *Primary* score.
- **Vendor = first CPE entry.** Good enough for ranking, but a CVE affecting several vendors is counted once, and CVEs without CPE data are `unknown` (excluded from the vendor chart).
- **"AI-related" is a keyword heuristic** on the description (`dbt_cve/macros/ai_regex.sql`). It is transparent and tunable but not ground truth: expect false positives and misses. If you change it, also change `AI_PATTERN` in `dashboard/build_sample_marts.py`.
- **The CWE → OWASP LLM / ATLAS mapping is an analytical choice** (`dbt_cve/seeds/cwe_owasp_atlas.csv`). It links the *weakness type* of a CVE to the closest framework category; it does not claim the CVE is an attack on an LLM. It covers only 11 CWEs, so other weaknesses show their bare ID instead of a name in the CWE view. Review it against the official OWASP and MITRE ATLAS pages.
- **"Affects our assets" is simulated.** `simulated_assets.csv` stands in for the asset matching a real security team would do against its own inventory (match on vendor + product).
- **P1–P4 is a project-defined rule**, not an official standard (see 2.4).
- **No risk history.** `fct_cve_daily_risk` is replaced on each run, so you cannot see how a CVE's tier changed over time.
- **KEV and EPSS are full snapshots**, replaced daily. EPSS keeps one score per CVE (the latest).
- **The current year is partial**, so compare it with earlier years carefully.
- **Rejected CVEs** are removed in staging.

---

## 9. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Fetch is very slow | No `NVD_API_KEY` | Add the key to `.env` (the script warns at startup) |
| `403` / `429` from NVD | Rate limit | The script retries automatically; wait or add an API key |
| `GCP_PROJECT_ID is not set` | Missing `.env` value | Edit `.env` (project **ID**, not the name) |
| `Dataset ... not found` / location error | Dataset in another location | Create `cve_raw` and `cve_dbt` in the same location as `BQ_LOCATION` |
| `403 Access Denied` in BigQuery | Service account lacks a role | Grant *BigQuery Data Editor* + *Job User* (or *Admin*) |
| `dbt: command not found` | venv not active | `source venv/bin/activate` and `pip install -r requirements.txt` |
| dbt "Env var required but not provided" | Not using the helper | Run dbt through `./run_dbt.sh ...` |
| Dashboard says "Local sample data" | `GCP_PROJECT_ID` missing, or BigQuery error | Read the yellow warning at the top of the page: it names the identity used |
| Patch Priorities says the risk mart is not available | `fct_cve_daily_risk` not built | Run `load_risk_feeds.py` (4.3), then `./run_dbt.sh run` (4.4) |
| `docker compose` says "Set POSTGRES_PASSWORD in docker/.env" | Missing variable | Fill `docker/.env` (see 4.6) |
| Airflow DAG fails at `load_to_bigquery` or `load_kev` | Key not readable in the container | `chmod 644 keys/service-account.json`, restart |
| Airflow DAG import error | Image not rebuilt | `docker compose build` then `docker compose up -d` |
| DAG fails at `prepare_dbt` after editing `packages.yml` | Stale package cache | `docker compose down -v`, then start again |

---

## 10. Roadmap

- Real-time lane with Google Pub/Sub next to the batch lane (**not implemented**; the batch pipeline is complete on its own).
- Keep risk snapshots over time (append instead of replace) to track how priorities change.
- Replace the simulated asset inventory with a real one.

---

## Team

Manal Alyami (team lead) · Hajer Almotaq · Asma Alrdini · Eman Alsayyar
