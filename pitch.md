# CVEYE — Pitch Script

*Speaker script matching the final presentation deck. ~6-8 minutes.*

## 1. Cover

"Hi, we're team CVEYE — CVE + Eye. We built a CVE Threat Intelligence Pipeline: it watches the CVE landscape so a security team doesn't have to. By the end of this you'll know which vendors are most affected, how severity is trending, where AI/LLM systems are exposed, and — most importantly — exactly what to patch first."

## 2. The problem

"Here's the problem we're solving. About 250,000 new CVEs are published every year. Almost none of them are confirmed exploited in the wild — but nearly nothing tells a team *which* ones are. So teams either try to patch everything, which is too slow, or patch by CVSS score alone, which gets the priorities wrong. There was no off-the-shelf tool combining severity, real exploitation signals, and your own asset exposure in one place. That's the gap CVEYE closes."

## 3. Solution overview

"At a high level: three public feeds — NVD, CISA's KEV catalog, and FIRST's EPSS scores — get ingested in Python, land in BigQuery, get transformed by dbt into seven marts, and surface in a Streamlit dashboard. Apache Airflow runs the whole chain daily."

## 4. Data sources

"Digging into sources specifically: NVD API 2.0 is our core feed — a paginated REST API, about 199,000 CVEs loaded from 2023 onward, pulled by `fetch_nvd.py` and loaded with `load_to_bigquery.py`. CISA KEV is a single JSON file — their full catalog of confirmed-exploited CVEs. FIRST EPSS is a gzipped CSV with a daily exploit-probability score per CVE. Both risk feeds are pulled by the same script, `load_risk_feeds.py`. All three land as flat tables in BigQuery's `cve_raw` dataset before dbt touches anything — ingestion and transformation are fully separate stages."

## 5. Conceptual data model

"Our data model centers on the CVE entity. A CVE has one primary CWE weakness. It may or may not appear in KEV — that's a 1-to-0-or-1 relationship. It gets at most one latest EPSS score, since EPSS republishes daily and we keep the newest. It may match one of our simulated assets, by vendor and product. And a CWE may map to one OWASP LLM category, for the subset relevant to AI systems. Everything folds into `fct_cve_daily_risk`, whose grain is one row per CVE per snapshot day — that's the table that joins every other entity together into a P1-P4 priority tier."

## 6. Pipeline / orchestration

"The whole thing runs as one Airflow DAG with six daily tasks: fetch recent CVEs, load to BigQuery with a MERGE — so no duplicates — prepare dbt, then dbt seed, run, and test. It runs daily and incrementally, only pulling CVEs modified in the last three days. We also added `max_active_runs=1` this week after reviewing the DAG, so two runs can never overlap if a trigger fires late."

## 7. How the dashboard connects to the warehouse

"The Streamlit app — `app.py` and `risk_queue.py` — talks to BigQuery directly through the `google-cloud-bigquery` Python client, authenticated with a service-account key. There's no API layer in between. Every chart reads from a materialized mart table in the `cve_dbt` dataset, never raw CVE rows, so queries stay fast even over 190,000-plus rows. Results are cached for 10 minutes with `st.cache_data`. And if BigQuery is ever unreachable, the app falls back to a bundled synthetic sample so a demo never breaks."

## 8. Dashboard walkthrough

"The dashboard has five tabs: Vendors, Severity trends, Weaknesses, AI & OWASP/ATLAS, and Patch priorities — plus a live 'latest critical and high CVEs' table up top, which is what a security team would actually triage first. [Switch to live dashboard here if demoing.]"

## 9. Patch priority — the business value

"This is the pitch. Out of roughly 194,000 CVEs in our risk mart, only 42 are P1 — critical, affecting our simulated assets, and either confirmed exploited or high-probability. 1,114 are P2. The rest fall into P3 or P4, safe to defer. The pitch to a stakeholder is simple: 42 CVEs need attention this week, not 194,000. That's the difference between 'we're overwhelmed' and 'we have a plan' — and it rebuilds automatically every day the pipeline runs."

## 10. Engineering rigor

"A few things we did beyond making charts render: 28 automated dbt tests across every mart. All seven marts are under enforced dbt contracts, so a column rename or type change fails the build loudly instead of breaking the dashboard silently. Every change goes through a feature branch and PR — which is actually how we caught and removed a leaked API key from a template file before it went further."

## 11. Limitations

"To be upfront: 'affects our assets' is simulated, not a real inventory. 'AI-related' is a keyword heuristic, not ground truth. We keep unscored CVEs rather than dropping them, since NVD has a scoring backlog. And KEV/EPSS are loaded as one-time snapshots right now, not refreshed daily yet."

## 12. Next steps

"Two scoped extensions: making the KEV/EPSS load incremental, same MERGE pattern as the main feed, so priorities reflect the latest exploitation signals automatically. And a real-time lane with Google Pub/Sub sitting next to the daily batch — not implemented, since the batch pipeline is complete on its own."

## Team

Manal Alyami (team lead) · Hajer Almotaq · Asma Alrdini · Eman Alsayyar

## 13. Thank you

"That's CVEYE. Thank you — happy to take questions, or we can jump back into the live dashboard."
