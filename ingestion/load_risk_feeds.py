"""
load_risk_feeds.py
--------------------
Downloads the two risk-enrichment feeds and loads them into BigQuery:

    CISA KEV  -> <project>.<BQ_RAW_DATASET>.raw_kev
    FIRST EPSS -> <project>.<BQ_RAW_DATASET>.raw_epss

Both feeds are FULL snapshots (KEV = the whole catalog, EPSS = one current
score per CVE), so each daily run replaces the table (WRITE_TRUNCATE).
A BigQuery load job is atomic: if anything fails, the old table is untouched.

Used by the Airflow DAG (dags/cve_pipeline_dag.py) and still runnable by hand:
    python ingestion/load_risk_feeds.py
"""

import csv
import gzip
import io
import json
import re

import requests
from google.cloud import bigquery

from config import BQ_RAW_DATASET, GCP_PROJECT_ID

PROJECT = GCP_PROJECT_ID or "cve-threat-intelligence-de"
DATASET = BQ_RAW_DATASET

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
HEADERS = {"User-Agent": "cve-threat-intelligence-pipeline/1.0"}


def _download(url: str) -> bytes:
    # No manual retry loop: Airflow retries the whole task (retries=2 in the DAG).
    r = requests.get(url, headers=HEADERS, timeout=120)
    r.raise_for_status()
    return r.content


def load_kev():
    data = json.loads(_download(KEV_URL).decode("utf-8"))

    rows = [
        {
            "cve_id": item["cveID"],
            "date_added": item["dateAdded"],
            "vendor_project": item.get("vendorProject"),
            "product": item.get("product"),
        }
        for item in data["vulnerabilities"]
    ]

    if not rows:
        raise ValueError("KEV feed is empty")

    config = bigquery.LoadJobConfig(
        schema=[
            bigquery.SchemaField("cve_id", "STRING"),
            bigquery.SchemaField("date_added", "DATE"),
            bigquery.SchemaField("vendor_project", "STRING"),
            bigquery.SchemaField("product", "STRING"),
        ],
        write_disposition="WRITE_TRUNCATE",
    )

    client = bigquery.Client(project=PROJECT)
    table = f"{PROJECT}.{DATASET}.raw_kev"
    client.load_table_from_json(rows, table, job_config=config).result()

    print(f"KEV loaded: {len(rows):,} rows -> {table}")


def load_epss():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["cve_id", "epss_score", "percentile", "score_date"])

    with gzip.open(io.BytesIO(_download(EPSS_URL)), "rt", encoding="utf-8") as file:
        metadata = next(file)
        match = re.search(r"score_date:(\d{4}-\d{2}-\d{2})", metadata)
        if not match:
            raise ValueError("EPSS score date missing")

        score_date = match.group(1)
        reader = csv.DictReader(file)

        if not {"cve", "epss", "percentile"}.issubset(reader.fieldnames or []):
            raise ValueError("Unexpected EPSS columns")

        count = 0
        for row in reader:
            writer.writerow([row["cve"], row["epss"], row["percentile"], score_date])
            count += 1

    if not count:
        raise ValueError("EPSS feed is empty")

    config = bigquery.LoadJobConfig(
        source_format="CSV",
        skip_leading_rows=1,
        schema=[
            bigquery.SchemaField("cve_id", "STRING"),
            bigquery.SchemaField("epss_score", "FLOAT64"),
            bigquery.SchemaField("percentile", "FLOAT64"),
            bigquery.SchemaField("score_date", "DATE"),
        ],
        write_disposition="WRITE_TRUNCATE",
    )

    client = bigquery.Client(project=PROJECT)
    table = f"{PROJECT}.{DATASET}.raw_epss"
    data = io.BytesIO(output.getvalue().encode("utf-8"))
    client.load_table_from_file(data, table, job_config=config).result()

    print(f"EPSS loaded: {count:,} rows (score_date {score_date}) -> {table}")


if __name__ == "__main__":
    load_kev()
    load_epss()