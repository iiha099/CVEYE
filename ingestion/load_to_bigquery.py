"""
load_to_bigquery.py
---------------------
Loads the flat CSV made by fetch_nvd.py into the BigQuery RAW table
`<project>.<BQ_RAW_DATASET>.raw_cves`.

Two modes:
  replace  wipes the table and loads the CSV   -> first / full load
  merge    upserts by cve_id                   -> daily incremental load (Airflow)
           (new CVEs are inserted, changed CVEs are updated, nothing is duplicated)

USAGE (from the repo root; settings come from .env)
----------------------------------------------------
  python ingestion/load_to_bigquery.py --input data/cves_raw.csv --mode replace
  python ingestion/load_to_bigquery.py --input data/cves_incoming.csv --mode merge
"""

import argparse
from pathlib import Path

from google.cloud import bigquery
from google.cloud.exceptions import NotFound

from config import BQ_LOCATION, BQ_RAW_DATASET, GCP_PROJECT_ID, ROOT

# MUST match the columns written by fetch_nvd.py (same order).
SCHEMA = [
    bigquery.SchemaField("cve_id", "STRING", mode="REQUIRED"),
    bigquery.SchemaField("published_date", "DATE"),
    bigquery.SchemaField("last_modified_date", "DATE"),
    bigquery.SchemaField("vuln_status", "STRING"),
    bigquery.SchemaField("severity", "STRING"),
    bigquery.SchemaField("cvss_score", "FLOAT64"),
    bigquery.SchemaField("vendor", "STRING"),
    bigquery.SchemaField("product", "STRING"),
    bigquery.SchemaField("cwe_id", "STRING"),
    bigquery.SchemaField("description", "STRING"),
]


def _load_csv(client: bigquery.Client, csv_path: Path, table_id: str, disposition: str) -> None:
    job_config = bigquery.LoadJobConfig(
        schema=SCHEMA,
        source_format=bigquery.SourceFormat.CSV,
        skip_leading_rows=1,
        allow_quoted_newlines=True,
        write_disposition=disposition,
    )
    with open(csv_path, "rb") as f:
        client.load_table_from_file(f, table_id, job_config=job_config).result()


def _ensure_dataset(client: bigquery.Client, project: str, dataset: str) -> None:
    try:
        ds = bigquery.Dataset(f"{project}.{dataset}")
        ds.location = BQ_LOCATION
        client.create_dataset(ds, exists_ok=True)
    except Exception as exc:  # no permission to create? fine if it already exists
        print(f"(skipping dataset check: {exc})")


def load_csv_to_bigquery(csv_path, project: str, dataset: str, table: str = "raw_cves", mode: str = "replace") -> None:
    csv_path = Path(csv_path)
    client = bigquery.Client(project=project)
    _ensure_dataset(client, project, dataset)
    target = f"{project}.{dataset}.{table}"

    if mode == "replace":
        _load_csv(client, csv_path, target, bigquery.WriteDisposition.WRITE_TRUNCATE)
        print(f"Done. {target} now has {client.get_table(target).num_rows:,} rows.")
        return

    # merge mode: stage the new rows, then upsert them into the main table
    incoming = f"{project}.{dataset}.{table}_incoming"
    _load_csv(client, csv_path, incoming, bigquery.WriteDisposition.WRITE_TRUNCATE)
    try:
        client.get_table(target)
    except NotFound:
        print(f"{target} does not exist yet -> creating it from the incoming rows.")
        _load_csv(client, csv_path, target, bigquery.WriteDisposition.WRITE_TRUNCATE)
        return

    cols = [f.name for f in SCHEMA]
    updates = ", ".join(f"{c} = S.{c}" for c in cols if c != "cve_id")
    sql = f"""
        MERGE `{target}` T
        USING `{incoming}` S
        ON T.cve_id = S.cve_id
        WHEN MATCHED AND S.last_modified_date >= T.last_modified_date THEN
          UPDATE SET {updates}
        WHEN NOT MATCHED THEN
          INSERT ({", ".join(cols)}) VALUES ({", ".join("S." + c for c in cols)})
    """
    job = client.query(sql)
    job.result()
    print(f"Merged into {target}: {job.num_dml_affected_rows} rows inserted/updated.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Load the flat CVE CSV into BigQuery")
    parser.add_argument("--input", type=Path, default=ROOT / "data" / "cves_raw.csv")
    parser.add_argument("--mode", choices=["replace", "merge"], default="replace")
    parser.add_argument("--project", default=GCP_PROJECT_ID)
    parser.add_argument("--dataset", default=BQ_RAW_DATASET)
    parser.add_argument("--table", default="raw_cves")
    args = parser.parse_args()

    if not args.project:
        raise SystemExit("GCP_PROJECT_ID is not set. Put it in .env or pass --project.")
    load_csv_to_bigquery(args.input, args.project, args.dataset, args.table, args.mode)


if __name__ == "__main__":
    main()
