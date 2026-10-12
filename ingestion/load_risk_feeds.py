
import csv
import gzip
import io
import json
import os
import re
from pathlib import Path

from google.cloud import bigquery

PROJECT = os.getenv("GCP_PROJECT_ID", "cve-threat-intelligence-de")
DATASET = "cve_raw"
client = bigquery.Client(project=PROJECT)


def load_kev():
    path = Path("/tmp/cve-kev.json")
    data = json.loads(path.read_text(encoding="utf-8"))

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
        write_disposition="WRITE_EMPTY",
    )

    table = f"{PROJECT}.{DATASET}.raw_kev"
    client.load_table_from_json(
        rows, table, job_config=config
    ).result()

    print(f"KEV loaded: {len(rows):,} rows")


def load_epss():
    path = Path("/tmp/cve-epss.csv.gz")
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["cve_id", "epss_score", "percentile", "score_date"])

    with gzip.open(path, "rt", encoding="utf-8") as file:
        metadata = next(file)
        match = re.search(
            r"score_date:(\d{4}-\d{2}-\d{2})",
            metadata
        )
        if not match:
            raise ValueError("EPSS score date missing")

        score_date = match.group(1)
        reader = csv.DictReader(file)

        if not {"cve", "epss", "percentile"}.issubset(
            reader.fieldnames or []
        ):
            raise ValueError("Unexpected EPSS columns")

        count = 0
        for row in reader:
            writer.writerow([
                row["cve"],
                row["epss"],
                row["percentile"],
                score_date,
            ])
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
        write_disposition="WRITE_EMPTY",
    )

    table = f"{PROJECT}.{DATASET}.raw_epss"
    data = io.BytesIO(output.getvalue().encode("utf-8"))

    client.load_table_from_file(
        data, table, job_config=config
    ).result()

    print(f"EPSS loaded: {count:,} rows")


if __name__ == "__main__":
    load_kev()
    load_epss()
