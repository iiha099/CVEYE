"""
fetch_nvd.py
-------------
Pulls CVE records from NIST's NVD API 2.0 and writes ONE flat CSV that the
rest of the pipeline (BigQuery -> dbt -> Streamlit) is built on.

Two steps, on purpose:
  1. DOWNLOAD  raw JSON pages -> data/bronze/   (the "bronze" layer, kept as-is)
     * The history is split into 120-day windows (NVD's maximum per request).
     * Every page is saved as its own file, so if the run is interrupted you
       just run the command again and it continues where it stopped.
  2. FLATTEN   bronze JSON -> data/cves_raw.csv  (one row per CVE)

USAGE (run from the repo root)
-------------------------------
  # full history from a start year (first run takes a while)
  python ingestion/fetch_nvd.py --start-year 2023

  # only turn the files you already downloaded into the CSV (no API calls)
  python ingestion/fetch_nvd.py --flatten-only --start-year 2023

  # incremental: CVEs created OR modified in the last 3 days (what Airflow does)
  python ingestion/fetch_nvd.py --last-modified-days 3 --out data/cves_incoming.csv

OUTPUT COLUMNS (the contract every other file in the project relies on)
------------------------------------------------------------------------
  cve_id, published_date, last_modified_date, vuln_status, severity,
  cvss_score, vendor, product, cwe_id, description

  severity   CRITICAL / HIGH / MEDIUM / LOW, or UNSCORED when NVD has not
             scored the CVE yet (very common for recent CVEs).
  vendor     first vendor found in the CVE's CPE list, or "unknown".
  cwe_id     the primary CWE (e.g. CWE-79) or "unknown".
"""

import argparse
import csv
import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

from config import NVD_API_KEY, ROOT

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
WINDOW_DAYS = 120  # NVD rejects date ranges longer than 120 days
PAGE_SIZE = 2000  # NVD maximum per request
# With an API key NVD allows ~50 requests / 30 s, without one only ~5.
SLEEP_SECONDS = 1.0 if NVD_API_KEY else 7.0
HEADERS = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}

BRONZE_DIR = ROOT / "data" / "bronze"
DEFAULT_OUT = ROOT / "data" / "cves_raw.csv"

COLUMNS = [
    "cve_id",
    "published_date",
    "last_modified_date",
    "vuln_status",
    "severity",
    "cvss_score",
    "vendor",
    "product",
    "cwe_id",
    "description",
]


# --------------------------------------------------------------- API helpers
def fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


def get_json(params: dict, retries: int = 6) -> dict:
    """GET one page from NVD, retrying with a growing pause on any failure."""
    for attempt in range(retries):
        try:
            r = requests.get(NVD_API_URL, params=params, headers=HEADERS, timeout=120)
            if r.status_code == 200:
                return r.json()
            print(f"  NVD answered {r.status_code}", end="")
        except requests.RequestException as exc:
            print(f"  network error: {exc}", end="")
        wait = 10 * (attempt + 1)
        print(f" -> retrying in {wait}s")
        time.sleep(wait)
    raise RuntimeError(f"NVD request failed after {retries} tries: {params}")


def iter_pages(date_params: dict):
    """Yield (page_number, json) for every page of one date filter."""
    start_index, page = 0, 0
    while True:
        data = get_json({**date_params, "resultsPerPage": PAGE_SIZE, "startIndex": start_index})
        yield page, data
        start_index += PAGE_SIZE
        page += 1
        if start_index >= data.get("totalResults", 0):
            break
        time.sleep(SLEEP_SECONDS)


# ---------------------------------------------------------------- flattening
def severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "UNSCORED"


def pick_severity_and_score(metrics: dict) -> tuple[str, float | None]:
    """Newest CVSS version first (v4.0 -> v3.1 -> v3.0 -> v2); prefer NVD's own 'Primary' score."""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData", {})
        score = data.get("baseScore")
        if score is None:
            continue
        severity = data.get("baseSeverity") or entry.get("baseSeverity")
        severity = (severity or severity_from_score(float(score))).upper()
        if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            severity = "UNSCORED"
        return severity, float(score)
    return "UNSCORED", None


def pick_vendor_product(configurations: list) -> tuple[str, str]:
    """First affected vendor/product found in a CPE string: cpe:2.3:a:<vendor>:<product>:..."""
    for config in configurations or []:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable") is False:
                    continue
                parts = match.get("criteria", "").split(":")
                if len(parts) >= 5 and parts[3] not in ("", "*", "-"):
                    return parts[3].lower(), (parts[4] or "unknown").lower()
    return "unknown", "unknown"


def pick_cwe(weaknesses: list) -> str:
    """Primary CWE first (e.g. CWE-79); otherwise whatever NVD gives (NVD-CWE-Other ...)."""
    found = []
    for w in weaknesses or []:
        for d in w.get("description", []):
            if d.get("lang") == "en" and d.get("value"):
                found.append((w.get("type") != "Primary", d["value"]))
    found.sort(key=lambda x: x[0])  # Primary first (stable sort)
    for _, value in found:
        if value.startswith("CWE-"):
            return value
    return found[0][1] if found else "unknown"


def flatten_cve(cve: dict) -> dict:
    description = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        "No description available.",
    )
    severity, score = pick_severity_and_score(cve.get("metrics", {}))
    vendor, product = pick_vendor_product(cve.get("configurations", []))
    return {
        "cve_id": cve["id"],
        "published_date": (cve.get("published") or "")[:10],
        "last_modified_date": (cve.get("lastModified") or "")[:10],
        "vuln_status": cve.get("vulnStatus", ""),
        "severity": severity,
        "cvss_score": "" if score is None else score,
        "vendor": vendor,
        "product": product,
        "cwe_id": pick_cwe(cve.get("weaknesses", [])),
        "description": " ".join(description.split()),  # one line, no stray newlines
    }


def add_row(rows: dict, row: dict) -> None:
    """Keep one row per CVE: the most recently modified version wins."""
    old = rows.get(row["cve_id"])
    if old is None or row["last_modified_date"] >= old["last_modified_date"]:
        rows[row["cve_id"]] = row


# ------------------------------------------------------------- the two steps
def download_published(start: datetime, end: datetime, bronze_dir: Path = BRONZE_DIR) -> None:
    """Step 1: save raw JSON pages for CVEs published between start and end."""
    bronze_dir.mkdir(parents=True, exist_ok=True)
    window_start = start
    while window_start < end:
        window_end = min(window_start + timedelta(days=WINDOW_DAYS), end)
        tag = f"{window_start:%Y%m%d}_{window_end:%Y%m%d}"
        print(f"Window {tag}")
        params = {"pubStartDate": fmt(window_start), "pubEndDate": fmt(window_end)}

        start_index, page = 0, 0
        while True:
            out_file = bronze_dir / f"nvd_{tag}_p{page:03d}.json"
            if out_file.exists():  # already downloaded -> resume support
                data = json.loads(out_file.read_text(encoding="utf-8"))
            else:
                data = get_json({**params, "resultsPerPage": PAGE_SIZE, "startIndex": start_index})
                out_file.write_text(json.dumps(data), encoding="utf-8")
                time.sleep(SLEEP_SECONDS)
            total = data["totalResults"]
            print(f"  page {page}: {len(data['vulnerabilities'])} CVEs (window total {total})")
            start_index += PAGE_SIZE
            page += 1
            if start_index >= total:
                break
        window_start = window_end


def flatten_bronze(bronze_dir: Path = BRONZE_DIR, min_year: int | None = None) -> list[dict]:
    """Step 2: read every bronze file, flatten, de-duplicate by cve_id."""
    rows: dict = {}
    files = sorted(bronze_dir.glob("nvd_*.json"))
    if not files:
        raise SystemExit(f"No bronze files in {bronze_dir}. Run without --flatten-only first.")
    for path in files:
        data = json.loads(path.read_text(encoding="utf-8"))
        for item in data.get("vulnerabilities", []):
            row = flatten_cve(item["cve"])
            if min_year and row["published_date"][:4].isdigit() and int(row["published_date"][:4]) < min_year:
                continue
            add_row(rows, row)
    return list(rows.values())


def fetch_modified(days: int) -> list[dict]:
    """Incremental mode: CVEs created or modified in the last `days` days (max 120)."""
    if not 1 <= days <= WINDOW_DAYS:
        raise ValueError(f"days must be between 1 and {WINDOW_DAYS}")
    end = datetime.now(timezone.utc)
    params = {"lastModStartDate": fmt(end - timedelta(days=days)), "lastModEndDate": fmt(end)}
    rows: dict = {}
    for page, data in iter_pages(params):
        print(f"  page {page}: {len(data['vulnerabilities'])} CVEs (total {data['totalResults']})")
        for item in data["vulnerabilities"]:
            add_row(rows, flatten_cve(item["cve"]))
    return list(rows.values())


def write_csv(rows: list[dict], out_path: Path) -> None:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    rows = sorted(rows, key=lambda r: (r["published_date"], r["cve_id"]))
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch CVEs from NVD into a flat CSV")
    parser.add_argument("--start-year", type=int, default=2023, help="first publication year to keep (default 2023)")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="output CSV (default data/cves_raw.csv)")
    parser.add_argument("--flatten-only", action="store_true", help="skip downloading, just flatten data/bronze")
    parser.add_argument("--last-modified-days", type=int, help="incremental mode: CVEs changed in the last N days")
    args = parser.parse_args()

    if not NVD_API_KEY:
        print("WARNING: no NVD_API_KEY found in .env -> requests are ~7x slower.\n")

    if args.last_modified_days:
        rows = fetch_modified(args.last_modified_days)
    else:
        if not args.flatten_only:
            start = datetime(args.start_year, 1, 1, tzinfo=timezone.utc)
            download_published(start, datetime.now(timezone.utc))
        rows = flatten_bronze(min_year=args.start_year)

    if not rows and not args.last_modified_days:
        print("ERROR: no records produced.")
        sys.exit(1)

    write_csv(rows, args.out)
    print(f"\nSaved {len(rows):,} CVEs -> {args.out}")


if __name__ == "__main__":
    main()
