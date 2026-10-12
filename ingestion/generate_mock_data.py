"""
generate_mock_data.py
------------------------
FOR LOCAL DEVELOPMENT / DEMO SAFETY NET ONLY. This does NOT call NVD and the
numbers it produces are SYNTHETIC (never present them as real findings).

It writes a CSV with the exact same columns as fetch_nvd.py, so the dbt models
and the dashboard can be tested without network access or a cloud account.
It deliberately includes the messy cases the real data has: UNSCORED recent
CVEs, "unknown" vendors, REJECTED CVEs, and a growing share of AI-related ones.

USAGE (from the repo root)
---------------------------
  python ingestion/generate_mock_data.py --rows 1200 --out data/sample/cves_raw.csv
"""

import argparse
import csv
import random
from datetime import date, timedelta
from pathlib import Path

COLUMNS = [
    "cve_id", "published_date", "last_modified_date", "vuln_status", "severity",
    "cvss_score", "vendor", "product", "cwe_id", "description",
]

VENDORS_AND_PRODUCTS = [
    ("microsoft", "windows"), ("microsoft", "office"), ("microsoft", "exchange_server"),
    ("google", "chrome"), ("google", "android"), ("apple", "ios"), ("apple", "macos"),
    ("oracle", "mysql"), ("oracle", "java_se"), ("adobe", "acrobat_reader"),
    ("cisco", "ios_xe"), ("cisco", "webex"), ("vmware", "esxi"), ("ibm", "websphere"),
    ("linux", "kernel"), ("apache", "http_server"), ("wordpress", "wordpress"),
    ("fortinet", "fortios"), ("tp-link", "archer_ax50"), ("d-link", "dir-816"),
]
AI_VENDORS_AND_PRODUCTS = [
    ("langchain", "langchain"), ("llamaindex", "llama_index"), ("ollama", "ollama"),
    ("gradio_project", "gradio"), ("pytorch", "pytorch"), ("mlflow", "mlflow"),
    ("vllm_project", "vllm"), ("google", "tensorflow"),
]
CWES = ["CWE-79", "CWE-89", "CWE-78", "CWE-787", "CWE-125", "CWE-22", "CWE-352", "CWE-20",
        "CWE-200", "CWE-502", "CWE-94", "CWE-862", "CWE-863", "CWE-400", "CWE-416",
        "NVD-CWE-Other", "NVD-CWE-noinfo"]
AI_CWES = ["CWE-94", "CWE-502", "CWE-78", "CWE-200", "CWE-862", "CWE-400", "CWE-918"]

SEVERITY_WEIGHTS = {"CRITICAL": 0.12, "HIGH": 0.33, "MEDIUM": 0.40, "LOW": 0.15}
SCORE_RANGES = {"CRITICAL": (9.0, 10.0), "HIGH": (7.0, 8.9), "MEDIUM": (4.0, 6.9), "LOW": (0.1, 3.9)}

TEMPLATES = [
    "A {adj} vulnerability in {product} allows {actor} to {impact} via {vector}.",
    "{product} is affected by a {adj} flaw that enables {impact} when {vector} is used.",
    "An issue was discovered in {product} where {actor} could {impact} through {vector}.",
]
AI_TEMPLATES = [
    "{product} allows {actor} to achieve {impact} through prompt injection against the LLM integration.",
    "A {adj} flaw in {product} lets {actor} {impact} when loading a malicious machine learning model.",
    "{product} exposes an LLM agent endpoint where {actor} can {impact} via {vector}.",
]
ADJ = ["remote code execution", "privilege escalation", "denial-of-service", "information disclosure", "authentication bypass"]
ACTORS = ["an unauthenticated attacker", "a remote attacker", "a local user", "an authenticated user"]
IMPACTS = ["execute arbitrary code", "escalate privileges to admin", "crash the affected service", "access sensitive memory", "bypass authentication checks"]
VECTORS = ["a crafted network request", "a malicious file upload", "a specially crafted URL", "an out-of-bounds memory write", "a race condition during startup"]

YEARS = [2023, 2024, 2025, 2026]
TODAY = date(2026, 10, 1)


def random_date(year: int) -> date:
    start = date(year, 1, 1)
    end = min(date(year, 12, 31), TODAY)
    return start + timedelta(days=random.randint(0, (end - start).days))


def generate_row(index: int) -> dict:
    year = random.choices(YEARS, weights=[22, 26, 30, 22])[0]
    published = random_date(year)
    modified = min(published + timedelta(days=random.randint(0, 120)), TODAY)

    # AI-related share grows over time (synthetic trend for demo purposes)
    is_ai = random.random() < {2023: 0.03, 2024: 0.06, 2025: 0.10, 2026: 0.15}[year]
    vendor, product = random.choice(AI_VENDORS_AND_PRODUCTS if is_ai else VENDORS_AND_PRODUCTS)
    if not is_ai and random.random() < 0.12:
        vendor, product = "unknown", "unknown"

    # recent CVEs are often not scored yet (like the real NVD backlog)
    unscored_chance = {2023: 0.01, 2024: 0.12, 2025: 0.25, 2026: 0.35}[year]
    status = random.choices(["Analyzed", "Modified", "Awaiting Analysis", "Rejected"], weights=[60, 20, 17, 3])[0]
    if random.random() < unscored_chance:
        severity, score = "UNSCORED", ""
    else:
        severity = random.choices(list(SEVERITY_WEIGHTS), weights=list(SEVERITY_WEIGHTS.values()))[0]
        score = round(random.uniform(*SCORE_RANGES[severity]), 1)

    template = random.choice(AI_TEMPLATES if is_ai else TEMPLATES)
    description = template.format(
        adj=random.choice(ADJ), product=product.replace("_", " "), actor=random.choice(ACTORS),
        impact=random.choice(IMPACTS), vector=random.choice(VECTORS),
    )
    return {
        "cve_id": f"CVE-{published.year}-{10000 + index}",
        "published_date": published.isoformat(),
        "last_modified_date": modified.isoformat(),
        "vuln_status": status,
        "severity": severity,
        "cvss_score": score,
        "vendor": vendor,
        "product": product,
        "cwe_id": random.choice(AI_CWES if is_ai else CWES),
        "description": description,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate SYNTHETIC CVE data for local testing")
    parser.add_argument("--rows", type=int, default=1200)
    parser.add_argument("--out", type=Path, default=Path("data/sample/cves_raw.csv"))
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    random.seed(args.seed)
    rows = sorted((generate_row(i) for i in range(args.rows)), key=lambda r: (r["published_date"], r["cve_id"]))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    print(f"Generated {len(rows)} SYNTHETIC CVE rows -> {args.out}")


if __name__ == "__main__":
    main()
