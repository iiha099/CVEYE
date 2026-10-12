"""
build_sample_marts.py
-----------------------
Re-creates, with pandas, the same six mart tables that dbt builds in BigQuery,
from data/sample/cves_raw.csv. The dashboard uses these CSVs as its offline
fallback (no cloud needed), so they must keep the same columns as the dbt marts.

USAGE (from the repo root):
    python dashboard/build_sample_marts.py
"""

import re
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "data" / "sample"
SEED = ROOT / "dbt_cve" / "seeds" / "cwe_owasp_atlas.csv"

# Keep in sync with dbt_cve/macros/ai_regex.sql
AI_PATTERN = re.compile(
    r"\b(llm|llms|large language model|prompt injection|langchain|llama[ _-]?index|llama\.cpp|ollama|openai|chatgpt"
    r"|hugging ?face|pytorch|tensorflow|keras|mlflow|gradio|vllm|onnx|machine learning|deep learning|neural network"
    r"|artificial intelligence|generative ai|ai agent|ai assistant|copilot|model context protocol|mcp server"
    r"|stable diffusion|autogpt|text-generation-webui)\b"
)


def build_staging(raw: pd.DataFrame) -> pd.DataFrame:
    df = raw.sort_values("last_modified_date", ascending=False).drop_duplicates("cve_id")
    df = df[df["vuln_status"].fillna("").str.lower() != "rejected"].copy()
    df["severity"] = df["severity"].fillna("").str.strip().str.upper().replace("", "UNSCORED")
    df["vendor"] = df["vendor"].fillna("").str.strip().str.lower().replace("", "unknown")
    df["cwe_id"] = df["cwe_id"].fillna("").str.strip().str.upper().replace("", "unknown")
    df["published_year"] = pd.to_datetime(df["published_date"]).dt.year
    df["is_ai_related"] = df["description"].fillna("").str.lower().apply(lambda s: bool(AI_PATTERN.search(s)))
    return df


def main() -> None:
    raw = pd.read_csv(SAMPLE / "cves_raw.csv")
    seed = pd.read_csv(SEED)
    stg = build_staging(raw)

    severity_trends = (
        stg.groupby(["published_year", "severity"])
        .agg(cve_count=("cve_id", "count"), avg_cvss_score=("cvss_score", "mean"))
        .round(2).reset_index()
    )

    v = stg[stg["vendor"] != "unknown"]
    vendor = v.groupby(["vendor", "published_year"]).size().rename("total_cves").reset_index()
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNSCORED"]:
        counts = v[v["severity"] == sev].groupby(["vendor", "published_year"]).size().rename(f"{sev.lower()}_count")
        vendor = vendor.merge(counts, on=["vendor", "published_year"], how="left")
    count_cols = [f"{s.lower()}_count" for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNSCORED"]]
    vendor[count_cols] = vendor[count_cols].fillna(0).astype(int)
    vendor = vendor[["vendor", "published_year", *count_cols, "total_cves"]]

    cwe = stg[stg["cwe_id"].str.startswith("CWE-")]
    cwe_trends = (
        cwe.groupby(["published_year", "cwe_id"]).size().rename("cve_count").reset_index()
        .merge(seed[["cwe_id", "cwe_name"]].drop_duplicates("cwe_id"), on="cwe_id", how="left")
        [["published_year", "cwe_id", "cwe_name", "cve_count"]]
    )

    ai_trends = stg.groupby("published_year").agg(
        total_cves=("cve_id", "count"), ai_related_cves=("is_ai_related", "sum")
    ).reset_index()
    ai_hc = stg[stg["is_ai_related"] & stg["severity"].isin(["CRITICAL", "HIGH"])].groupby("published_year").size()
    ai_trends["ai_high_critical_cves"] = ai_trends["published_year"].map(ai_hc).fillna(0).astype(int)
    ai_trends["ai_related_cves"] = ai_trends["ai_related_cves"].astype(int)
    ai_trends["ai_share_pct"] = (100.0 * ai_trends["ai_related_cves"] / ai_trends["total_cves"]).round(2)
    ai_trends = ai_trends[["published_year", "total_cves", "ai_related_cves", "ai_high_critical_cves", "ai_share_pct"]]

    ai_list = (
        stg[stg["is_ai_related"]]
        .sort_values(["published_date", "cve_id"], ascending=False).head(500)
        [["cve_id", "published_date", "published_year", "severity", "cvss_score", "vendor", "product", "cwe_id", "description"]]
    )

    mapped = stg.merge(seed, on="cwe_id", how="inner")
    mapped["atlas_technique_id"] = mapped["atlas_technique_id"].fillna("n/a")
    mapped["atlas_technique_name"] = mapped["atlas_technique_name"].fillna("n/a")
    owasp = (
        mapped.groupby(["published_year", "owasp_llm_id", "owasp_llm_name", "atlas_technique_id", "atlas_technique_name"])
        .size().rename("cve_count").reset_index()
    )

    outputs = {
        "mart_severity_trends": severity_trends,
        "mart_vendor_severity": vendor,
        "mart_cwe_trends": cwe_trends,
        "mart_ai_trends": ai_trends,
        "mart_ai_cve_list": ai_list,
        "mart_owasp_atlas": owasp,
    }
    for name, df in outputs.items():
        df.to_csv(SAMPLE / f"{name}.csv", index=False)
        print(f"{name}: {len(df)} rows")


if __name__ == "__main__":
    main()
