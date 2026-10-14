"""Patch priorities: professional dark UI on top of the existing BigQuery risk mart.

Only rendering changes. Queries preserve the existing newest-snapshot filter,
priority sorting, 200-row cap and 1 GB BigQuery maximum_bytes_billed limit.
"""
import os
import streamlit as st
from google.cloud import bigquery
from google.api_core.exceptions import NotFound
from theme import ACCENT, SEVERITY_COLORS, render_table, stat_cards

TABLE_NAME = "fct_cve_daily_risk"
REQUIRED = {"snapshot_date", "cve_id", "priority_tier", "severity_score", "epss_score", "in_kev", "affects_our_assets"}
PRIORITY_ACCENT = {
    "P1": SEVERITY_COLORS["CRITICAL"],
    "P2": SEVERITY_COLORS["HIGH"],
    "P3": SEVERITY_COLORS["MEDIUM"],
    "P4": ACCENT,
}
PRIORITY_LABEL = {
    "P1": "P1 · Immediate review", "P2": "P2 · High attention",
    "P3": "P3 · Moderate", "P4": "P4 · Lower priority",
}
PRIORITY_SUB = {
    "P1": "Project-defined priority", "P2": "Project-defined priority",
    "P3": "Project-defined priority", "P4": "Project-defined priority",
}


@st.cache_data(ttl=600)
def load_tier_counts(project, dataset, tiers):
    """Actual totals on the most recent snapshot; not limited to top 200."""
    client = bigquery.Client(project=project)
    table = f"{project}.{dataset}.{TABLE_NAME}"
    sql = f"""
        SELECT priority_tier, COUNT(*) AS n
        FROM `{table}`
        WHERE snapshot_date = (SELECT MAX(snapshot_date) FROM `{table}`)
        AND priority_tier IN UNNEST(@tiers)
        GROUP BY priority_tier
    """
    config = bigquery.QueryJobConfig(
        query_parameters=[bigquery.ArrayQueryParameter("tiers", "STRING", list(tiers))],
        maximum_bytes_billed=1_000_000_000,
    )
    df = client.query(sql, job_config=config).to_dataframe()
    return dict(zip(df["priority_tier"], df["n"]))


@st.cache_data(ttl=600)
def load_priorities(project, dataset, tiers):
    client = bigquery.Client(project=project)
    table = f"{project}.{dataset}.{TABLE_NAME}"
    sql = f"""
        SELECT snapshot_date, cve_id, priority_tier, severity_score,
               epss_score, in_kev, affects_our_assets
        FROM `{table}`
        WHERE snapshot_date = (SELECT MAX(snapshot_date) FROM `{table}`)
        AND priority_tier IN UNNEST(@tiers)
        ORDER BY CASE priority_tier
            WHEN 'P1' THEN 1 WHEN 'P2' THEN 2
            WHEN 'P3' THEN 3 WHEN 'P4' THEN 4 ELSE 5 END,
            epss_score DESC, severity_score DESC
        LIMIT 200
    """
    config = bigquery.QueryJobConfig(
        query_parameters=[bigquery.ArrayQueryParameter("tiers", "STRING", list(tiers))],
        maximum_bytes_billed=1_000_000_000,
    )
    return client.query(sql, job_config=config).to_dataframe()


def render_risk_queue(data_source):
    st.markdown('<p class="cveye-eyebrow">RISK INTELLIGENCE</p>', unsafe_allow_html=True)
    st.subheader("Patch Priority Queue")
    st.caption("Risk-ranked vulnerabilities using CVSS, CISA KEV, FIRST EPSS and simulated asset exposure.")
    if data_source != "BigQuery (live)":
        st.info("BigQuery connection is required for risk priority data.")
        return
    project = os.getenv("GCP_PROJECT_ID")
    dataset = os.getenv("BQ_DBT_DATASET", "cve_dbt")
    if not project:
        st.warning("GCP_PROJECT_ID is missing.")
        return
    try:
        client = bigquery.Client(project=project)
        table = client.get_table(f"{project}.{dataset}.{TABLE_NAME}")
    except NotFound:
        st.info("Risk Mart not available. The fct_cve_daily_risk table hasn't been created yet.")
        return
    except Exception as exc:
        st.error(f"BigQuery connection error: {exc}")
        return
    missing = REQUIRED - {field.name for field in table.schema}
    if missing:
        st.warning("Missing columns: " + ", ".join(sorted(missing)))
        return

    # Streamlit native pills adopt the dark color system in .streamlit/config.toml
    options = ["P1", "P2", "P3", "P4"]
    if hasattr(st, "pills"):
        tiers = st.pills("Priority levels", options, selection_mode="multi", default=options)
    else:
        tiers = st.multiselect("Priority levels", options, default=options)
    if not tiers:
        st.info("Choose at least one priority level.")
        return
    try:
        tier_counts = load_tier_counts(project, dataset, tuple(tiers))
        data = load_priorities(project, dataset, tuple(tiers))
        total = sum(int(x) for x in tier_counts.values())
        if not total:
            st.info("No CVEs found for the selected priorities.")
            return
        stat_cards([
            {
                "label": PRIORITY_LABEL[tier],
                "value": f"{int(tier_counts.get(tier, 0)):,}",
                "sub": PRIORITY_SUB[tier],
                "accent": PRIORITY_ACCENT[tier],
            }
            for tier in options if tier in tiers
        ])
        st.markdown('<p class="cveye-eyebrow" style="margin-top:22px">PRIORITIZED VULNERABILITIES</p>', unsafe_allow_html=True)
        st.caption("Latest available risk snapshot · Showing up to 200 CVEs. Counts above reflect all matching CVEs.")
        if data.empty:
            st.info("No rows to display.")
        else:
            render_table(
                data,
                numeric_cols=("severity_score", "epss_score"),
                chip_col="priority_tier",
                chip_colors=PRIORITY_ACCENT,
                max_height=540,
            )
        st.caption("Asset exposure is simulated. Priority thresholds are project-defined, not an official industry standard.")
    except Exception as exc:
        st.error(f"Unable to load Risk Mart: {exc}")
