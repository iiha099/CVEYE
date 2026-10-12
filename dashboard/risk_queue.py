"""Patch Priority Queue: reads the team's risk mart."""

import os
import streamlit as st
from google.cloud import bigquery
from google.api_core.exceptions import NotFound

TABLE_NAME = "fct_cve_daily_risk"

REQUIRED = {
    "snapshot_date", "cve_id", "priority_tier",
    "severity_score", "epss_score",
    "in_kev", "affects_our_assets"
}


@st.cache_data(ttl=600)
def load_priorities(project, dataset, tiers):
    client = bigquery.Client(project=project)
    table = f"{project}.{dataset}.{TABLE_NAME}"

    sql = f"""
        SELECT
            snapshot_date,
            cve_id,
            priority_tier,
            severity_score,
            epss_score,
            in_kev,
            affects_our_assets
        FROM `{table}`
        WHERE snapshot_date = (
            SELECT MAX(snapshot_date) FROM `{table}`
        )
        AND priority_tier IN UNNEST(@tiers)
        ORDER BY
            CASE priority_tier
                WHEN 'P1' THEN 1
                WHEN 'P2' THEN 2
                WHEN 'P3' THEN 3
                WHEN 'P4' THEN 4
                ELSE 5
            END,
            epss_score DESC,
            severity_score DESC
        LIMIT 200
    """

    config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ArrayQueryParameter(
                "tiers", "STRING", list(tiers)
            )
        ],
        maximum_bytes_billed=1_000_000_000,
    )
    return client.query(
        sql, job_config=config
    ).to_dataframe()


def render_risk_queue(data_source):
    st.subheader("Patch Priority Queue (P1-P4)")
    st.caption(
        "Prioritize CVEs using KEV, EPSS, CVSS "
        "and simulated asset exposure."
    )

    if data_source != "BigQuery (live)":
        st.info("Live BigQuery data is required.")
        return

    project = os.getenv("GCP_PROJECT_ID")
    dataset = os.getenv("BQ_DBT_DATASET", "cve_dbt")

    if not project:
        st.warning("GCP_PROJECT_ID is missing.")
        return

    try:
        client = bigquery.Client(project=project)
        table = client.get_table(
            f"{project}.{dataset}.{TABLE_NAME}"
        )
    except NotFound:
        st.info(
            "Risk Mart is not available yet. "
            "Waiting for the team's "
            "fct_cve_daily_risk table."
        )
        return
    except Exception as exc:
        st.error(f"BigQuery connection error: {exc}")
        return

    columns = {field.name for field in table.schema}
    missing = REQUIRED - columns

    if missing:
        st.warning(
            "Missing columns: " + ", ".join(sorted(missing))
        )
        return

    tiers = st.multiselect(
        "Priority",
        ["P1", "P2", "P3", "P4"],
        default=["P1", "P2", "P3", "P4"],
    )

    if not tiers:
        st.info("Select at least one priority.")
        return

    try:
        data = load_priorities(
            project, dataset, tuple(tiers)
        )
        if data.empty:
            st.info("No CVEs found for these priorities.")
        else:
            st.caption(
                "Latest risk snapshot - up to 200 rows."
            )
            st.dataframe(
                data, width="stretch", hide_index=True
            )
    except Exception as exc:
        st.error(f"Unable to load Risk Mart: {exc}")
