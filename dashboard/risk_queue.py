"""Patch Priority Queue: reads the team's risk mart."""

import os
import streamlit as st
from google.cloud import bigquery
from google.api_core.exceptions import NotFound

from theme import ACCENT, SEVERITY_COLORS, render_table, stat_cards

TABLE_NAME = "fct_cve_daily_risk"

REQUIRED = {
    "snapshot_date", "cve_id", "priority_tier",
    "severity_score", "epss_score",
    "in_kev", "affects_our_assets"
}

# Same status palette as the main dashboard (app.py / theme.py) - P1 is the
# worst case so it reuses the CRITICAL color, P4 the mildest reuses the
# brand accent green ("safe"). Icon + label always goes together with the
# color, never color alone (status colors aren't reliably distinguishable
# for every viewer).
PRIORITY_ACCENT = {
    "P1": SEVERITY_COLORS["CRITICAL"],
    "P2": SEVERITY_COLORS["HIGH"],
    "P3": SEVERITY_COLORS["MEDIUM"],
    "P4": ACCENT,
}
PRIORITY_SUB = {
    "P1": "patch this week",
    "P2": "patch this sprint",
    "P3": "track, no rush",
    "P4": "safe to defer",
}
PRIORITY_ICON = {
    "P1": "🔴",
    "P2": "🟠",
    "P3": "🟡",
    "P4": "🟢",
}
PRIORITY_LABEL = {
    "P1": "P1 · Critical",
    "P2": "P2 · Serious",
    "P3": "P3 · Warning",
    "P4": "P4 · Low",
}


@st.cache_data(ttl=600)
def load_tier_counts(project, dataset, tiers):
    """TRUE count per tier on the latest snapshot - independent of the
    200-row LIMIT used for the detail table below. Without this, the stat
    tiles were just counting whatever happened to survive the detail
    query's ORDER BY + LIMIT, which silently drops P3/P4 whenever P1+P2
    alone already fill 200 rows."""
    client = bigquery.Client(project=project)
    table = f"{project}.{dataset}.{TABLE_NAME}"

    sql = f"""
        SELECT priority_tier, COUNT(*) AS n
        FROM `{table}`
        WHERE snapshot_date = (
            SELECT MAX(snapshot_date) FROM `{table}`
        )
        AND priority_tier IN UNNEST(@tiers)
        GROUP BY priority_tier
    """

    config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ArrayQueryParameter(
                "tiers", "STRING", list(tiers)
            )
        ],
        maximum_bytes_billed=1_000_000_000,
    )
    df = client.query(sql, job_config=config).to_dataframe()
    return dict(zip(df["priority_tier"], df["n"]))


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
        # True totals per tier, NOT limited to the 200-row detail sample.
        tier_counts = load_tier_counts(project, dataset, tuple(tiers))

        data = load_priorities(
            project, dataset, tuple(tiers)
        )
        if sum(tier_counts.values()) == 0:
            st.info("No CVEs found for these priorities.")
        else:
            st.caption(
                "Latest risk snapshot - stat tiles show true totals; "
                "table below is capped at 200 rows for display."
            )
            # true counts per tier, as small colored stat tiles - computed
            # from a separate COUNT query so they're never cut off by the
            # detail table's LIMIT 200
            stat_cards(
                [
                    {
                        "label": PRIORITY_LABEL.get(tier, tier),
                        "value": f"{int(tier_counts.get(tier, 0)):,}",
                        "icon": PRIORITY_ICON.get(tier, "●"),
                        "sub": PRIORITY_SUB.get(tier, ""),
                        "accent": PRIORITY_ACCENT.get(tier, "#00E676"),
                    }
                    for tier in sorted(tiers)
                ]
            )

            if data.empty:
                st.info("No rows to display for the selected priorities.")
            else:
                render_table(
                    data,
                    numeric_cols=("severity_score", "epss_score"),
                    chip_col="priority_tier",
                    chip_colors=PRIORITY_ACCENT,
                    max_height=460,
                )
    except Exception as exc:
        st.error(f"Unable to load Risk Mart: {exc}")
