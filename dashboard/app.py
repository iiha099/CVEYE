"""
app.py - CVE Threat Intelligence Dashboard (Streamlit)
=======================================================
Reads the six mart tables that dbt builds and shows them as an interactive
dashboard: vendors, severity trends, weaknesses (CWE), and AI/LLM-related
vulnerabilities mapped to OWASP Top 10 for LLM and MITRE ATLAS.

TWO DATA MODES
---------------
1. BigQuery (real): set GCP_PROJECT_ID (and GOOGLE_APPLICATION_CREDENTIALS) in
   the repo-root .env file. Marts are read from the BQ_DBT_DATASET dataset.
2. Local sample (automatic fallback): if BigQuery is not configured or fails,
   the app reads data/sample/mart_*.csv. These are SYNTHETIC numbers.

RUN (from the repo root):
    streamlit run dashboard/app.py
"""

import os
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st
from risk_queue import render_risk_queue

ROOT = Path(__file__).resolve().parent.parent
SAMPLE_DIR = ROOT / "data" / "sample"

try:
    from dotenv import load_dotenv

    load_dotenv(ROOT / ".env")
except ImportError:
    pass

_creds = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
if _creds and not os.path.isabs(_creds):
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = str((ROOT / _creds).resolve())

MARTS = [
    "mart_severity_trends",
    "mart_vendor_severity",
    "mart_cwe_trends",
    "mart_ai_trends",
    "mart_ai_cve_list",
    "mart_owasp_atlas",
]
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNSCORED"]
SEVERITY_COLUMN = {s: f"{s.lower()}_count" for s in SEVERITIES}
SEVERITY_COLORS = {
    "CRITICAL": "#d62728",
    "HIGH": "#ff7f0e",
    "MEDIUM": "#f2c94c",
    "LOW": "#2ca02c",
    "UNSCORED": "#9e9e9e",
}

st.set_page_config(page_title="CVE Threat Intelligence", page_icon="🛡️", layout="wide")


@st.cache_data(ttl=600, show_spinner="Loading data...")
def load_data():
    """Returns (dict of DataFrames, source label, warning or None)."""
    project_id = os.getenv("GCP_PROJECT_ID")
    warning = None

    if project_id:
        try:
            from google.cloud import bigquery

            client = bigquery.Client(project=project_id)
            dataset = os.getenv("BQ_DBT_DATASET") or "cve_dbt"
            frames = {
                name: client.query(f"SELECT * FROM `{project_id}.{dataset}.{name}`").to_dataframe()
                for name in MARTS
            }
            if "published_date" in frames["mart_ai_cve_list"].columns:
                frames["mart_ai_cve_list"]["published_date"] = frames["mart_ai_cve_list"]["published_date"].astype(str)
            return frames, "BigQuery (live)", None
        except Exception as exc:  # fall back, but tell the user why
            warning = f"Could not read BigQuery ({exc}). Showing local SYNTHETIC sample data instead."

    frames = {name: pd.read_csv(SAMPLE_DIR / f"{name}.csv") for name in MARTS}
    return frames, "Local sample data (synthetic)", warning


def color_scale():
    return alt.Scale(domain=list(SEVERITY_COLORS), range=list(SEVERITY_COLORS.values()))


frames, data_source, warning = load_data()
if warning:
    st.warning(warning)

sev_trends = frames["mart_severity_trends"].copy()
vendors = frames["mart_vendor_severity"].copy()
cwes = frames["mart_cwe_trends"].copy()
ai_trends = frames["mart_ai_trends"].copy()
ai_list = frames["mart_ai_cve_list"].copy()
owasp = frames["mart_owasp_atlas"].copy()

for df in (sev_trends, vendors, cwes, ai_trends, ai_list, owasp):
    df["published_year"] = df["published_year"].astype(int)

# ------------------------------------------------------------------ header
st.title("🛡️ CVE Threat Intelligence Dashboard")
st.caption(f"Source: NIST National Vulnerability Database (NVD) · Data mode: **{data_source}**")

# ----------------------------------------------------------------- sidebar
st.sidebar.header("Filters")
all_years = sorted(sev_trends["published_year"].unique().tolist())
if len(all_years) > 1:
    year_from, year_to = st.sidebar.select_slider(
        "Publication years", options=all_years, value=(all_years[0], all_years[-1])
    )
else:
    year_from = year_to = all_years[0]
selected_severities = st.sidebar.multiselect("Severity", options=SEVERITIES, default=SEVERITIES)
top_n = st.sidebar.slider("Top N (vendors / weaknesses)", min_value=5, max_value=20, value=10)
st.sidebar.caption(
    "UNSCORED = NVD has not published a CVSS score yet. This is common for recent CVEs, "
    "so recent years can look milder than they are."
)


def in_years(df):
    return df[(df["published_year"] >= year_from) & (df["published_year"] <= year_to)]


sev_f = in_years(sev_trends)
vendors_f = in_years(vendors)
cwes_f = in_years(cwes)
ai_f = in_years(ai_trends)
owasp_f = in_years(owasp)
ai_list_f = in_years(ai_list)

# --------------------------------------------------------------------- KPIs
total = int(sev_f["cve_count"].sum())
critical = int(sev_f.loc[sev_f["severity"] == "CRITICAL", "cve_count"].sum())
unscored = int(sev_f.loc[sev_f["severity"] == "UNSCORED", "cve_count"].sum())
ai_total = int(ai_f["ai_related_cves"].sum())
ai_den = int(ai_f["total_cves"].sum())

c1, c2, c3, c4 = st.columns(4)
c1.metric("CVEs in range", f"{total:,}")
c2.metric("Critical", f"{critical:,}")
c3.metric("AI/LLM-related", f"{ai_total:,}")
c3.caption(f"{(100 * ai_total / ai_den) if ai_den else 0:.1f}% of all CVEs")
c4.metric("Not yet scored", f"{(100 * unscored / total) if total else 0:.1f}%")
st.divider()
tab_vendor, tab_trend, tab_cwe, tab_ai, tab_risk = st.tabs(
    ["🏢 Vendors", "📈 Severity trends", "🧩 Weaknesses (CWE)", "🤖 AI & OWASP / ATLAS", "Patch priorities (P1-P4)"]
)

# ------------------------------------------------------------------ vendors
with tab_vendor:
    st.subheader("Most affected vendors")
    if not selected_severities:
        st.info("Select at least one severity in the sidebar.")
    else:
        cols = [SEVERITY_COLUMN[s] for s in selected_severities if SEVERITY_COLUMN[s] in vendors_f.columns]
        agg = vendors_f.groupby("vendor")[cols].sum()
        agg["selected_total"] = agg.sum(axis=1)
        top = agg.sort_values("selected_total", ascending=False).head(top_n).drop(columns="selected_total")
        long = top.reset_index().melt(id_vars="vendor", var_name="severity", value_name="count")
        long["severity"] = long["severity"].str.replace("_count", "", regex=False).str.upper()
        chart = (
            alt.Chart(long)
            .mark_bar()
            .encode(
                x=alt.X("count:Q", title="Number of CVEs"),
                y=alt.Y("vendor:N", sort="-x", title="Vendor"),
                color=alt.Color("severity:N", scale=color_scale(), legend=alt.Legend(title="Severity")),
                tooltip=["vendor", "severity", "count"],
            )
            .properties(height=max(300, 30 * len(top)))
        )
        st.altair_chart(chart, width="stretch")
        st.caption("Vendor 'unknown' (CVEs with no CPE data yet) is excluded.")

# ------------------------------------------------------------------- trends
with tab_trend:
    st.subheader("How severity changes over time")
    trend_f = sev_f[sev_f["severity"].isin(selected_severities)]
    chart = (
        alt.Chart(trend_f)
        .mark_line(point=True)
        .encode(
            x=alt.X("published_year:O", title="Year published"),
            y=alt.Y("cve_count:Q", title="Number of CVEs"),
            color=alt.Color("severity:N", scale=color_scale(), legend=alt.Legend(title="Severity")),
            tooltip=["published_year", "severity", "cve_count", "avg_cvss_score"],
        )
        .properties(height=400)
    )
    st.altair_chart(chart, width="stretch")
    st.caption("The latest year is incomplete (partial year), so compare it with care.")

# ---------------------------------------------------------------------- CWE
with tab_cwe:
    st.subheader("Most common weakness types (CWE)")
    top_cwe = cwes_f.groupby(["cwe_id", "cwe_name"], dropna=False)["cve_count"].sum().reset_index()
    top_cwe["label"] = top_cwe.apply(
        lambda r: r["cwe_id"] if pd.isna(r["cwe_name"]) else f"{r['cwe_id']} · {r['cwe_name']}", axis=1
    )
    top_cwe = top_cwe.sort_values("cve_count", ascending=False).head(top_n)
    chart = (
        alt.Chart(top_cwe)
        .mark_bar(color="#4c78a8")
        .encode(
            x=alt.X("cve_count:Q", title="Number of CVEs"),
            y=alt.Y("label:N", sort="-x", title=None),
            tooltip=["cwe_id", "cwe_name", "cve_count"],
        )
        .properties(height=max(300, 30 * len(top_cwe)))
    )
    st.altair_chart(chart, width="stretch")
    st.caption("Names are shown for the CWEs listed in dbt_cve/seeds/cwe_owasp_atlas.csv.")

# ----------------------------------------------------------------------- AI
with tab_ai:
    st.subheader("AI / LLM-related vulnerabilities")
    left, right = st.columns(2)
    with left:
        bars = (
            alt.Chart(ai_f)
            .mark_bar(color="#7b61ff")
            .encode(
                x=alt.X("published_year:O", title="Year published"),
                y=alt.Y("ai_related_cves:Q", title="AI-related CVEs"),
                tooltip=["published_year", "ai_related_cves", "ai_high_critical_cves", "ai_share_pct"],
            )
            .properties(height=320, title="Count per year")
        )
        st.altair_chart(bars, width="stretch")
    with right:
        share = (
            alt.Chart(ai_f)
            .mark_line(point=True, color="#e45756")
            .encode(
                x=alt.X("published_year:O", title="Year published"),
                y=alt.Y("ai_share_pct:Q", title="% of all CVEs"),
                tooltip=["published_year", "ai_share_pct"],
            )
            .properties(height=320, title="Share of all CVEs (%)")
        )
        st.altair_chart(share, width="stretch")
    st.caption("AI-related = the CVE description matches a keyword list (see dbt_cve/macros/ai_regex.sql). A heuristic, not ground truth.")

    st.subheader("CVEs mapped to OWASP Top 10 for LLM Applications")
    owasp_sum = (
        owasp_f.groupby(["owasp_llm_id", "owasp_llm_name"])["cve_count"].sum().reset_index()
        .assign(label=lambda d: d["owasp_llm_id"] + " · " + d["owasp_llm_name"])
        .sort_values("cve_count", ascending=False)
    )
    chart = (
        alt.Chart(owasp_sum)
        .mark_bar(color="#f58518")
        .encode(
            x=alt.X("cve_count:Q", title="Number of CVEs"),
            y=alt.Y("label:N", sort="-x", title=None),
            tooltip=["owasp_llm_id", "owasp_llm_name", "cve_count"],
        )
        .properties(height=max(220, 40 * len(owasp_sum)))
    )
    st.altair_chart(chart, width="stretch")

    atlas = owasp_f[owasp_f["atlas_technique_id"] != "n/a"]
    atlas_sum = (
        atlas.groupby(["atlas_technique_id", "atlas_technique_name"])["cve_count"].sum().reset_index()
        .sort_values("cve_count", ascending=False)
        .rename(columns={"atlas_technique_id": "ATLAS technique", "atlas_technique_name": "Name", "cve_count": "CVEs"})
    )
    st.markdown("**MITRE ATLAS techniques linked through CWE**")
    st.dataframe(atlas_sum, width="stretch", hide_index=True)
    st.caption("The CWE → OWASP/ATLAS mapping is an analytical choice made by the team (dbt_cve/seeds/cwe_owasp_atlas.csv).")

    st.subheader("Latest AI/LLM-related CVEs")
    show = ai_list_f[["cve_id", "published_date", "severity", "cvss_score", "vendor", "product", "cwe_id", "description"]]
    st.dataframe(show.head(100), width="stretch", hide_index=True)

with tab_risk:
    render_risk_queue(data_source)

st.divider()
st.caption("CVE Threat Intelligence Pipeline · Le Wagon Data Engineering final project")
