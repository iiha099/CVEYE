"""
app.py - CVEYE · CVE Threat Intelligence Dashboard (Streamlit)
=================================================================
Reads the six mart tables that dbt builds and shows them as an interactive
dashboard: vendors, severity trends, weaknesses (CWE), AI/LLM-related
vulnerabilities mapped to OWASP Top 10 for LLM and MITRE ATLAS, and the
Patch Priority Queue.

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
import gcp_auth
import pandas as pd
import streamlit as st
from risk_queue import render_risk_queue
from theme import (
    ACCENT,
    ACCENT_PAIRED,
    CATEGORICAL,
    SEVERITY_COLORS,
    get_theme,
    inject_css,
    render_footer,
    render_hero,
    render_sidebar_brand,
    render_sidebar_status,
    render_table,
    stat_cards,
    style_chart,
)

ROOT = Path(__file__).resolve().parent.parent
SAMPLE_DIR = ROOT / "data" / "sample"

try:
    from dotenv import load_dotenv

    load_dotenv(ROOT / ".env")
except ImportError:
    pass

GCP_IDENTITY = gcp_auth.apply(ROOT)

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

st.set_page_config(page_title="CVEYE · CVE Threat Intelligence", page_icon="🦅", layout="wide")

if "cveye_dark" not in st.session_state:
    st.session_state["cveye_dark"] = True

inject_css(get_theme())


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
            warning = (
                f"Could not read BigQuery as {GCP_IDENTITY}: {exc}. "
                f"{gcp_auth.hint(project_id)} Showing local SYNTHETIC sample data instead."
            )

    frames = {name: pd.read_csv(SAMPLE_DIR / f"{name}.csv") for name in MARTS}
    return frames, "Local sample data (synthetic)", warning


@st.cache_data(ttl=600)
def load_recent_critical(project_id, dataset, days=30, limit=25):
    """Latest CRITICAL/HIGH CVEs, for the "what needs attention now" table.

    Reads the staging table directly (not a mart) - this is a simple recency
    query, not an analytical aggregation, so a dedicated mart would be
    overkill. Returns None if the table/columns aren't available yet, so the
    caller can show a calm "not available" message instead of crashing.
    """
    from google.cloud import bigquery
    from google.api_core.exceptions import NotFound

    client = bigquery.Client(project=project_id)
    table_ref = f"{project_id}.{dataset}.stg_cves"
    try:
        table = client.get_table(table_ref)
    except NotFound:
        return None

    needed = {"cve_id", "published_date", "severity", "cvss_score", "vendor", "product", "description"}
    have = {f.name for f in table.schema}
    if not needed.issubset(have):
        return None

    sql = f"""
        SELECT cve_id, published_date, severity, cvss_score, vendor, product, description
        FROM `{table_ref}`
        WHERE severity IN ('CRITICAL', 'HIGH')
          AND published_date >= DATE_SUB(CURRENT_DATE(), INTERVAL {int(days)} DAY)
        ORDER BY published_date DESC, cvss_score DESC
        LIMIT {int(limit)}
    """
    return client.query(sql).to_dataframe()


def color_scale():
    return alt.Scale(domain=list(SEVERITY_COLORS), range=list(SEVERITY_COLORS.values()))


frames, data_source, warning = load_data()

render_hero(data_source)
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

# ----------------------------------------------------------------- sidebar
render_sidebar_brand(data_source)
st.sidebar.markdown(
    '<p class="cveye-eyebrow" style="margin-bottom:10px;">📊 Filters</p>', unsafe_allow_html=True
)
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
render_sidebar_status(data_source)


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


def _yoy_sub(df, year, severity=None, label="total CVEs"):
    """Year-over-year change for the last two complete-enough years in range,
    e.g. 'vs 2025: +4,210'. Returns a neutral caption if there's no prior
    year to compare against - never a fabricated number."""
    prior = year - 1
    if prior not in all_years:
        return None, False
    cur = df[df["published_year"] == year]
    prev = df[df["published_year"] == prior]
    if severity:
        cur = cur[cur["severity"] == severity]
        prev = prev[prev["severity"] == severity]
    cur_n, prev_n = int(cur["cve_count"].sum()), int(prev["cve_count"].sum())
    if prev_n == 0:
        return None, False
    pct = 100 * (cur_n - prev_n) / prev_n
    arrow = "↑" if pct >= 0 else "↓"
    return f"{arrow} {abs(pct):.0f}% vs {prior}", pct >= 0


total_sub, total_up = _yoy_sub(sev_trends, year_to)
crit_sub, crit_up = _yoy_sub(sev_trends, year_to, severity="CRITICAL")

stat_cards(
    [
        {
            "label": "CVEs in range", "value": f"{total:,}", "icon": "🛡️",
            "sub": total_sub or f"{year_from}–{year_to}", "up": total_up,
            "accent": SEVERITY_COLORS["UNSCORED"],
        },
        {
            "label": "Critical", "value": f"{critical:,}", "icon": "⚠️",
            "sub": crit_sub or "needs the fastest response", "up": crit_up,
            "accent": SEVERITY_COLORS["CRITICAL"],
        },
        {
            "label": "AI / LLM-related", "value": f"{ai_total:,}", "icon": "🤖",
            "sub": f"{(100 * ai_total / ai_den) if ai_den else 0:.1f}% of all CVEs",
            "accent": ACCENT_PAIRED,
        },
        {
            "label": "Not yet scored", "value": f"{(100 * unscored / total) if total else 0:.1f}%", "icon": "⏳",
            "sub": "pending a CVSS score from NVD", "accent": SEVERITY_COLORS["MEDIUM"],
        },
    ]
)

# ------------------------------------------------------- latest critical CVEs
st.markdown("")
st.markdown('<p class="cveye-eyebrow">Live triage</p>', unsafe_allow_html=True)
st.subheader("Latest critical & high CVEs")
st.caption("Last 30 days — what a security team would triage first, no filtering needed.")
if data_source == "BigQuery (live)":
    project_id = os.getenv("GCP_PROJECT_ID")
    dataset = os.getenv("BQ_DBT_DATASET", "cve_dbt")
    try:
        recent = load_recent_critical(project_id, dataset)
    except Exception as exc:
        recent = None
        st.error(f"Could not load recent CVEs: {exc}")
    if recent is None:
        st.info("Not available yet - waiting on the staging table columns this needs.")
    elif recent.empty:
        st.info("No CRITICAL/HIGH CVEs published in the last 30 days. Good news.")
    else:
        render_table(
            recent,
            numeric_cols=("cvss_score",),
            chip_col="severity",
            chip_colors=SEVERITY_COLORS,
            max_height=420,
        )
else:
    st.info("Switch to BigQuery (live) mode to see this table - not meaningful on synthetic sample data.")

st.divider()
tab_vendor, tab_trend, tab_cwe, tab_ai, tab_risk = st.tabs(
    ["🏢 Vendors", "📈 Severity trends", "🧩 Weaknesses (CWE)", "🤖 AI & OWASP / ATLAS", "🎯 Patch priorities (P1-P4)"]
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
        st.altair_chart(style_chart(chart), width="stretch")
        st.caption("Vendor 'unknown' (CVEs with no CPE data yet) is excluded.")

# ------------------------------------------------------------------- trends
with tab_trend:
    st.subheader("How severity changes over time")
    trend_f = sev_f[sev_f["severity"].isin(selected_severities)]

    left, right = st.columns(2)
    with left:
        st.caption("Count per year")
        chart = (
            alt.Chart(trend_f)
            .mark_line(point=True)
            .encode(
                x=alt.X("published_year:O", title="Year published"),
                y=alt.Y("cve_count:Q", title="Number of CVEs"),
                color=alt.Color("severity:N", scale=color_scale(), legend=alt.Legend(title="Severity")),
                tooltip=["published_year", "severity", "cve_count", "avg_cvss_score"],
            )
            .properties(height=380)
        )
        st.altair_chart(style_chart(chart), width="stretch")
    with right:
        st.caption("Share of CVEs that year (%) - fixes the 'this year looks mild' illusion")
        pct_chart = (
            alt.Chart(trend_f)
            .mark_bar()
            .encode(
                x=alt.X("published_year:O", title="Year published"),
                y=alt.Y("cve_count:Q", title="Share of CVEs", stack="normalize", axis=alt.Axis(format="%")),
                color=alt.Color("severity:N", scale=color_scale(), legend=alt.Legend(title="Severity")),
                order=alt.Order("severity:N"),
                tooltip=["published_year", "severity", "cve_count"],
            )
            .properties(height=380)
        )
        st.altair_chart(style_chart(pct_chart), width="stretch")
    st.caption(
        "The latest year is incomplete (partial year) - the left chart's final point will keep "
        "rising; the right chart already accounts for that by showing proportion, not raw count."
    )

# ---------------------------------------------------------------------- CWE
with tab_cwe:
    st.subheader("Most common weakness types (CWE)")
    top_cwe = cwes_f.groupby(["cwe_id", "cwe_name"], dropna=False)["cve_count"].sum().reset_index()
    top_cwe["label"] = top_cwe.apply(
        lambda r: r["cwe_id"] if pd.isna(r["cwe_name"]) else f"{r['cwe_id']} · {r['cwe_name']}", axis=1
    )
    top_cwe = top_cwe.sort_values("cve_count", ascending=False).head(top_n)
    bar_height = max(300, 30 * len(top_cwe))
    t = get_theme()
    base = alt.Chart(top_cwe).encode(
        x=alt.X("cve_count:Q", title="Number of CVEs"),
        y=alt.Y("label:N", sort="-x", title=None, axis=alt.Axis(labelLimit=320)),
    )
    bars = base.mark_bar(color=ACCENT).encode(
        tooltip=["cwe_id", "cwe_name", "cve_count"],
    )
    labels = base.mark_text(align="left", dx=4, color=t["chart_label"]).encode(
        text=alt.Text("cve_count:Q", format=","),
    )
    st.altair_chart(style_chart((bars + labels).properties(height=bar_height)), width="stretch")
    missing_names = int(top_cwe["cwe_name"].isna().sum())
    if missing_names:
        st.caption(
            f"Names are shown for the CWEs listed in dbt_cve/seeds/cwe_owasp_atlas.csv "
            f"- {missing_names} of the {len(top_cwe)} shown here aren't in that list yet, "
            f"so they display as a bare ID."
        )
    else:
        st.caption("Names are shown for the CWEs listed in dbt_cve/seeds/cwe_owasp_atlas.csv.")

    st.divider()
    st.subheader("CWE trend over time")
    st.caption(
        "How the top weakness types have shifted year to year - a static ranking "
        "can hide a weakness that's emerging (or fading) that the total doesn't show."
    )
    trend_n = min(top_n, 8)  # cap at 8: beyond that, line colors stop being reliably distinct
    trend_ids = top_cwe["cwe_id"].head(trend_n).tolist()
    cwe_trend_f = cwes_f[cwes_f["cwe_id"].isin(trend_ids)].copy()
    cwe_trend_f["label"] = cwe_trend_f.apply(
        lambda r: r["cwe_id"] if pd.isna(r["cwe_name"]) else f"{r['cwe_id']} · {r['cwe_name']}", axis=1
    )
    line = (
        alt.Chart(cwe_trend_f)
        .mark_line(point=True)
        .encode(
            x=alt.X("published_year:O", title="Year published"),
            y=alt.Y("cve_count:Q", title="Number of CVEs"),
            color=alt.Color("label:N", title="CWE", scale=alt.Scale(range=CATEGORICAL)),
            tooltip=["published_year", "label", "cve_count"],
        )
        .properties(height=380)
    )
    st.altair_chart(style_chart(line), width="stretch")
    if top_n > trend_n:
        st.caption(
            f"Showing the top {trend_n} of the {top_n} selected (sidebar) for readability - "
            "the ranking above still reflects all of them."
        )

# ----------------------------------------------------------------------- AI
with tab_ai:
    st.subheader("AI / LLM-related vulnerabilities")
    left, right = st.columns(2)
    with left:
        bars = (
            alt.Chart(ai_f)
            .mark_bar(color=ACCENT)
            .encode(
                x=alt.X("published_year:O", title="Year published"),
                y=alt.Y("ai_related_cves:Q", title="AI-related CVEs"),
                tooltip=["published_year", "ai_related_cves", "ai_high_critical_cves", "ai_share_pct"],
            )
            .properties(height=320, title="Count per year")
        )
        st.altair_chart(style_chart(bars), width="stretch")
    with right:
        share = (
            alt.Chart(ai_f)
            .mark_line(point=True, color=ACCENT_PAIRED)
            .encode(
                x=alt.X("published_year:O", title="Year published"),
                y=alt.Y("ai_share_pct:Q", title="% of all CVEs"),
                tooltip=["published_year", "ai_share_pct"],
            )
            .properties(height=320, title="Share of all CVEs (%)")
        )
        st.altair_chart(style_chart(share), width="stretch")
    st.caption("AI-related = the CVE description matches a keyword list (see dbt_cve/macros/ai_regex.sql). A heuristic, not ground truth.")

    st.subheader("CVEs mapped to OWASP Top 10 for LLM Applications")
    owasp_sum = (
        owasp_f.groupby(["owasp_llm_id", "owasp_llm_name"])["cve_count"].sum().reset_index()
        .assign(label=lambda d: d["owasp_llm_id"] + " · " + d["owasp_llm_name"])
        .sort_values("cve_count", ascending=False)
    )
    chart = (
        alt.Chart(owasp_sum)
        .mark_bar(color=ACCENT)
        .encode(
            x=alt.X("cve_count:Q", title="Number of CVEs"),
            y=alt.Y("label:N", sort="-x", title=None),
            tooltip=["owasp_llm_id", "owasp_llm_name", "cve_count"],
        )
        .properties(height=max(220, 40 * len(owasp_sum)))
    )
    st.altair_chart(style_chart(chart), width="stretch")

    atlas = owasp_f[owasp_f["atlas_technique_id"] != "n/a"]
    atlas_sum = (
        atlas.groupby(["atlas_technique_id", "atlas_technique_name"])["cve_count"].sum().reset_index()
        .sort_values("cve_count", ascending=False)
        .rename(columns={"atlas_technique_id": "ATLAS technique", "atlas_technique_name": "Name", "cve_count": "CVEs"})
    )
    st.markdown("**MITRE ATLAS techniques linked through CWE**")
    render_table(atlas_sum, numeric_cols=("CVEs",), max_height=320)
    st.caption("The CWE → OWASP/ATLAS mapping is an analytical choice made by the team (dbt_cve/seeds/cwe_owasp_atlas.csv).")

    st.subheader("Latest AI/LLM-related CVEs")
    show = ai_list_f[["cve_id", "published_date", "severity", "cvss_score", "vendor", "product", "cwe_id", "description"]]
    render_table(
        show.head(100),
        numeric_cols=("cvss_score",),
        chip_col="severity",
        chip_colors=SEVERITY_COLORS,
        max_height=480,
    )

with tab_risk:
    render_risk_queue(data_source)

render_footer()
