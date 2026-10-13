"""
theme.py - CVEYE visual system
================================
One place that owns: color tokens for light/dark mode, the CSS injected into
the page, the Altair chart styling helper, small HTML component renderers
(hero header, stat cards, section footer), and a fully custom HTML table
renderer.

Why a custom table renderer instead of st.dataframe
-----------------------------------------------------
st.dataframe's grid is a separate component (glide-data-grid) that reads
Streamlit's own global theme context, not CSS we inject and not our own
light/dark toggle. There is no supported per-call way to force it into a
specific color set. Since every table in this app must react to CVEYE's own
theme switch - not just the page chrome around it - tables are rendered as
plain HTML/CSS we fully control instead.

Nothing here touches data. app.py and risk_queue.py import from this module
so the whole dashboard reads as one consistent, branded product instead of
default Streamlit chrome with a logo pasted on top.
"""

import base64
import html
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

ASSETS = Path(__file__).resolve().parent / "assets"

# ---------------------------------------------------------------------------
# Color tokens - DARK matches the reference style guide exactly:
#   Primary Green #00E676 · Secondary Teal #0EA5A6 · Dark Background #1F2937
#   Card Background #111822 · Text Primary #E5E7EB · Text Secondary #9CA3AF
#   Critical/Danger #EF4444 · Warning #F59E0B
# LIGHT is the same system rebuilt on a white surface, same accent hues, so a
# color still means the same thing in both modes.
DARK = {
    "mode": "dark",
    "bg": "#1F2937",
    "bg_grad": "radial-gradient(1100px 480px at 12% -12%, #16331f 0%, #1F2937 55%)",
    "surface": "#111822",
    "surface_alt": "#0c121a",
    "border": "#263241",
    "text": "#E5E7EB",
    "muted": "#9CA3AF",
    "accent": "#00E676",
    "accent_strong": "#34f598",
    "accent_soft": "rgba(0, 230, 118, 0.14)",
    "teal": "#0EA5A6",
    "teal_soft": "rgba(14, 165, 166, 0.14)",
    "shadow": "0 18px 40px -22px rgba(0,0,0,0.65)",
    "chart_bg": "transparent",
    "chart_grid": "#26323f",
    "chart_label": "#9CA3AF",
    "chart_title": "#E5E7EB",
    "table_head_bg": "#0c121a",
    "table_row_hover": "rgba(0, 230, 118, 0.06)",
    "table_row_alt": "rgba(255,255,255,0.015)",
}
LIGHT = {
    "mode": "light",
    "bg": "#F4F6F8",
    "bg_grad": "radial-gradient(1100px 480px at 12% -12%, #e3f9ec 0%, #F4F6F8 55%)",
    "surface": "#FFFFFF",
    "surface_alt": "#EEF1F4",
    "border": "#E2E8F0",
    "text": "#111822",
    "muted": "#64748B",
    "accent": "#00C767",
    "accent_strong": "#009e52",
    "accent_soft": "rgba(0, 199, 103, 0.10)",
    "teal": "#0b8687",
    "teal_soft": "rgba(11, 134, 135, 0.10)",
    "shadow": "0 16px 36px -24px rgba(17, 24, 34, 0.22)",
    "chart_bg": "transparent",
    "chart_grid": "#E7ECF1",
    "chart_label": "#52606d",
    "chart_title": "#111822",
    "table_head_bg": "#F8FAFC",
    "table_row_hover": "rgba(0, 199, 103, 0.06)",
    "table_row_alt": "rgba(17,24,34,0.015)",
}

# Status palette stays constant across themes - a color always means the same
# risk level whether the page is light or dark.
SEVERITY_COLORS = {
    "CRITICAL": "#EF4444",
    "HIGH": "#F59E0B",
    "MEDIUM": "#3B82F6",
    "LOW": "#0EA5A6",
    "UNSCORED": "#9CA3AF",
}
CATEGORICAL = [
    "#00E676", "#3B82F6", "#F59E0B", "#EF4444",
    "#0EA5A6", "#A78BFA", "#F472B6", "#84CC16",
]
ACCENT = "#00E676"
ACCENT_PAIRED = "#0EA5A6"


def get_theme() -> dict:
    return DARK if st.session_state.get("cveye_dark", True) else LIGHT


@st.cache_data(show_spinner=False)
def _logo_b64() -> str:
    path = ASSETS / "cveye_logo.png"
    if not path.exists():
        return ""
    return base64.b64encode(path.read_bytes()).decode("ascii")


def inject_css(t: dict) -> None:
    st.markdown(
        f"""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500&display=swap');

        html, body, [class*="css"] {{ font-family: 'Inter', -apple-system, sans-serif; }}

        .stApp {{
            background: {t['bg_grad']};
            background-color: {t['bg']};
            color: {t['text']};
        }}
        [data-testid="stHeader"] {{ background: transparent; }}
        [data-testid="stSidebar"] {{
            background: {t['surface_alt']};
            border-right: 1px solid {t['border']};
            color: {t['text']};
        }}
        /* Scoped to Streamlit's own widget text only - never *, so our
           custom .cveye-side-* elements below keep their own muted/accent
           colors instead of being forced back to full-text color. */
        [data-testid="stSidebar"] label p,
        [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p,
        [data-testid="stSidebar"] span {{ color: {t['text']}; }}
        [data-testid="stSidebar"] label p {{ font-weight: 600; font-size: 13px; letter-spacing: .3px; }}
        [data-testid="stSidebarUserContent"] {{ padding-top: 1.2rem; }}
        .block-container {{ padding-top: 1.6rem; padding-bottom: 2.5rem; max-width: 1320px; }}
        p, span, div, label {{ color: {t['text']}; }}

        /* ---- sidebar brand block --------------------------------------- */
        .cveye-side-brand {{ display:flex; align-items:center; gap:10px; padding: 2px 2px 18px 2px;
            border-bottom: 1px solid {t['border']}; margin-bottom: 16px; }}
        .cveye-side-brand img {{ height: 30px; }}
        .cveye-side-brand-name {{ font-size: 16px; font-weight: 800; letter-spacing: .5px; margin:0; }}
        .cveye-side-brand-sub {{ font-size: 10.5px; color: {t['muted']} !important; letter-spacing: 1.5px;
            text-transform: uppercase; margin: 0; }}
        .cveye-side-status {{ display:flex; align-items:center; gap:8px; font-size: 12px; color: {t['muted']} !important;
            padding-top: 14px; margin-top: 14px; border-top: 1px solid {t['border']}; }}
        .cveye-side-dot {{ width:7px; height:7px; border-radius:50%; background:{t['accent']};
            box-shadow: 0 0 0 3px {t['accent_soft']}; }}

        /* ---- hero ---------------------------------------------------- */
        .cveye-hero {{
            display: flex; align-items: center; justify-content: space-between;
            gap: 24px; padding: 20px 28px; border-radius: 18px; margin-bottom: 20px;
            background: linear-gradient(135deg, {t['surface']} 0%, {t['surface_alt']} 100%);
            border: 1px solid {t['border']}; box-shadow: {t['shadow']};
        }}
        .cveye-hero-left {{ display: flex; align-items: center; gap: 16px; }}
        .cveye-hero img {{ height: 46px; width: auto; display: block; }}
        .cveye-hero-tag {{ font-size: 13px; font-weight: 500; color: {t['muted']}; margin: 0; }}
        .cveye-hero-tag b {{ color: {t['text']}; font-weight: 700; }}
        .cveye-hero-tag .accent {{ color: {t['accent']}; font-weight: 700; }}
        .cveye-badge {{
            display: inline-flex; align-items: center; gap: 7px; font-size: 12px;
            font-family: 'JetBrains Mono', monospace; font-weight: 600; padding: 6px 13px; border-radius: 999px;
            background: {t['accent_soft']}; color: {t['accent_strong']}; border: 1px solid {t['border']};
            white-space: nowrap; letter-spacing: .4px;
        }}
        .cveye-badge-dot {{ width: 7px; height: 7px; border-radius: 50%; background: currentColor; }}

        /* ---- stat cards ------------------------------------------------ */
        .cveye-stat {{
            background: {t['surface']}; border: 1px solid {t['border']}; border-radius: 14px;
            padding: 16px 18px; box-shadow: {t['shadow']}; height: 100%;
            transition: transform .15s ease;
        }}
        .cveye-stat:hover {{ transform: translateY(-2px); }}
        .cveye-stat-top {{ display:flex; align-items:center; justify-content:space-between; margin-bottom: 10px; }}
        .cveye-stat-icon {{ width: 34px; height: 34px; border-radius: 10px; display:flex; align-items:center;
            justify-content:center; font-size: 16px; background: var(--accent-soft); color: var(--accent); }}
        .cveye-stat-label {{ font-size: 12.5px; font-weight: 600; letter-spacing: .3px;
            color: {t['muted']}; margin: 0; }}
        .cveye-stat-value {{ font-size: 27px; font-weight: 800; color: {t['text']}; margin: 2px 0 0 0; line-height: 1.1; }}
        .cveye-stat-sub {{ font-size: 12px; color: {t['muted']}; margin: 5px 0 0 0; }}
        .cveye-stat-sub.up {{ color: {t['accent_strong']}; font-weight: 600; }}

        /* ---- section headers ------------------------------------------ */
        h2, h3 {{ color: {t['text']}; font-weight: 700; letter-spacing: -.2px; }}
        .cveye-eyebrow {{ font-family: 'JetBrains Mono', monospace; font-size: 11.5px; letter-spacing: 3px;
            color: {t['accent']} !important; text-transform: uppercase; margin-bottom: 4px; font-weight: 600; }}

        /* ---- tabs -------------------------------------------------- */
        [data-baseweb="tab-list"] {{ gap: 4px; border-bottom: 1px solid {t['border']}; }}
        [data-baseweb="tab"] {{
            font-weight: 600; font-size: 14.5px; color: {t['muted']};
            padding: 10px 18px; border-radius: 10px 10px 0 0;
        }}
        [aria-selected="true"][data-baseweb="tab"] {{
            color: {t['accent_strong']} !important; background: {t['accent_soft']};
        }}
        [data-baseweb="tab-highlight"] {{ background-color: {t['accent']} !important; }}
        [data-baseweb="tab-border"] {{ background-color: {t['border']} !important; }}

        /* ---- themed HTML tables ----------------------------------------- */
        .cveye-table-wrap {{ border: 1px solid {t['border']}; border-radius: 14px; overflow: hidden;
            box-shadow: {t['shadow']}; background: {t['surface']}; }}
        .cveye-table-scroll {{ max-height: var(--max-h, 440px); overflow-y: auto; }}
        table.cveye-table {{ width: 100%; border-collapse: collapse; font-size: 13.5px; }}
        table.cveye-table thead th {{
            position: sticky; top: 0; z-index: 1; background: {t['table_head_bg']};
            text-align: left; font-weight: 700; font-size: 11.5px; letter-spacing: .5px;
            text-transform: uppercase; color: {t['muted']}; padding: 11px 16px;
            border-bottom: 1px solid {t['border']};
        }}
        table.cveye-table th.num, table.cveye-table td.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
        table.cveye-table tbody td {{ padding: 10px 16px; border-bottom: 1px solid {t['border']};
            color: {t['text']}; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 360px; }}
        table.cveye-table tbody tr:nth-child(even) {{ background: {t['table_row_alt']}; }}
        table.cveye-table tbody tr:hover {{ background: {t['table_row_hover']}; }}
        table.cveye-table tbody tr:last-child td {{ border-bottom: none; }}
        .cveye-empty {{ padding: 28px; text-align:center; color: {t['muted']}; font-size: 13.5px; }}
        .cveye-chip {{ display:inline-flex; align-items:center; gap:5px; padding: 2px 9px; border-radius: 999px;
            font-size: 11.5px; font-weight: 700; letter-spacing: .2px; }}

        /* ---- misc Streamlit chrome ------------------------------------ */
        [data-testid="stMetricValue"] {{ color: {t['text']}; }}
        hr {{ border-color: {t['border']}; }}
        [data-testid="stCaptionContainer"] {{ color: {t['muted']} !important; }}
        [data-testid="stCaptionContainer"] p {{ color: {t['muted']} !important; }}
        .stAlert {{ border-radius: 12px; }}

        /* ---- footer ----------------------------------------------- */
        .cveye-footer {{ display: flex; align-items: center; justify-content: center; gap: 10px;
            padding: 24px 0 6px 0; opacity: .85; }}
        .cveye-footer img {{ height: 18px; }}
        .cveye-footer span {{ font-size: 12px; color: {t['muted']}; font-family: 'JetBrains Mono', monospace; }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_hero(data_source: str) -> None:
    logo = _logo_b64()
    t = get_theme()
    logo_html = (
        f'<img src="data:image/png;base64,{logo}" alt="CVEYE" />'
        if logo else '<span style="font-size:28px">🦅</span>'
    )
    live = data_source == "BigQuery (live)"
    badge_text = "LIVE · BIGQUERY" if live else "SAMPLE DATA"
    badge_color = t["accent"] if live else "#F59E0B"

    left, right = st.columns([3.2, 1], vertical_alignment="center")
    with left:
        st.markdown(
            f"""
            <div class="cveye-hero">
              <div class="cveye-hero-left">
                {logo_html}
                <div>
                  <p class="cveye-hero-tag"><b>More than data...</b> It's a <span class="accent">clear vision.</span></p>
                  <p class="cveye-hero-tag" style="margin-top:3px;">Watching the CVE landscape so your security
                  team doesn't have to — vendors, severity, AI/LLM exposure, and what to patch first.</p>
                </div>
              </div>
              <div class="cveye-badge" style="color:{badge_color}"><span class="cveye-badge-dot"></span>{badge_text}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with right:
        # NOTE: no value= here on purpose - the default is set once via
        # st.session_state in app.py before this widget is created. Passing
        # both a pre-set session_state value AND value= raises a Streamlit
        # API warning/exception.
        st.toggle("🌙 Dark mode", key="cveye_dark")


def render_sidebar_brand(data_source: str) -> None:
    logo = _logo_b64()
    logo_html = f'<img src="data:image/png;base64,{logo}" alt="CVEYE"/>' if logo else "🦅"
    st.sidebar.markdown(
        f"""
        <div class="cveye-side-brand">
          {logo_html}
          <div>
            <p class="cveye-side-brand-name">CVEYE</p>
            <p class="cveye-side-brand-sub">Threat Intelligence</p>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_sidebar_status(data_source: str) -> None:
    label = "Connected to BigQuery" if data_source == "BigQuery (live)" else "Running on sample data"
    st.sidebar.markdown(
        f"""
        <div class="cveye-side-status"><span class="cveye-side-dot"></span>{label} · cache refreshes every 10 min</div>
        """,
        unsafe_allow_html=True,
    )


def render_footer() -> None:
    logo = _logo_b64()
    logo_html = f'<img src="data:image/png;base64,{logo}" alt="CVEYE" />' if logo else ""
    st.markdown(
        f"""
        <div class="cveye-footer">{logo_html}<span>CVEYE — CVE Threat Intelligence Pipeline</span></div>
        """,
        unsafe_allow_html=True,
    )


def stat_cards(cards: list[dict]) -> None:
    """cards: [{label, value, sub, accent, icon}]. accent is a hex color for the icon chip."""
    t = get_theme()
    cols = st.columns(len(cards))
    for col, card in zip(cols, cards):
        accent = card.get("accent", t["accent"])
        sub_class = "cveye-stat-sub up" if card.get("up") else "cveye-stat-sub"
        with col:
            st.markdown(
                f"""
                <div class="cveye-stat" style="--accent: {accent}; --accent-soft: {accent}22">
                  <div class="cveye-stat-top">
                    <p class="cveye-stat-label">{card['label']}</p>
                    <div class="cveye-stat-icon">{card.get('icon', '●')}</div>
                  </div>
                  <p class="cveye-stat-value">{card['value']}</p>
                  <p class="{sub_class}">{card.get('sub', '')}</p>
                </div>
                """,
                unsafe_allow_html=True,
            )


def style_chart(chart: alt.Chart) -> alt.Chart:
    """Apply the current theme's colors to any Altair chart before display."""
    t = get_theme()
    return (
        chart
        .configure_view(strokeWidth=0, fill=t["chart_bg"])
        .configure_axis(
            gridColor=t["chart_grid"], domainColor=t["border"], tickColor=t["border"],
            labelColor=t["chart_label"], titleColor=t["chart_label"],
            labelFontSize=11.5, titleFontSize=12,
        )
        .configure_legend(labelColor=t["chart_label"], titleColor=t["chart_label"])
        .configure_title(color=t["chart_title"])
        .properties(background=t["chart_bg"])
    )


# ---------------------------------------------------------------------------
# Themed HTML tables - see module docstring for why this replaces st.dataframe.
def _fmt_cell(value) -> str:
    if pd.isna(value):
        return ""
    return html.escape(str(value))


def render_table(
    df: pd.DataFrame,
    *,
    numeric_cols: tuple = (),
    chip_col: str = None,
    chip_colors: dict = None,
    max_height: int = 440,
    empty_message: str = "No rows to display.",
) -> None:
    """Render a DataFrame as a fully themed HTML table (sticky header, zebra
    rows, hover highlight, right-aligned numeric columns, optional colored
    chip for one column e.g. severity or priority tier)."""
    if df is None or df.empty:
        st.markdown(f'<div class="cveye-table-wrap"><div class="cveye-empty">{html.escape(empty_message)}</div></div>', unsafe_allow_html=True)
        return

    headers = "".join(
        f'<th class="{"num" if c in numeric_cols else ""}">{html.escape(str(c).replace("_", " "))}</th>'
        for c in df.columns
    )
    rows_html = []
    for _, row in df.iterrows():
        cells = []
        for c in df.columns:
            val = row[c]
            if c == chip_col and chip_colors:
                color = chip_colors.get(str(val), "#9CA3AF")
                cells.append(
                    f'<td><span class="cveye-chip" style="background:{color}22;color:{color}">'
                    f'<span style="width:6px;height:6px;border-radius:50%;background:{color}"></span>'
                    f'{_fmt_cell(val)}</span></td>'
                )
            elif c in numeric_cols:
                cells.append(f'<td class="num">{_fmt_cell(val)}</td>')
            else:
                cells.append(f'<td title="{_fmt_cell(val)}">{_fmt_cell(val)}</td>')
        rows_html.append(f"<tr>{''.join(cells)}</tr>")

    st.markdown(
        f"""
        <div class="cveye-table-wrap">
          <div class="cveye-table-scroll" style="--max-h:{max_height}px">
            <table class="cveye-table">
              <thead><tr>{headers}</tr></thead>
              <tbody>{''.join(rows_html)}</tbody>
            </table>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
