"""CVEYE / Observatory — a premium Streamlit visual system.

Drop-in replacement for dashboard/theme.py.
No data queries, business rules, or upstream marts are changed.
Requires the supplied dashboard/assets/hawk_hero.webp and hawk_icon.webp.
"""
from __future__ import annotations

import base64
import html
import re
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

ASSETS = Path(__file__).resolve().parent / "assets"

DARK = {
    "mode": "dark", "bg": "#07130F", "bg_grad": "radial-gradient(ellipse 75% 43% at 98% 0%, #123327 0%, transparent 75%),linear-gradient(180deg,#071310 0%,#07110F 100%)",
    "surface": "#10211A", "surface_alt": "#091811", "border": "#234235",
    "text": "#EDF8F1", "muted": "#9BB3A5", "accent": "#68DFA9",
    "accent_strong": "#A0F1C7", "accent_soft": "rgba(108,227,171,.12)",
    "teal": "#5DBCAF", "teal_soft": "rgba(93,188,175,.12)",
    "shadow": "0 18px 55px rgba(0,0,0,.19)",
    "chart_bg": "transparent", "chart_grid": "#234034", "chart_label": "#B2CBBE",
    "chart_title": "#F0F6F1", "table_head_bg": "#153025",
    "table_row_hover": "rgba(108,227,171,.06)", "table_row_alt": "rgba(255,255,255,.014)",
    "hero_scrim": "linear-gradient(90deg,#081A13 0%,#081A13 40%,rgba(8,26,19,.83) 60%,rgba(8,26,19,.28) 100%)",
}
LIGHT = {
    "mode": "light", "bg": "#F5F8F5", "bg_grad": "radial-gradient(ellipse 70% 38% at 97% 0%,#DFEFE6 0%,transparent 78%),linear-gradient(180deg,#F7FAF7,#F2F6F3)",
    "surface": "#FFFFFF", "surface_alt": "#ECF4EE", "border": "#DCE8DF",
    "text": "#162921", "muted": "#60786B", "accent": "#117B58",
    "accent_strong": "#096947", "accent_soft": "rgba(17,123,88,.10)",
    "teal": "#247C80", "teal_soft": "rgba(36,124,128,.1)",
    "shadow": "0 16px 46px rgba(34,72,48,.065)",
    "chart_bg": "transparent", "chart_grid": "#E1ECE5", "chart_label": "#587469",
    "chart_title": "#162921", "table_head_bg": "#F2F7F3",
    "table_row_hover": "rgba(17,123,88,.055)", "table_row_alt": "rgba(17,55,33,.018)",
    "hero_scrim": "linear-gradient(90deg,#102B20 0%,#102B20 42%,rgba(16,43,32,.80) 63%,rgba(16,43,32,.22) 100%)",
}
# Semantic colors: same severity carries the same meaning in both themes.
SEVERITY_COLORS = {
    "CRITICAL": "#F47C78", "HIGH": "#EBAE69", "MEDIUM": "#79A9F8",
    "LOW": "#63BEAF", "UNSCORED": "#93A6A0",
}
CATEGORICAL = ["#68DFA9", "#79A9F8", "#EBAE69", "#F47C78", "#63BEAF", "#B2A0F7", "#DE88B3", "#BAD981"]
ACCENT = DARK["accent"]
ACCENT_PAIRED = "#63BEAF"


def get_theme() -> dict:
    # Single coherent dark palette; Streamlit native widgets use .streamlit/config.toml.
    return DARK


@st.cache_data(show_spinner=False)
def _asset_b64(name: str) -> str:
    path = ASSETS / name
    return base64.b64encode(path.read_bytes()).decode("ascii") if path.exists() else ""


def _color(value: str, default: str = "#6CE3AB") -> str:
    return value if isinstance(value, str) and re.fullmatch(r"#[0-9a-fA-F]{6}", value) else default


def inject_css(t: dict) -> None:
    """Scoped, responsive styling. No JS and no external UI dependencies."""
    css = r"""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800&family=Manrope:wght@400;500;600;700;800&display=swap');
:root { --ink:__TEXT__; --muted:__MUTED__; --panel:__SURFACE__; --subpanel:__SURFACE_ALT__; --line:__BORDER__; --mint:__ACCENT__; --mint-soft:__ACCENT_SOFT__; --glow:__SHADOW__; }
html,body, .stApp, .stApp p, .stApp button, .stApp label, .stApp input, .stApp [data-baseweb] { font-family:'DM Sans','Segoe UI',sans-serif; }
.stApp { background: __BG_GRAD__; background-color:__BG__; color:var(--ink); }
[data-testid='stHeader'] { background:transparent; }
[data-testid='stDecoration'] { display:none; }
.block-container { max-width:1480px; padding:1.4rem 3.35rem 5rem; }
[data-testid='stSidebar'] { background:__SURFACE_ALT__; border-right:1px solid var(--line); }
[data-testid='stSidebarUserContent'] { padding:2rem 1.45rem 2rem; }
[data-testid='stSidebar'] [data-testid='stMarkdownContainer'] p { color:var(--muted); }
[data-testid='stSidebar'] label p { color:var(--ink)!important; font-weight:600; font-size:13px; }
h1,h2,h3,h4 { font-family:'Manrope','Segoe UI',sans-serif!important; color:var(--ink)!important; letter-spacing:-.035em!important; }
h3 { font-size:1.45rem!important; margin-top:.6rem!important; }
[data-testid='stCaptionContainer'] p, .stCaption p, small { color:var(--muted)!important; }
hr { border-color:var(--line)!important; margin:1.4rem 0 1.6rem!important; }
/* CVEYE executive / native widget polish ------------------------------------- */
html {color-scheme:dark;}
[data-testid='stAppViewContainer'], [data-testid='stMain'] {background:transparent!important;}
[data-testid='stMainBlockContainer'] {background:transparent!important;}
[data-testid='stSidebar'] {background:#091811!important;}
[data-testid='stSidebarContent'] {background:transparent!important;}
[data-testid='stSidebarNav'] {background:transparent!important;}
[data-testid='stToolbar'], [data-testid='stStatusWidget'], [data-testid='stHeader'] {color:var(--ink);}
/* Baseweb multiselects and dropdown menus (sidebar + risk queue) */
.stApp div[data-baseweb='select'] > div,
.stApp div[data-baseweb='input'] > div,
.stApp div[data-baseweb='base-input'],
.stApp div[data-baseweb='textarea'] > div {
  background:#12261E!important;border:1px solid #30503E!important;color:#EAF5EE!important;
  box-shadow:none!important;border-radius:11px!important;min-height:42px;
}
.stApp div[data-baseweb='select'] * {color:#EAF5EE;}
.stApp [data-baseweb='tag'] {
  background:#1B3C2D!important;border:1px solid #3F7457!important;
  color:#B8F2D2!important;border-radius:7px!important;margin:2px!important;
}
.stApp [data-baseweb='tag'] span, .stApp [data-baseweb='tag'] svg {color:#B8F2D2!important;fill:#B8F2D2!important;}
.stApp [data-baseweb='tag'] button {background:transparent!important;}
.stApp div[data-baseweb='popover'],
.stApp [data-baseweb='popover'] > div,
.stApp [data-baseweb='menu'],
.stApp [role='listbox'] {
  background:#132920!important;color:#EAF5EE!important;
  border:1px solid #31533F!important;border-radius:12px!important;
  box-shadow:0 16px 42px rgba(0,0,0,.45)!important;
}
.stApp [role='option'], .stApp [role='option'] span,
.stApp [data-baseweb='menu'] li {color:#EAF5EE!important;background:transparent!important;}
.stApp [role='option']:hover, .stApp [role='option'][aria-selected='true'] {background:#254535!important;}
.stApp [role='checkbox'], .stApp [role='radio'] {border-color:#4F8064!important;}
.stApp [data-testid='stMultiSelect'] label,
.stApp [data-testid='stSelectSlider'] label {color:var(--ink)!important;}
.stApp [data-testid='stSlider'] [role='slider'],
.stApp [data-testid='stSelectSlider'] [role='slider'] {box-shadow:0 0 0 3px rgba(104,223,169,.13)!important;}
.stApp [data-testid='stSlider'] [data-testid='stTickBar'] {color:var(--muted)!important;}
/* New Streamlit segmented / pill filters — no red tags or white backgrounds */
.stApp [data-testid='stPills'] button,
.stApp [data-testid='stSegmentedControl'] button {
   border-radius:9px!important;background:#13291F!important;color:#B7CDBF!important;
   border:1px solid #2D4A3A!important;font-size:12px!important;font-weight:700!important;
}
.stApp [data-testid='stPills'] button[aria-pressed='true'],
.stApp [data-testid='stSegmentedControl'] button[aria-pressed='true'] {
   background:#24513A!important;border-color:#66D9A2!important;color:#E5FFF0!important;
}
/* Native Glide dataframe/table widget: dark base comes from config.toml. */
.stApp [data-testid='stDataFrame'], .stApp [data-testid='stDataEditor'],
.stApp [data-testid='stTable'] {background:#10221A!important;border:1px solid #30513E!important;border-radius:15px!important;overflow:hidden;}
.stApp [data-testid='stDataFrame'] [data-testid='stDataFrameResizable'] {background:#10221A!important;}
.stApp [data-testid='stDataFrame'] iframe {color-scheme:dark!important;}
/* The main display grid is pure CSS/HTML, so every table row remains dark. */
.cveye-table-wrap {background:#10221A!important;border:1px solid #315040!important;}
.cveye-table-scroll {scrollbar-color:#3C5B49 #10221A;}
table.cveye-table th {background:#193426!important;color:#A7C1B2!important;}
table.cveye-table td {background:#10221A!important;color:#E7F1E9!important;}
table.cveye-table tr:nth-child(even) td {background:#11271D!important;}
table.cveye-table tr:hover td {background:#204033!important;}
.cveye-table td a {color:#8CF1B9!important;text-decoration:none!important;font-weight:700;}
.cveye-table td a:hover {text-decoration:underline!important;}
.cveye-boolean {display:inline-block;font-size:10px;font-weight:800;letter-spacing:.06em;
 padding:4px 7px;border-radius:6px;border:1px solid transparent;}
.cveye-boolean.true {color:#A8F3C7;background:#1E4730;border-color:#3B7855;}
.cveye-boolean.false {color:#849D8D;background:#1B3027;border-color:#274436;}
/* Sidebar brand must never wrap letter-by-letter */
.cveye-side-brand{gap:12px;align-items:center;min-width:0;}
.cveye-side-brand > div:last-child {min-width:0;flex:1;}
.cveye-side-brand-name {font-size:18px!important;white-space:nowrap;letter-spacing:.04em!important;}
.cveye-side-brand-sub {font-size:9px!important;letter-spacing:.075em!important;white-space:nowrap!important;}
/* Footer and heading spacing */
.cveye-eyebrow {letter-spacing:.15em!important;}
.stApp [data-testid='stAlert'] {background:#193328;border:1px solid #365C45;color:var(--ink);}
/* Hide blank Streamlit link decoration in headings while leaving icons accessible on hover. */
@media(max-width:1000px){ .block-container{padding:1rem 1.4rem 3rem!important;} }

/* Side identity */
.cveye-side-brand { display:flex;align-items:center;gap:13px;padding:0 0 26px;border-bottom:1px solid var(--line);margin-bottom:27px; }
.cveye-side-mark {width:45px;height:45px;flex:0 0 45px;border:1px solid #416754;border-radius:12px;overflow:hidden;background:#0a251b;box-shadow:0 0 0 4px __ACCENT_SOFT__;}
.cveye-side-mark img {height:100%;width:100%;object-fit:cover;}
.cveye-side-brand-name {font-family:'Manrope',sans-serif;font-size:19px;line-height:1.2;font-weight:800;letter-spacing:.06em;color:var(--ink);margin:0;}
.cveye-side-brand-sub {font-size:9px;font-weight:700;letter-spacing:.20em;text-transform:uppercase;color:var(--muted);margin:4px 0 0;}
.cveye-eyebrow { color:__ACCENT__!important;font-size:10px!important;font-weight:800!important;letter-spacing:.19em!important;text-transform:uppercase;margin:16px 0 9px!important; }
.cveye-side-status {margin-top:26px;padding:18px 13px;display:flex;align-items:flex-start;gap:11px;border:1px solid var(--line);border-radius:13px;background:__SURFACE__;font-size:12px;line-height:1.55;color:var(--muted);}
.cveye-side-status strong {color:var(--ink);display:block;font-size:12px;margin-bottom:1px;}
.cveye-side-dot {width:8px;height:8px;background:__ACCENT__;box-shadow:0 0 0 4px __ACCENT_SOFT__;border-radius:50%;margin-top:5px;flex-shrink:0;}
/* Field styling */
[data-testid='stSidebar'] div[data-baseweb='select'] > div,
[data-testid='stSidebar'] div[data-baseweb='slider'],
[data-testid='stSidebar'] div[data-testid='stSelectSlider'] {border-radius:11px;}
[data-testid='stSidebar'] div[data-baseweb='select'] > div {background:__SURFACE__;border-color:var(--line);}
[data-testid='stSidebar'] [data-baseweb='tag'] {background:__ACCENT_SOFT__; border:1px solid var(--line);border-radius:7px;}
[data-testid='stSidebar'] [data-baseweb='tag'] span {color:var(--ink)!important;}
/* Hero */
.cveye-hero {position:relative;display:flex;flex-direction:column;justify-content:center;min-height:260px;overflow:hidden;padding:32px 40px 35px;border-radius:23px;border:1px solid #28503b;background-color:#0B1C15;background-image:__HERO_SCRIM__,url('__HAWK_HERO__');background-size:cover,50% auto;background-position:center,right center;background-repeat:no-repeat;box-shadow:0 18px 55px rgba(0,0,0,.16);margin:4px 0 23px;isolation:isolate;}
.cveye-hero:before {content:'';position:absolute;left:0;top:0;bottom:0;width:4px;background:linear-gradient(180deg,#a7edc8,#208e65);}
.cveye-hero:after {content:'';position:absolute;inset:0;pointer-events:none;background:repeating-linear-gradient(90deg,transparent 0px,transparent 78px,rgba(255,255,255,.012) 79px,transparent 80px);z-index:-1;}
.cveye-hero-kicker {display:flex;gap:12px;align-items:center;color:#98CEB1;letter-spacing:.21em;font-size:10px;font-weight:800;text-transform:uppercase;margin-bottom:20px;}
.cveye-hero-kicker:before {content:'';width:23px;height:1px;background:#80DCAA;}
.cveye-hero-title {font-family:'Manrope',sans-serif;font-size:clamp(32px,3.4vw,51px);font-weight:800;line-height:1.12;letter-spacing:-.05em;color:#F3FBF5;max-width:700px;margin:0 0 16px;}
.cveye-hero-title em {font-style:normal;color:#8AEAB7;}
.cveye-hero-description {color:#B4CFC0;font-size:13.5px;line-height:1.7;max-width:490px;margin:0;}
.cveye-hero-foot {display:flex;align-items:center;gap:11px;margin-top:26px;flex-wrap:wrap;}
.cveye-badge {display:inline-flex;align-items:center;gap:9px;border-radius:8px;padding:8px 12px;background:rgba(12,42,29,.68);border:1px solid rgba(130,223,171,.28);color:#AFEEC9;font-size:10px;font-weight:800;letter-spacing:.09em;text-transform:uppercase;}
.cveye-badge.sample {color:#EFD29E;border-color:#96764c;}
.cveye-badge-dot {width:6px;height:6px;border-radius:50%;background:currentColor;box-shadow:0 0 12px currentColor;}
.cveye-hero-mini {font-size:11px;color:#AFC5B6;letter-spacing:.025em;}
/* Stats */
.cveye-stat {position:relative;isolation:isolate;background:__SURFACE__;border:1px solid var(--line);border-radius:18px;padding:20px 20px 21px;min-height:167px;overflow:hidden;box-shadow:__SHADOW__;transition:border-color .2s ease,transform .2s ease;}
.cveye-stat:before {content:'';position:absolute;left:0;top:0;width:100%;height:2px;background:var(--card-accent);opacity:.9;}
.cveye-stat:after {content:'';position:absolute;right:-48px;top:-58px;width:140px;height:140px;border-radius:50%;background:var(--card-accent);filter:blur(54px);opacity:.095;pointer-events:none;z-index:-1;}
.cveye-stat:hover {transform:translateY(-3px);border-color:var(--card-accent);}
.cveye-stat-top {display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:20px;}
.cveye-stat-label {margin:0;color:var(--muted);font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;}
.cveye-stat-icon {width:31px;height:31px;display:flex;align-items:center;justify-content:center;border-radius:9px;color:var(--card-accent);background:var(--card-accent-soft);font-size:16px;filter:saturate(.8);}
.cveye-stat-value {font-family:'Manrope',sans-serif;font-weight:800;font-size:clamp(25px,2.2vw,35px);letter-spacing:-.06em;line-height:1.1;color:var(--ink);font-variant-numeric:tabular-nums;margin:0;}
.cveye-stat-sub {margin:10px 0 0;font-size:11.5px;line-height:1.4;color:var(--muted);}
.cveye-stat-sub.up {color:__ACCENT_STRONG__;}
/* Data sections */
.stTabs {margin-top:.8rem;}
.stTabs [data-baseweb='tab-list'] {gap:6px;flex-wrap:wrap;border-bottom:1px solid var(--line);padding:4px 0 12px;}
.stTabs [data-baseweb='tab'] {border:1px solid transparent!important;border-radius:11px!important;background:transparent!important;color:var(--muted)!important;font-weight:700;font-size:12px;padding:10px 15px;letter-spacing:.004em;}
.stTabs [data-baseweb='tab']:hover {background:__ACCENT_SOFT__!important;color:var(--ink)!important;}
.stTabs [data-baseweb='tab'][aria-selected='true'] {background:__ACCENT_SOFT__!important;border-color:__BORDER__!important;color:__ACCENT_STRONG__!important;}
.stTabs [data-baseweb='tab-highlight'], .stTabs [data-baseweb='tab-border'] {display:none!important;}
.stTabs [data-baseweb='tab-panel'] {padding-top:1.7rem;}
[data-testid='stVegaLiteChart'] {background:__SURFACE__;border:1px solid var(--line);border-radius:16px;padding:16px 14px 8px;box-shadow:__SHADOW__;}
/* Tables */
.cveye-table-wrap {background:__SURFACE__;border:1px solid var(--line);border-radius:17px;overflow:hidden;box-shadow:__SHADOW__;}
.cveye-table-scroll {max-height:var(--max-h,440px);overflow:auto;scrollbar-width:thin;scrollbar-color:__BORDER__ transparent;}
table.cveye-table {width:100%;border-collapse:separate;border-spacing:0;font-size:12px;}
table.cveye-table th {position:sticky;top:0;z-index:2;background:__TABLE_HEAD_BG__;color:var(--muted);font-size:10px;text-transform:uppercase;font-weight:800;letter-spacing:.09em;text-align:left;padding:14px 17px;border-bottom:1px solid var(--line);white-space:nowrap;}
table.cveye-table td {padding:13px 17px;border-bottom:1px solid var(--line);color:var(--ink);max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-variant-numeric:tabular-nums;}
table.cveye-table th.num,table.cveye-table td.num {text-align:right;}
table.cveye-table tr:nth-child(even) {background:__TABLE_ROW_ALT__;}
table.cveye-table tr:hover {background:__TABLE_ROW_HOVER__;}
table.cveye-table tr:last-child td {border-bottom:0;}
.cveye-chip {display:inline-flex;align-items:center;gap:7px;border-radius:6px;padding:5px 9px;font-size:11px;font-weight:800;letter-spacing:.035em;}
.cveye-chip-dot {width:6px;height:6px;border-radius:50%;background:currentColor;}
.cveye-empty {padding:34px;text-align:center;color:var(--muted);}
/* Native widgets */
[data-testid='stToggle'] label {font-size:12px;color:var(--muted)!important;}
.stAlert {border-radius:13px!important;}
[data-testid='stCaptionContainer'] {padding-top:2px;}
.cveye-footer {border-top:1px solid var(--line);margin:45px 0 0;padding:22px 0 14px;display:flex;justify-content:space-between;align-items:center;gap:12px;color:var(--muted);font-size:11px;letter-spacing:.04em;}
.cveye-footer strong {color:var(--ink);font-family:'Manrope',sans-serif;letter-spacing:.05em;}
@media (max-width:1100px) { .block-container {padding:1.2rem 2rem 4rem;} .cveye-stat {padding:16px;min-height:150px;} .cveye-stat-value {font-size:25px;} .cveye-hero {background-size:cover,75% auto;} }
@media (max-width:800px) { .block-container {padding:1rem 1rem 3rem;} .cveye-hero {min-height:230px;padding:27px 25px;background-size:cover,110% auto;background-position:center,105% 40%;} .cveye-hero-description {max-width:370px;} .cveye-stat {min-height:130px;padding:15px;} .cveye-stat-top {margin-bottom:10px;} .cveye-hero-title {font-size:30px;} .cveye-footer {flex-direction:column;align-items:flex-start;} }
@media (prefers-reduced-motion:reduce) { .cveye-stat {transition:none!important;} }
</style>
"""
    replacements = {
        "__BG__": t["bg"], "__BG_GRAD__": t["bg_grad"], "__SURFACE__": t["surface"],
        "__SURFACE_ALT__": t["surface_alt"], "__BORDER__": t["border"],
        "__TEXT__": t["text"], "__MUTED__": t["muted"], "__ACCENT__": t["accent"],
        "__ACCENT_STRONG__": t["accent_strong"], "__ACCENT_SOFT__": t["accent_soft"],
        "__SHADOW__": t["shadow"], "__TABLE_HEAD_BG__": t["table_head_bg"],
        "__TABLE_ROW_ALT__": t["table_row_alt"], "__TABLE_ROW_HOVER__": t["table_row_hover"],
        "__HERO_SCRIM__": t["hero_scrim"],
        "__HAWK_HERO__": f"data:image/webp;base64,{_asset_b64('hawk_hero.webp')}",
    }
    for key, value in replacements.items():
        css = css.replace(key, value)
    st.markdown(css, unsafe_allow_html=True)


def render_hero(data_source: str) -> None:
    live = data_source == "BigQuery (live)"
    label = "BIGQUERY CONNECTED" if live else "SYNTHETIC SAMPLE"
    badge_class = "" if live else " sample"
    st.markdown(f"""
<div class="cveye-hero">
  <div class="cveye-hero-kicker">CVEYE / SECURITY INTELLIGENCE</div>
  <h1 class="cveye-hero-title">See the threat.<br><em>Know the priority.</em></h1>
  <p class="cveye-hero-description">Vulnerability intelligence, real exploitation signals, and risk priorities — in one clear view.</p>
  <div class="cveye-hero-foot"><span class="cveye-badge{badge_class}"><span class="cveye-badge-dot"></span>{label}</span><span class="cveye-hero-mini">NVD · CISA KEV · FIRST EPSS</span></div>
</div>""", unsafe_allow_html=True)


def render_sidebar_brand(data_source: str) -> None:
    src = _asset_b64("hawk_icon.webp")
    icon = f'<img src="data:image/webp;base64,{src}" alt="Hawk eye" />' if src else "◉"
    st.sidebar.markdown(f"""
<div class="cveye-side-brand"><div class="cveye-side-mark">{icon}</div><div><p class="cveye-side-brand-name">CVEYE</p><p class="cveye-side-brand-sub">SECURITY INTELLIGENCE</p></div></div>
""", unsafe_allow_html=True)


def render_sidebar_status(data_source: str) -> None:
    live = data_source == "BigQuery (live)"
    label = "BigQuery connected" if live else "Sample data mode"
    detail = "Queries are cached for up to 10 min" if live else "Synthetic data; not live threat signals"
    st.sidebar.markdown(f"""
<div class="cveye-side-status"><span class="cveye-side-dot"></span><div><strong>{label}</strong>{detail}</div></div>
""", unsafe_allow_html=True)


def render_footer() -> None:
    st.markdown('<div class="cveye-footer"><strong>CVEYE / THREAT OBSERVATORY</strong><span>Built on NVD · CISA KEV · FIRST EPSS</span></div>',unsafe_allow_html=True)


def stat_cards(cards: list[dict]) -> None:
    """Small interactive overview tiles; accepts existing app/risk_queue card dictionaries."""
    if not cards:
        return
    t = get_theme()
    cols = st.columns(len(cards), gap="small")
    for index, (col, card) in enumerate(zip(cols, cards), start=1):
        accent = _color(card.get("accent", t["accent"]))
        safe_label = html.escape(str(card.get("label", "")))
        safe_value = html.escape(str(card.get("value", "—")))
        safe_sub = html.escape(str(card.get("sub", "")))
        tier_match = re.match(r"P[1-4]\b", str(card.get("label", "")))
        safe_icon = tier_match.group(0) if tier_match else f"{index:02d}"
        klass = "cveye-stat-sub up" if card.get("up", False) else "cveye-stat-sub"
        with col:
            st.markdown(f"""
<div class="cveye-stat" style="--card-accent:{accent};--card-accent-soft:{accent}21">
 <div class="cveye-stat-top"><p class="cveye-stat-label">{safe_label}</p><div class="cveye-stat-icon">{safe_icon}</div></div>
 <p class="cveye-stat-value">{safe_value}</p><p class="{klass}">{safe_sub}</p>
</div>""",unsafe_allow_html=True)


def style_chart(chart: alt.Chart) -> alt.Chart:
    """Keep chart labels legible while leaving the host card styled in CSS."""
    t = get_theme()
    return (chart
        .configure_view(strokeWidth=0, fill=t["chart_bg"])
        .configure_axis(gridColor=t["chart_grid"], gridOpacity=.65, domain=False, ticks=False,
            labelColor=t["chart_label"], titleColor=t["chart_label"],
            labelFont="DM Sans", titleFont="DM Sans", labelFontSize=12,
            titleFontSize=12, titlePadding=12, labelPadding=8)
        .configure_legend(labelColor=t["chart_label"], titleColor=t["chart_label"],
            labelFont="DM Sans", titleFont="DM Sans", labelFontSize=11)
        .configure_title(color=t["chart_title"],font="Manrope",fontWeight=700)
        .properties(background=t["chart_bg"]))


def _fmt_cell(value) -> str:
    try:
        if pd.isna(value):
            return "—"
    except (ValueError, TypeError):
        pass
    if isinstance(value, bool):
        return "Yes" if value else "No"
    return html.escape(str(value))


def render_table(df: pd.DataFrame, *, numeric_cols: tuple=(), chip_col: str=None,
                 chip_colors: dict=None, max_height: int=440, empty_message: str="No rows to display.") -> None:
    """XSS-safe, responsive, sticky-header data grid with semantic risk chips."""
    if df is None or df.empty:
        st.markdown(f'<div class="cveye-table-wrap"><div class="cveye-empty">{html.escape(empty_message)}</div></div>',unsafe_allow_html=True)
        return
    headers = "".join(
        f'<th class="{"num" if c in numeric_cols else ""}">{html.escape(str(c).replace("_", " "))}</th>'
        for c in df.columns
    )
    rows = []
    for row in df.itertuples(index=False, name=None):
        cells = []
        for c,val in zip(df.columns,row):
            safe = _fmt_cell(val)
            if isinstance(val, bool) or str(type(val)).find("bool_") != -1:
                yes = bool(val)
                word = "YES" if yes else "NO"
                klass = "true" if yes else "false"
                cells.append(f'<td><span class="cveye-boolean {klass}">{word}</span></td>')
            elif str(c).lower() == "cve_id" and re.fullmatch(r"CVE-\d{4}-\d{4,}", str(val), re.IGNORECASE):
                cve = html.escape(str(val))
                cells.append(f'<td><a target="_blank" rel="noopener noreferrer" href="https://nvd.nist.gov/vuln/detail/{cve}">{cve}</a></td>')
            elif c == chip_col and chip_colors:
                color = _color(chip_colors.get(str(val), "#93A6A0"))
                cells.append(f'<td><span class="cveye-chip" style="color:{color};background:{color}19"><span class="cveye-chip-dot"></span>{safe}</span></td>')
            else:
                klass = ' class="num"' if c in numeric_cols else ''
                cells.append(f'<td{klass} title="{safe}">{safe}</td>')
        rows.append('<tr>'+''.join(cells)+'</tr>')
    st.markdown(f'<div class="cveye-table-wrap"><div class="cveye-table-scroll" style="--max-h:{int(max_height)}px"><table class="cveye-table"><thead><tr>{headers}</tr></thead><tbody>{"".join(rows)}</tbody></table></div></div>',unsafe_allow_html=True)
