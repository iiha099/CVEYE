"""Visual-only components for CVEYE Observatory v2 (no data access)."""
from __future__ import annotations
import base64
import html
import re
from pathlib import Path
from typing import Iterable

import pandas as pd
import streamlit as st

ASSET_DIR = Path(__file__).resolve().parent / 'assets'
# Shared semantic colors. Dark and light charts keep the same meaning.
COLORS = {
    'bg':'#f4f6fb', 'surface':'#ffffff', 'surface2':'#f8faff',
    'text':'#243049', 'muted':'#65748b',
    'mint':'#139b9d', 'blue':'#627be7', 'purple':'#8c72da',
    'critical':'#dd5673', 'high':'#e58b46',
    'medium':'#ad84d6', 'low':'#299e91', 'unscored':'#8c96a9'
}
SEVERITY_COLORS = {k: COLORS[k.lower()] for k in ('CRITICAL','HIGH','MEDIUM','LOW','UNSCORED')}
TIER_COLORS = {'P1': COLORS['critical'], 'P2': COLORS['high'], 'P3': COLORS['medium'], 'P4': COLORS['low']}

PALETTES = {
 'Light': {
    'bg':'#f3f5fa', 'bg2':'#eef3fb', 'sidebar':'#fcfdff',
    'panel':'#ffffff', 'panelhi':'#f8faff', 'panel-hover':'#f0f6ff',
    'text':'#243148', 'muted':'#66758e', 'subtle':'#8a98ad',
    'stroke':'#dce4ef', 'accent':'#0e8891', 'accenttext':'#087980',
    'chip':'#e5f3f2', 'chiptext':'#0e6f78',
    'shadow':'rgba(54,72,104,.07)', 'shadowhover':'rgba(54,72,104,.13)',
    'row':'#ffffff', 'rowalt':'#f9fbfe', 'rowhover':'#eaf3fd',
    'tablehead':'#eff4fb', 'tablerule':'#e6ebf4',
    'statusbg':'#e4f4f1', 'statustext':'#0c797e',
    'borderbright':'#c4d5e7',
 },
 'Dark': {
    'bg':'#101827', 'bg2':'#142034', 'sidebar':'#152033',
    'panel':'#19283a', 'panelhi':'#21334a', 'panel-hover':'#263a54',
    'text':'#edf3fc', 'muted':'#b0bed0', 'subtle':'#8294aa',
    'stroke':'#33455d', 'accent':'#65d5d3', 'accenttext':'#65d5d3',
    'chip':'#1d4554', 'chiptext':'#b2edf1',
    'shadow':'rgba(0,4,14,.16)', 'shadowhover':'rgba(0,4,14,.28)',
    'row':'#19283a', 'rowalt':'#1e2f44', 'rowhover':'#293e56',
    'tablehead':'#253951', 'tablerule':'#31435b',
    'statusbg':'#1f464b', 'statustext':'#a4ecdf',
    'borderbright':'#4b647f',
 },
}


def asset_data(name: str) -> str:
    file = ASSET_DIR / name
    if not file.is_file(): return ''
    return 'data:image/webp;base64,' + base64.b64encode(file.read_bytes()).decode('ascii')


def install_css(mode: str = 'Light') -> None:
    """True two-palette UI. Reruns redraw the CSS when the user changes Appearance."""
    mode = mode if mode in PALETTES else 'Light'
    pal = PALETTES[mode]
    bg_start = '#f3f5fa' if mode == 'Light' else '#101827'
    bg_end = '#eef2f9' if mode == 'Light' else '#131f32'
    sidebar_end = '#f5f8fe' if mode == 'Light' else '#121d2e'
    bloom1 = 'rgba(113,132,231,.11)' if mode == 'Light' else 'rgba(98,113,210,.095)'
    bloom2 = 'rgba(35,166,166,.10)' if mode == 'Light' else 'rgba(35,166,166,.08)'
    variables = ';'.join(f'--obs-{key}:{value}' for key,value in pal.items())
    css = r"""
<style>
:root {__VARIABLES__}
html {color-scheme:__SCHEME__}
.stApp {background:
    radial-gradient(ellipse 65% 34% at 80% -7%, __BLOOM1__ 0%,transparent 82%),
    radial-gradient(ellipse 39% 31% at 7% 100%, __BLOOM2__ 0%,transparent 90%),
    linear-gradient(180deg,__BGSTART__,__BGEND__ 95%)!important;
    color:var(--obs-text)!important;}
[data-testid="stAppViewContainer"],[data-testid="stMain"],[data-testid="stMainBlockContainer"] {background:transparent!important;}
[data-testid="stHeader"] {background:transparent!important;}
.block-container {max-width:1550px;padding:1.4rem 3rem 5rem;}
html,body,.stApp p,.stApp input,.stApp button,.stApp label {font-family:Inter,"Segoe UI",Arial,sans-serif;}
.stApp p,.stApp label,.stApp li,.stApp [data-testid="stWidgetLabel"] {color:var(--obs-text);}
.stApp h1,.stApp h2,.stApp h3 {color:var(--obs-text)!important;letter-spacing:-.03em!important;}
[data-testid="stSidebar"] {background:linear-gradient(175deg,var(--obs-sidebar),__SIDEBAR_END__)!important;border-right:1px solid var(--obs-stroke)!important;}
[data-testid="stSidebarUserContent"] {padding:1.7rem 1.25rem;}
[data-testid="stSidebar"] p,[data-testid="stSidebar"] label {color:var(--obs-text)!important;}
[data-testid="stSidebar"] [data-testid="stWidgetLabel"] p {font-weight:650;}
[data-testid="stSidebar"] .stRadio [role="radiogroup"] {display:flex;flex-direction:column;gap:.27rem;}
[data-testid="stSidebar"] .stRadio label {border:1px solid transparent;border-radius:11px;padding:7px 10px;margin:0;transition:background .22s ease,border-color .22s ease,transform .22s;}
[data-testid="stSidebar"] .stRadio label:hover {background:var(--obs-panel-hover);border-color:var(--obs-stroke);transform:translateX(2px);}
[data-testid="stSidebar"] .stRadio label:has(input:checked) {background:var(--obs-chip);border-color:var(--obs-borderbright);}
[data-testid="stSidebar"] .stRadio label:has(input:checked) p {color:var(--obs-accenttext)!important;font-weight:750;}
/* Real Streamlit controls, not fake mockup widgets. */
[data-baseweb="select"] > div,[data-baseweb="input"] > div,[data-baseweb="textarea"] > div {
    background:var(--obs-panel)!important;color:var(--obs-text)!important;
    border:1px solid var(--obs-stroke)!important;border-radius:10px!important;}
[data-baseweb="select"] input,[data-baseweb="input"] input {color:var(--obs-text)!important;}
[data-baseweb="select"] svg,[data-baseweb="input"] svg {fill:var(--obs-muted)!important;color:var(--obs-muted)!important;}
[data-baseweb="tag"] {background:var(--obs-chip)!important;border:1px solid var(--obs-stroke)!important;border-radius:7px!important;}
[data-baseweb="tag"] span {color:var(--obs-chiptext)!important;}
[data-baseweb="popover"],[role="listbox"] {background:var(--obs-panel)!important;color:var(--obs-text)!important;border:1px solid var(--obs-stroke)!important;}
[data-baseweb="popover"] [role="option"],[role="listbox"] [role="option"] {background:var(--obs-panel)!important;color:var(--obs-text)!important;}
[data-baseweb="popover"] [role="option"]:hover,[role="listbox"] [role="option"]:hover {background:var(--obs-panel-hover)!important;}
.stButton button,[data-testid="stDownloadButton"] button {background:var(--obs-panel)!important;color:var(--obs-accenttext)!important;border:1px solid var(--obs-stroke)!important;border-radius:11px!important;box-shadow:0 2px 9px var(--obs-shadow);transition:transform .2s ease,box-shadow .2s ease!important;}
.stButton button:hover,[data-testid="stDownloadButton"] button:hover {transform:translateY(-2px);box-shadow:0 9px 22px var(--obs-shadowhover)!important;border-color:var(--obs-accent)!important;}
[data-testid="stSegmentedControl"] button,[data-testid="stPills"] button {background:var(--obs-panel)!important;color:var(--obs-muted)!important;border-color:var(--obs-stroke)!important;}
[data-testid="stSegmentedControl"] button p,[data-testid="stPills"] button p {color:inherit!important;}
[data-testid="stSegmentedControl"] button[aria-pressed="true"],[data-testid="stPills"] button[aria-pressed="true"] {background:var(--obs-chip)!important;color:var(--obs-accenttext)!important;border-color:var(--obs-accent)!important;}
[data-testid="stSlider"] [role="slider"] {background:var(--obs-accent)!important;}
[data-testid="stDataFrame"] {border:1px solid var(--obs-stroke)!important;border-radius:16px!important;overflow:hidden;}
[data-testid="stCaptionContainer"] p {color:var(--obs-muted)!important;}
.stAlert,[data-testid="stAlert"] {background:var(--obs-panelhi)!important;border:1px solid var(--obs-stroke)!important;}
hr {border-color:var(--obs-stroke)!important;}
/* Dark photographic hero contrasts with light editorial canvas. */
.obs-hero {position:relative;overflow:hidden;min-height:270px;
    background:linear-gradient(94deg,rgba(14,29,48,.99) 0%,rgba(14,32,49,.99) 37%,rgba(17,39,57,.83) 53%,rgba(16,35,51,.24) 100%),var(--hawk) right center/auto 114% no-repeat;
    border:1px solid rgba(96,158,182,.24);border-radius:22px;padding:35px 44px;
    box-shadow:0 19px 55px var(--obs-shadowhover);isolation:isolate;margin:2px 0 28px;
    animation:obs-in .65s cubic-bezier(.2,.8,.2,1) both;}
.obs-hero:after {content:"";position:absolute;inset:-200% -65%;z-index:-1;pointer-events:none;
    background:linear-gradient(115deg,transparent 46%,rgba(121,190,226,.05) 51%,transparent 56%);animation:obs-scan 22s linear infinite;}
.obs-kicker {color:#a4bfff;font-size:10px;letter-spacing:.21em;font-weight:800;margin-bottom:18px;}
.obs-title {font-size:clamp(34px,3.3vw,52px);line-height:1.04;letter-spacing:-.055em;font-weight:800;max-width:660px;margin:0 0 14px;color:#f9fbff;}
.obs-title span {color:#82e1d7;}
.obs-desc {max-width:490px;color:#c4d4e7;font-size:14px;line-height:1.7;margin:0 0 25px;}
.obs-meta {display:flex;align-items:center;gap:13px;flex-wrap:wrap;font-size:10px;letter-spacing:.08em;font-weight:720;color:#bdcce0;}
.obs-status {display:inline-flex;align-items:center;gap:9px;background:rgba(24,85,88,.65);border:1px solid rgba(108,215,199,.35);padding:8px 12px;border-radius:999px;color:#dcfaf0;}
.obs-led {width:7px;height:7px;border-radius:50%;background:#80e5d9;box-shadow:0 0 9px #54c7bf;animation:obs-pulse 3.1s ease-in-out infinite;}
.obs-led.off {background:#f2ba72;box-shadow:none;}
/* Purposeful whitespace + balanced jewel-tone accents. */
.obs-section {margin:20px 0 13px;display:flex;align-items:baseline;justify-content:space-between;gap:15px;}
.obs-eyebrow {color:var(--obs-accenttext);font-size:10px;font-weight:800;letter-spacing:.17em;text-transform:uppercase;}
.obs-h2 {font-size:23px;font-weight:780;letter-spacing:-.035em;color:var(--obs-text);margin:5px 0 0;}
.obs-small {color:var(--obs-muted);font-size:12px;}
.obs-card {background:linear-gradient(148deg,var(--obs-panel),var(--obs-panelhi));border:1px solid var(--obs-stroke);border-radius:17px;padding:22px 22px 19px;position:relative;overflow:hidden;min-height:146px;box-shadow:0 10px 27px var(--obs-shadow);animation:obs-in .6s ease both;transition:transform .24s ease,border-color .24s ease,box-shadow .24s ease;}
.obs-card:nth-child(2) {animation-delay:.06s;}.obs-card:nth-child(3) {animation-delay:.12s;}
.obs-card:hover {transform:translateY(-5px);border-color:var(--obs-borderbright);box-shadow:0 16px 36px var(--obs-shadowhover);}
.obs-card:before {content:"";height:3px;position:absolute;top:0;left:18px;right:18px;background:linear-gradient(90deg,var(--accent),transparent);}
.obs-card .label {color:var(--obs-muted);font-size:12px;font-weight:650;}
.obs-card .value {color:var(--obs-text);font-weight:780;letter-spacing:-.055em;font-size:clamp(25px,2.45vw,37px);margin:18px 0 7px;font-variant-numeric:tabular-nums;line-height:1;}
.obs-card .foot {color:var(--obs-subtle);font-size:11px;}
.obs-info {background:var(--obs-panel);border:1px solid var(--obs-stroke);border-radius:13px;padding:16px 19px;display:flex;justify-content:space-between;flex-wrap:wrap;gap:12px;font-size:12px;color:var(--obs-muted);margin:19px 0;box-shadow:0 6px 19px var(--obs-shadow);}
.obs-info strong {color:var(--obs-accenttext);}
.obs-panel-label {font-size:10px;color:var(--obs-accenttext);font-weight:800;letter-spacing:.15em;margin:18px 0 3px;}
.obs-panel-head {font-size:21px;letter-spacing:-.035em;color:var(--obs-text);font-weight:750;margin:0 0 3px;}
[data-testid="stPlotlyChart"] {border:1px solid var(--obs-stroke);border-radius:17px;background:var(--obs-panel);overflow:hidden;padding:10px 7px;box-shadow:0 8px 24px var(--obs-shadow);transition:box-shadow .25s ease,border-color .25s ease;}
[data-testid="stPlotlyChart"]:hover {border-color:var(--obs-borderbright);box-shadow:0 12px 33px var(--obs-shadowhover);}
.obs-rail {background:var(--obs-panel);border:1px solid var(--obs-stroke);border-radius:14px;overflow:hidden;padding:16px 19px;margin:12px 0 19px;box-shadow:0 8px 25px var(--obs-shadow);}
.obs-rail-row {display:flex;justify-content:space-between;flex-wrap:wrap;gap:9px;margin-bottom:12px;font-size:11px;color:var(--obs-muted);}
.obs-rail-bar {display:flex;height:9px;background:var(--obs-panelhi);overflow:hidden;border-radius:99px;gap:2px;}
.obs-rail-bar>span {height:100%;display:block;min-width:2px;transition:width .4s ease;}
.obs-table-wrap {background:var(--obs-panel);border:1px solid var(--obs-stroke);border-radius:16px;overflow:auto;max-height:565px;box-shadow:0 8px 28px var(--obs-shadow);scrollbar-color:var(--obs-borderbright) var(--obs-panel);}
.obs-table {width:100%;border-collapse:collapse;font-size:12px;font-variant-numeric:tabular-nums;}
.obs-table th {position:sticky;top:0;z-index:3;color:var(--obs-muted);background:var(--obs-tablehead);text-align:left;letter-spacing:.065em;text-transform:uppercase;font-size:10px;padding:15px;border-bottom:1px solid var(--obs-stroke);white-space:nowrap;}
.obs-table td {padding:12px 15px;border-bottom:1px solid var(--obs-tablerule);color:var(--obs-text);white-space:nowrap;max-width:360px;overflow:hidden;text-overflow:ellipsis;}
.obs-table tr:nth-child(even) {background:var(--obs-rowalt);}
.obs-table tbody tr:hover {background:var(--obs-rowhover);}
.obs-table a {color:var(--obs-accenttext);text-decoration:none;font-weight:750;}
.obs-table a:hover {text-decoration:underline;}
.obs-pill {font-size:10px;font-weight:800;border-radius:7px;padding:5px 9px;display:inline-block;background:color-mix(in srgb,var(--chip) 13%,var(--obs-panel));border:1px solid color-mix(in srgb,var(--chip) 38%,var(--obs-stroke));color:var(--chip);}
.obs-no {color:var(--obs-muted)}.obs-yes {color:var(--obs-accenttext);font-weight:760;}
.obs-foot {border-top:1px solid var(--obs-stroke);margin-top:42px;padding-top:22px;display:flex;justify-content:space-between;gap:14px;flex-wrap:wrap;color:var(--obs-muted);font-size:11px;letter-spacing:.025em;}
@keyframes obs-in {from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
@keyframes obs-pulse {0%,100%{opacity:.8;box-shadow:0 0 5px #54c7bf}50%{opacity:1;box-shadow:0 0 13px #75dcd3}}
@keyframes obs-scan {0%{transform:translateX(-22%)}100%{transform:translateX(25%)}}
@media(max-width:1100px) {.block-container{padding:1.4rem 1.5rem 3rem}.obs-hero{padding:29px 30px;background-size:cover,auto 106%}.obs-title{font-size:37px}}
@media(max-width:740px) {.block-container{padding:1rem .9rem 3rem}.obs-hero{padding:25px;min-height:275px;background:linear-gradient(94deg,#101d30ed,#15243cb8),var(--hawk) center/auto 100% no-repeat}.obs-title{font-size:32px}.obs-card{min-height:118px}.obs-card .value{font-size:26px}.obs-section{align-items:flex-start;flex-direction:column}}
@media(prefers-reduced-motion:reduce) {*,*:before,*:after{animation:none!important;transition:none!important}}
</style>
"""
    css = css.replace('__VARIABLES__', variables)
    css = css.replace('__SCHEME__', mode.lower())
    css = css.replace('__SIDEBAR_END__', sidebar_end)
    css = css.replace('__BLOOM1__', bloom1).replace('__BLOOM2__', bloom2)
    css = css.replace('__BGSTART__', bg_start).replace('__BGEND__', bg_end)
    st.markdown(css, unsafe_allow_html=True)


def hero(source: str) -> None:
    src = asset_data('hawk_hero.webp')
    status = ('BIGQUERY CONNECTED',False) if source == 'BigQuery (live)' else ('SYNTHETIC SAMPLE',True)
    st.markdown(f'''<section class="obs-hero" style="--hawk:url('{src}')">
      <div class="obs-kicker">CVEYE &nbsp; / &nbsp; THREAT INTELLIGENCE PLATFORM</div>
      <div class="obs-title">From raw threats<br>to <span>clear priorities.</span></div>
      <div class="obs-desc">One signal-driven view of vulnerabilities, severity, exploitation intelligence and patch priorities.</div>
      <div class="obs-meta"><span class="obs-status"><i class="obs-led {'off' if status[1] else ''}"></i>{status[0]}</span><span>NVD &nbsp; / &nbsp; CISA KEV &nbsp; / &nbsp; FIRST EPSS</span></div>
    </section>''', unsafe_allow_html=True)


def sidebar_brand():
    icon = asset_data('hawk_icon.webp')
    st.sidebar.markdown(f'''<div style="display:flex;align-items:center;gap:12px;margin:0 0 20px;padding:0 0 20px;border-bottom:1px solid var(--obs-stroke)">
    <img src="{icon}" alt="Hawk emblem" style="width:46px;height:46px;border-radius:11px;border:1px solid var(--obs-stroke);object-fit:cover"/>
    <div><div style="color:var(--obs-text);font-size:20px;font-weight:800;letter-spacing:.09em">CVEYE</div>
    <div style="color:var(--obs-muted);letter-spacing:.15em;font-size:9px;font-weight:760">THREAT OBSERVATORY</div></div></div>''',unsafe_allow_html=True)


def section(kicker: str, heading: str, sub: str=''):
    st.markdown(f'<div class="obs-section"><div><div class="obs-eyebrow">{html.escape(kicker)}</div><div class="obs-h2">{html.escape(heading)}</div></div><div class="obs-small">{html.escape(sub)}</div></div>', unsafe_allow_html=True)


def metrics(items: Iterable[dict]) -> None:
    items = list(items)
    cols = st.columns(len(items), gap='medium')
    for col, it in zip(cols,items):
        with col:
            st.markdown(f'''<div class="obs-card" style="--accent:{it.get('accent','#69ebb6')}">
            <div class="label">{html.escape(str(it['label']))}</div><div class="value">{html.escape(str(it['value']))}</div>
            <div class="foot">{html.escape(str(it.get('foot','')))}</div></div>''', unsafe_allow_html=True)


def info_line(left: str, right: str):
    st.markdown(f'<div class="obs-info"><span>{html.escape(left)}</span><strong>{html.escape(right)}</strong></div>',unsafe_allow_html=True)


def tier_rail(counts: dict[str,int]) -> None:
    total = sum(int(x) for x in counts.values())
    chunks=[]
    for t in ['P1','P2','P3','P4']:
        v=int(counts.get(t,0))
        percent=100*v/total if total else 0
        chunks.append(f'<span title="{t}: {v:,}" style="width:{percent:.4f}%;background:{TIER_COLORS[t]}"></span>')
    labels=''.join(f'<span style="color:{TIER_COLORS[t]}">{t} <b>{int(counts.get(t,0)):,}</b></span>' for t in ['P1','P2','P3','P4'])
    st.markdown(f'<div class="obs-rail"><div class="obs-rail-row">{labels}</div><div class="obs-rail-bar">{"".join(chunks)}</div></div>',unsafe_allow_html=True)


def render_table(df:pd.DataFrame, max_rows:int=100) -> None:
    if df is None or df.empty:
        st.info('No records match the selected filters.')
        return
    headers=''.join(f'<th>{html.escape(str(c).replace("_"," "))}</th>' for c in df.columns)
    body=[]
    for values in df.head(max_rows).itertuples(index=False,name=None):
        cells=[]
        for col,val in zip(df.columns,values):
            if pd.isna(val):
                content='—'
            elif col=='cve_id' and re.fullmatch(r'CVE-\d{4}-\d{4,}',str(val),re.I):
                c=html.escape(str(val))
                content=f'<a href="https://nvd.nist.gov/vuln/detail/{c}" target="_blank" rel="noopener noreferrer">{c}</a>'
            elif col in ('priority_tier','severity'):
                c=TIER_COLORS.get(str(val),SEVERITY_COLORS.get(str(val),'#8aa598'))
                content=f'<span class="obs-pill" style="--chip:{c}">{html.escape(str(val))}</span>'
            elif col in ('in_kev','affects_our_assets'):
                yes=bool(val);content=f'<span class="{"obs-yes" if yes else "obs-no"}">{"YES" if yes else "NO"}</span>'
            elif isinstance(val,float):
                content=f'{val:,.4f}' if col=='epss_score' else f'{val:,.1f}'
            else:
                content=html.escape(str(val))
            cells.append(f'<td title="{html.escape(str(val),quote=True)}">{content}</td>')
        body.append('<tr>'+''.join(cells)+'</tr>')
    st.markdown('<div class="obs-table-wrap"><table class="obs-table"><thead><tr>'+headers+'</tr></thead><tbody>'+''.join(body)+'</tbody></table></div>',unsafe_allow_html=True)


def footer():
    st.markdown('<div class="obs-foot"><span>CVEYE / THREAT OBSERVATORY</span><span>Signals from NVD, CISA KEV and FIRST EPSS · Asset data is simulated</span></div>',unsafe_allow_html=True)
