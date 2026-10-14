"""CVEYE Observatory v3 — an independent, interactive Streamlit UI.

Launch instead of dashboard/app.py. Existing app and dbt pipeline remain untouched.
Only actual BigQuery mart values or explicitly labelled synthetic CSV fallback are used.
"""
from __future__ import annotations
import os
from pathlib import Path
import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st
import gcp_auth
from google.api_core.exceptions import NotFound
from observatory_ui import (
    COLORS,SEVERITY_COLORS,TIER_COLORS,install_css,hero,sidebar_brand,
    section,metrics,info_line,tier_rail,render_table,footer,
)

ROOT=Path(__file__).resolve().parent.parent
MARTS=('mart_severity_trends','mart_vendor_severity','mart_cwe_trends',
       'mart_ai_trends','mart_ai_cve_list','mart_owasp_atlas')
SEVERITIES=['CRITICAL','HIGH','MEDIUM','LOW','UNSCORED']

st.set_page_config(page_title='CVEYE | Threat Observatory',page_icon=':material/shield:',layout='wide',initial_sidebar_state='expanded')
try:
    from dotenv import load_dotenv
    load_dotenv(ROOT/'.env')
except ImportError:
    pass
GCP_IDENTITY=gcp_auth.apply(ROOT)

def make_bigquery_client(project):
    from google.cloud import bigquery
    from google.oauth2 import service_account

    try:
        account = st.secrets.get("gcp_service_account")
    except FileNotFoundError:
        account = None

    if account:
        credentials = service_account.Credentials.from_service_account_info(
            dict(account)
        )
        return bigquery.Client(
            project=project,
            credentials=credentials,
        )

    return bigquery.Client(project=project)

install_css(st.session_state.get("obs_appearance", "Light"))

@st.cache_data(ttl=600,show_spinner='Reading vulnerability intelligence…')
def load_marts(project:str|None,dataset:str) -> tuple[dict[str,pd.DataFrame],str,str|None]:
    warning=None
    if project:
        try:
            from google.cloud import bigquery
            client=make_bigquery_client(project)
            frames={}
            for name in MARTS:
                job=client.query(f'SELECT * FROM `{project}.{dataset}.{name}`',job_config=bigquery.QueryJobConfig(maximum_bytes_billed=1_000_000_000))
                frames[name]=job.to_dataframe()
            return frames,'BigQuery (live)',None
        except Exception as exc:
            warning=(f'Could not read BigQuery as {GCP_IDENTITY}: {exc}. '
                     f'{gcp_auth.hint(project)} Showing SYNTHETIC sample data instead.')
    sample=ROOT/'data'/'sample'
    frames={name:pd.read_csv(sample/f'{name}.csv') for name in MARTS}
    return frames,'Local sample data (synthetic)',warning

@st.cache_data(ttl=600)
def load_risk_counts(project:str,dataset:str)->dict[str,int]|None:
    from google.cloud import bigquery
    client=make_bigquery_client(project)
    table=f'{project}.{dataset}.fct_cve_daily_risk'
    try:client.get_table(table)
    except NotFound:return None
    sql=f'''SELECT priority_tier, COUNT(*) AS n FROM `{table}`
    WHERE snapshot_date = (SELECT MAX(snapshot_date) FROM `{table}`)
    GROUP BY priority_tier'''
    job=client.query(sql,job_config=bigquery.QueryJobConfig(maximum_bytes_billed=1_000_000_000))
    return {row.priority_tier:int(row.n) for row in job.result()}

@st.cache_data(ttl=600)
def load_risk_list(project:str,dataset:str,tiers:tuple[str,...])->pd.DataFrame:
    from google.cloud import bigquery
    client=make_bigquery_client(project)
    table=f'{project}.{dataset}.fct_cve_daily_risk'
    sql=f'''SELECT snapshot_date,cve_id,priority_tier,severity_score,epss_score,in_kev,affects_our_assets
        FROM `{table}` WHERE snapshot_date=(SELECT MAX(snapshot_date) FROM `{table}`)
        AND priority_tier IN UNNEST(@tiers)
        ORDER BY CASE priority_tier WHEN 'P1' THEN 1 WHEN 'P2' THEN 2 WHEN 'P3' THEN 3 ELSE 4 END,
        epss_score DESC, severity_score DESC LIMIT 200'''
    config=bigquery.QueryJobConfig(query_parameters=[bigquery.ArrayQueryParameter('tiers','STRING',list(tiers))],maximum_bytes_billed=1_000_000_000)
    return client.query(sql,job_config=config).to_dataframe()

@st.cache_data(ttl=600)
def load_recent(project:str,dataset:str)->pd.DataFrame:
    from google.cloud import bigquery
    client=make_bigquery_client(project)
    table=f'{project}.{dataset}.stg_cves'
    sql=f'''SELECT cve_id,published_date,severity,cvss_score,vendor,product
    FROM `{table}` WHERE severity IN ('CRITICAL','HIGH')
    AND published_date >= DATE_SUB(CURRENT_DATE(),INTERVAL 30 DAY)
    ORDER BY published_date DESC,cvss_score DESC LIMIT 50'''
    job=client.query(sql,job_config=bigquery.QueryJobConfig(maximum_bytes_billed=1_000_000_000))
    return job.to_dataframe()

# All Plotly UI is real, mouse-interactive and dark; no fake metrics or mocked queries.
PLOT_BG='rgba(0,0,0,0)'
GRAPH_CONFIG={'displaylogo':False,'displayModeBar':'hover','responsive':True,'scrollZoom':False,'toImageButtonOptions':{'format':'png','filename':'cveye-chart'}}

def base_chart(fig:go.Figure, height:int=350,legend:bool=True):
    light = st.session_state.get('obs_appearance', 'Light') == 'Light'
    text = '#4b5870' if light else '#c2ccdd'
    grid = 'rgba(75, 92, 126, .13)' if light else 'rgba(166, 184, 218, .12)'
    fig.update_layout(
        height=height,paper_bgcolor=PLOT_BG,plot_bgcolor=PLOT_BG,
        font=dict(family='Inter, Segoe UI, sans-serif',size=12,color=text),
        margin=dict(t=26,l=22,r=16,b=25),
        hoverlabel=dict(bgcolor='#ffffff' if light else '#26334e',
                        bordercolor='#d7dfec' if light else '#4b5e7c',
                        font=dict(color='#243049' if light else '#f3f6ff',size=12)),
        hovermode='closest',
        legend=dict(orientation='h',x=0,y=1.14,bgcolor='rgba(0,0,0,0)',font=dict(size=10)) if legend else dict(visible=False),
    )
    fig.update_xaxes(showgrid=True,gridcolor=grid,zeroline=False,linecolor=grid,ticks='',showline=False)
    fig.update_yaxes(showgrid=False,zeroline=False,linecolor=grid,ticks='',showline=False)
    return fig

def display(fig:go.Figure):
    st.plotly_chart(fig,theme=None,width='stretch',config=GRAPH_CONFIG)


def vendors_chart(vendors:pd.DataFrame,selected:list[str],top_n:int):
    cols=[f'{x.lower()}_count' for x in selected if f'{x.lower()}_count' in vendors.columns]
    if not cols or vendors.empty:
        st.info('Choose at least one severity to display vendor data.');return
    d=vendors.groupby('vendor',dropna=False)[cols].sum()
    d=d.drop(index='unknown',errors='ignore')
    d['total']=d[cols].sum(axis=1)
    d=d.nlargest(top_n,'total').iloc[::-1]
    fig=go.Figure()
    for sev in SEVERITIES:
        c=f'{sev.lower()}_count'
        if c in d.columns:
            fig.add_bar(name=sev,x=d[c],y=d.index.astype(str),orientation='h',marker=dict(color=SEVERITY_COLORS[sev]),
                hovertemplate='<b>%{y}</b><br>'+sev+': %{x:,} CVEs<extra></extra>')
    fig.update_layout(barmode='stack',bargap=.33)
    display(base_chart(fig,max(340,32*len(d)),True))


def trend_chart(df:pd.DataFrame,selected:list[str]):
    df=df[df['severity'].isin(selected)]
    fig=go.Figure()
    for sev in SEVERITIES:
        sub=df[df['severity']==sev].sort_values('published_year')
        if sub.empty:continue
        fig.add_trace(go.Scatter(x=sub['published_year'].astype(str),y=sub['cve_count'],name=sev,mode='lines+markers',
            line=dict(color=SEVERITY_COLORS[sev],width=2.4,shape='spline',smoothing=.65),marker=dict(size=7),
            hovertemplate='<b>%{x}</b><br>'+sev+': %{y:,} CVEs<extra></extra>'))
    display(base_chart(fig,360,True))


def share_chart(df:pd.DataFrame,selected:list[str]):
    df=df[df['severity'].isin(selected)]
    if df.empty:st.info('No data for this filter.');return
    d=df.copy();tot=d.groupby('published_year')['cve_count'].transform('sum').replace(0, np.nan)
    d['share']=d['cve_count']/tot*100
    fig=go.Figure()
    for sev in SEVERITIES:
        sub=d[d['severity']==sev].sort_values('published_year')
        if sub.empty:continue
        fig.add_bar(name=sev,x=sub['published_year'].astype(str),y=sub['share'],marker_color=SEVERITY_COLORS[sev],
            hovertemplate='<b>%{x}</b><br>'+sev+': %{y:.1f}%<extra></extra>')
    fig.update_layout(barmode='stack',bargap=.33)
    fig.update_yaxes(range=[0,100],ticksuffix='%')
    display(base_chart(fig,360,True))


def bar_chart(df:pd.DataFrame,label:str,value:str,color:str='#69ebb6',height:int=360,top_n:int|None=10):
    d=df.sort_values(value,ascending=False)
    if top_n is not None:d=d.head(top_n)
    d=d.iloc[::-1]
    if d.empty:st.info('No data to show.');return
    fig=go.Figure(go.Bar(y=d[label].astype(str),x=d[value],orientation='h',
        marker=dict(color=color,line=dict(width=0)),
        hovertemplate='<b>%{y}</b><br>%{x:,.0f} CVEs<extra></extra>'))
    fig.update_layout(bargap=.34)
    display(base_chart(fig,height,False))


def risk_donut(counts:dict[str,int],height:int=335):
    vals=[int(counts.get(t,0)) for t in ['P1','P2','P3','P4']]
    if sum(vals)==0:return
    fig=go.Figure(go.Pie(labels=['P1','P2','P3','P4'],values=vals,hole=.77,
        marker=dict(colors=[TIER_COLORS[t] for t in ['P1','P2','P3','P4']],line=dict(color='#dce3ec' if st.session_state.get('obs_appearance','Light')=='Light' else '#19283a',width=3)),
        sort=False,textinfo='none',hovertemplate='<b>%{label}</b><br>%{value:,} vulnerabilities<br>%{percent}<extra></extra>'))
    fig.add_annotation(text=f'<b>{sum(vals):,}</b><br><span style="font-size:11px;color:#64748b">Ranked CVEs</span>',x=.5,y=.5,showarrow=False,font=dict(color='#25314a' if st.session_state.get('obs_appearance','Light')=='Light' else '#f1f6ff',size=19))
    display(base_chart(fig,height,True))

project=os.getenv('GCP_PROJECT_ID')
dataset=os.getenv('BQ_DBT_DATASET','cve_dbt')
frames,source,warning=load_marts(project,dataset)

sidebar_brand()
if hasattr(st.sidebar, 'segmented_control'):
    st.sidebar.segmented_control('Appearance', options=['Light', 'Dark'],
                                 default='Light', key='obs_appearance')
else:
    st.sidebar.radio('Appearance', ['Light', 'Dark'], horizontal=True,
                     key='obs_appearance')
st.sidebar.markdown('<p style="font-size:10px;color:var(--obs-accent);font-weight:800;letter-spacing:.18em;margin:5px 0 5px">WORKSPACE</p>',unsafe_allow_html=True)
page=st.sidebar.radio('Workspace', ['Overview','Threat Watch','Vendors','Severity Trends','Weaknesses','AI Intelligence','Patch Priorities'],label_visibility='collapsed')
st.sidebar.divider()
st.sidebar.markdown('<p style="font-size:10px;color:var(--obs-accent);font-weight:800;letter-spacing:.18em">FILTERS</p>',unsafe_allow_html=True)
trend=frames['mart_severity_trends'].copy()
for frame in frames.values():
    if 'published_year' in frame.columns:frame['published_year']=pd.to_numeric(frame['published_year'],errors='coerce').fillna(0).astype(int)
years=sorted(int(y) for y in trend['published_year'].unique() if y>0)
if len(years)>1:
    lo,hi=st.sidebar.select_slider('Publication years',options=years,value=(years[0],years[-1]))
elif years:
    lo=hi=years[0];st.sidebar.caption(f'Publication year: {lo}')
else:st.error('No publication years in the dataset.');st.stop()
if hasattr(st.sidebar,'pills'):
    selected=st.sidebar.pills('Severity',SEVERITIES,default=SEVERITIES,selection_mode='multi')
else:
    selected=st.sidebar.multiselect('Severity',SEVERITIES,default=SEVERITIES)
selected=list(selected or [])
top_n=st.sidebar.slider('Top vendors / weaknesses',5,20,10)
st.sidebar.markdown('<div style="margin-top:20px;color:var(--obs-muted);font-size:11px;line-height:1.7">UNSCORED vulnerabilities do not yet have a published CVSS score. Recent-year comparisons need context.</div>',unsafe_allow_html=True)
st.sidebar.markdown('<div style="margin-top:24px;border-top:1px solid var(--obs-stroke);padding-top:14px;color:var(--obs-text);font-size:11px">'+('● BigQuery connected' if source=='BigQuery (live)' else '● Synthetic sample mode')+'</div>',unsafe_allow_html=True)

hero(source)
if warning:st.warning(warning)

def years_filter(frame:pd.DataFrame):
    return frame[frame['published_year'].between(lo,hi)]
sev=years_filter(trend)
ai=years_filter(frames['mart_ai_trends'])
vendor=years_filter(frames['mart_vendor_severity'])
cwes=years_filter(frames['mart_cwe_trends'])
owasp=years_filter(frames['mart_owasp_atlas'])
ai_list=years_filter(frames['mart_ai_cve_list'])
num=int(sev['cve_count'].sum())
critical=int(sev.loc[sev['severity']=='CRITICAL','cve_count'].sum())
unscored=int(sev.loc[sev['severity']=='UNSCORED','cve_count'].sum())
ai_count=int(ai['ai_related_cves'].sum())
section('INTELLIGENCE AT A GLANCE','Security landscape',f'{lo}–{hi} publication years')
metrics([
 {'label':'Total vulnerabilities','value':f'{num:,}','foot':'NVD CVEs in selected years','accent':'#139b9d'},
 {'label':'Critical severity','value':f'{critical:,}','foot':'CVSS classification','accent':'#e86676'},
 {'label':'AI / LLM related','value':f'{ai_count:,}','foot':'Keyword heuristic · not ground truth','accent':'#7375e8'},
 {'label':'Not yet scored','value':f'{100*unscored/num:.1f}%' if num else '—','foot':'CVSS pending from NVD','accent':'#d69a48'},
])
info_line('DATA FOUNDATION · NVD, CISA KEV, FIRST EPSS',f'{"LIVE BIGQUERY READ" if source=="BigQuery (live)" else "SYNTHETIC EXAMPLE"}  · 10-minute query cache')

if page=='Overview':
    section('COMMAND CENTER','Where should the team focus?','Explore charts · hover for detail')
    left,right=st.columns([1.65,1],gap='medium')
    with left:
        st.markdown('<div class="obs-panel-label">VENDOR EXPOSURE</div><div class="obs-panel-head">Most affected vendors</div>',unsafe_allow_html=True)
        vendors_chart(vendor,selected,top_n)
    with right:
        st.markdown('<div class="obs-panel-label">SEVERITY MIX</div><div class="obs-panel-head">Distribution at a glance</div>',unsafe_allow_html=True)
        sev_counts=sev.groupby('severity')['cve_count'].sum().to_dict()
        values=[int(sev_counts.get(s,0)) for s in SEVERITIES]
        f=go.Figure(go.Pie(labels=SEVERITIES,values=values,hole=.73,sort=False,textinfo='none',
            marker=dict(colors=[SEVERITY_COLORS[s] for s in SEVERITIES],line=dict(color='#e4e8f2' if st.session_state.get('obs_appearance','Light')=='Light' else '#19283a',width=3)),
            hovertemplate='%{label}<br>%{value:,} CVEs<br>%{percent}<extra></extra>'))
        f.add_annotation(text=f'<b>{num:,}</b><br><span style="font-size:11px;color:#64748b">Total CVEs</span>',x=.5,y=.5,showarrow=False,font=dict(color='#25314a' if st.session_state.get('obs_appearance','Light')=='Light' else '#f1f6ff',size=21))
        display(base_chart(f, max(340,32*top_n),True))
    st.markdown('<div class="obs-panel-label">TEMPORAL INTELLIGENCE</div><div class="obs-panel-head">Severity over time</div>',unsafe_allow_html=True)
    trend_chart(sev,selected)
    if source=='BigQuery (live)' and project:
        try:
            counts=load_risk_counts(project,dataset)
            if counts:
                section('PATCH INTELLIGENCE','Risk tiers','Project-defined · simulated assets')
                tier_rail(counts)
        except Exception as exc: st.caption('Risk tier summary unavailable: '+str(exc))

elif page=='Threat Watch':
    section('OPERATIONAL TRIAGE','Recent critical and high CVEs','Latest 30 days · live-only')
    if source!='BigQuery (live)' or not project:st.info('Live BigQuery access is required for recent vulnerabilities.')
    else:
        try:
            recent=load_recent(project,dataset)
            info_line('Newly published, high-severity vulnerabilities','Last 30 days · up to 50 results')
            render_table(recent,50)
        except Exception as exc:st.error(f'Cannot load recent threats: {exc}')

elif page=='Vendors':
    section('EXPOSURE ANALYSIS','Which vendors are most affected?','Toggle severities and use Plotly hover')
    vendors_chart(vendor,selected,top_n)
    st.caption('Counts reflect CVEs associated with vendor strings. One CVE may affect multiple products/vendors.')

elif page=='Severity Trends':
    section('TEMPORAL INTELLIGENCE','Severity trends','Totals and per-year distribution')
    left,right=st.columns(2,gap='medium')
    with left:
        st.markdown('<div class="obs-panel-label">YEARLY VOLUME</div>',unsafe_allow_html=True)
        trend_chart(sev,selected)
    with right:
        st.markdown('<div class="obs-panel-label">RELATIVE SHARE</div>',unsafe_allow_html=True)
        share_chart(sev,selected)
    st.caption('2026 may be incomplete. The share chart helps avoid misleading comparisons between full and partial years.')

elif page=='Weaknesses':
    section('WEAKNESS INTELLIGENCE','Common weakness types','CWE patterns in published records')
    d=cwes.groupby(['cwe_id','cwe_name'],dropna=False)['cve_count'].sum().reset_index()
    d['label']=d.apply(lambda x: str(x['cwe_id'])+(f" · {str(x['cwe_name'])}" if pd.notna(x['cwe_name']) else ''),axis=1)
    bar_chart(d,'label','cve_count',height=max(340,34*top_n),top_n=top_n)
    st.caption('Some CWE names are not present in the curated seed mapping; these appear as IDs only.')
    subset_ids=d.nlargest(min(top_n,6),'cve_count')['cwe_id'].tolist()
    by=cwes[cwes['cwe_id'].isin(subset_ids)].copy()
    section('CHANGES OVER TIME','How weaknesses evolve')
    fig=go.Figure()
    palette=['#169e9d','#668ced','#e8a15d','#a782da','#e06c7c','#5ea99b']
    for i,c in enumerate(subset_ids):
        s=by[by['cwe_id']==c].sort_values('published_year')
        if s.empty:continue
        fig.add_scatter(x=s['published_year'].astype(str),y=s['cve_count'],name=str(c),mode='lines+markers',line=dict(color=palette[i%len(palette)],width=2.4),
            hovertemplate='<b>%{x}</b><br>'+str(c)+': %{y:,}<extra></extra>')
    display(base_chart(fig,360,True))

elif page=='AI Intelligence':
    section('AI THREAT LANDSCAPE','AI / LLM vulnerability signals','Keyword-based heuristic, not formal attribution')
    left,right=st.columns(2,gap='medium')
    with left:
        st.markdown('<div class="obs-panel-label">DETECTED AI-RELATED CVEs</div>',unsafe_allow_html=True)
        bar_chart(ai,'published_year','ai_related_cves',color='#159b9d',height=325,top_n=None)
    with right:
        st.markdown('<div class="obs-panel-label">AI SHARE OF ALL CVEs</div>',unsafe_allow_html=True)
        fig=go.Figure(go.Scatter(x=ai['published_year'].astype(str),y=ai['ai_share_pct'],mode='lines+markers',line=dict(color='#6e77e8',width=3,shape='spline',smoothing=.5),fill='tozeroy',fillcolor='rgba(110,119,232,.10)',
            hovertemplate='%{x}<br>%{y:.2f}%<extra></extra>'))
        display(base_chart(fig,325,False))
    section('FRAMEWORK MAPPING','OWASP LLM categories')
    if not owasp.empty:
        ow=owasp.groupby(['owasp_llm_id','owasp_llm_name'],dropna=False)['cve_count'].sum().reset_index()
        ow['label']=ow['owasp_llm_id'].astype(str)+' · '+ow['owasp_llm_name'].astype(str)
        bar_chart(ow,'label','cve_count',color='#8275db',height=360,top_n=10)
    section('REVIEW THE EVIDENCE','Latest AI-related records')
    cols=[x for x in ['cve_id','published_date','severity','cvss_score','vendor','product','cwe_id'] if x in ai_list.columns]
    render_table(ai_list[cols].head(80),80)
    st.caption('OWASP / MITRE ATLAS associations are curated analytical mappings, not official categorization of individual CVEs.')

elif page=='Patch Priorities':
    section('PATCH DECISIONS','Risk-prioritized queue','Real KEV/EPSS signals · simulated asset exposure')
    if source!='BigQuery (live)' or not project:
        st.info('Connect to BigQuery to view real risk priorities. Synthetic samples are not used in this section.')
    else:
        try:
            counts=load_risk_counts(project,dataset)
            if counts is None:
                st.info('Risk mart not yet available: fct_cve_daily_risk.')
            else:
                metrics([{'label':t+' · '+description,'value':f'{int(counts.get(t,0)):,}','foot':'Project-defined priority','accent':TIER_COLORS[t]} for t,description in [('P1','Immediate'),('P2','High'),('P3','Moderate'),('P4','Lower')]])
                tier_rail(counts)
                st.markdown('<div class="obs-panel-label">PRIORITY FILTER</div>',unsafe_allow_html=True)
                opts=['P1','P2','P3','P4']
                if hasattr(st,'pills'):
                    chosen=st.pills('Choose tiers',opts,default=opts,selection_mode='multi')
                else:chosen=st.multiselect('Choose tiers',opts,default=opts)
                if not chosen:st.info('Select at least one priority tier.')
                else:
                    d=load_risk_list(project,dataset,tuple(chosen))
                    st.caption(f'Latest available risk snapshot · Showing up to 200 rows; totals above represent all {sum(counts.values()):,} CVEs.')
                    q=st.text_input('Search displayed CVE IDs',placeholder='e.g. CVE-2023-',key='cve_search')
                    if q:d=d[d['cve_id'].astype(str).str.contains(q,case=False,regex=False,na=False)]
                    display_cols=['cve_id','priority_tier','severity_score','epss_score','in_kev','affects_our_assets','snapshot_date']
                    render_table(d[display_cols],150)
                    st.download_button('Export displayed rows (CSV)',data=d.to_csv(index=False).encode('utf-8'),file_name='cveye-priority-queue.csv',mime='text/csv',key='export_risk')
                st.caption('Important: these tiers use project-defined thresholds, and affects_our_assets is a simulated asset match, not real corporate inventory.')
        except Exception as exc:st.error(f'Cannot load Risk Mart: {exc}')

footer()
