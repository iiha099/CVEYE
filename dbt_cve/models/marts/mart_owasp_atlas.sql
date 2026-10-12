-- CVEs mapped to OWASP Top 10 for LLM Applications and MITRE ATLAS through
-- their CWE (mapping lives in seeds/cwe_owasp_atlas.csv - edit it to refine).
-- One row per (year, OWASP category, ATLAS technique).

with cves as (

    select cve_id, published_year, cwe_id from {{ ref('stg_cves') }}

),

mapping as (

    select * from {{ ref('cwe_owasp_atlas') }}

)

select
    c.published_year,
    m.owasp_llm_id,
    m.owasp_llm_name,
    coalesce(m.atlas_technique_id, 'n/a')   as atlas_technique_id,
    coalesce(m.atlas_technique_name, 'n/a') as atlas_technique_name,
    count(*)                                as cve_count
from cves c
inner join mapping m on m.cwe_id = c.cwe_id
group by
    c.published_year,
    m.owasp_llm_id,
    m.owasp_llm_name,
    coalesce(m.atlas_technique_id, 'n/a'),
    coalesce(m.atlas_technique_name, 'n/a')
