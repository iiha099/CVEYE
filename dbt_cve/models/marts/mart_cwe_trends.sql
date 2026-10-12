-- One row per (year, CWE): the most common weakness types over time.
-- Placeholder values (unknown / NVD-CWE-noinfo / NVD-CWE-Other) are excluded.

with cves as (

    select * from {{ ref('stg_cves') }}
    where cwe_id like 'CWE-%'

),

names as (

    select cwe_id, cwe_name from {{ ref('cwe_owasp_atlas') }}

)

select
    c.published_year,
    c.cwe_id,
    max(n.cwe_name) as cwe_name,
    count(*)        as cve_count
from cves c
left join names n on n.cwe_id = c.cwe_id
group by c.published_year, c.cwe_id
