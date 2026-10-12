-- The 500 most recent AI/LLM-related CVEs (for the dashboard's detail table).

select
    cve_id,
    published_date,
    published_year,
    severity,
    cvss_score,
    vendor,
    product,
    cwe_id,
    description
from {{ ref('stg_cves') }}
where is_ai_related
order by published_date desc, cve_id desc
limit 500
