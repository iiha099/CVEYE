-- One row per (year, severity): how the severity mix changes over time.
-- UNSCORED is kept as its own category so the backlog is visible.

select
    published_year,
    severity,
    count(*)                    as cve_count,
    round(avg(cvss_score), 2)   as avg_cvss_score
from {{ ref('stg_cves') }}
group by published_year, severity
