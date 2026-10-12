-- One row per (vendor, year): CVE counts by severity.
-- Vendor 'unknown' is excluded: many recent CVEs have no CPE data yet, so
-- 'unknown' would otherwise always be the "most affected vendor".

select
    vendor,
    published_year,
    sum(case when severity = 'CRITICAL' then 1 else 0 end) as critical_count,
    sum(case when severity = 'HIGH'     then 1 else 0 end) as high_count,
    sum(case when severity = 'MEDIUM'   then 1 else 0 end) as medium_count,
    sum(case when severity = 'LOW'      then 1 else 0 end) as low_count,
    sum(case when severity = 'UNSCORED' then 1 else 0 end) as unscored_count,
    count(*)                                               as total_cves
from {{ ref('stg_cves') }}
where vendor != 'unknown'
group by vendor, published_year
