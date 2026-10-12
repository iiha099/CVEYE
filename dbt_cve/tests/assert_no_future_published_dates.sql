-- Singular test: returns the rows that BREAK the rule (dbt fails if any come back).
select cve_id, published_date
from {{ ref('stg_cves') }}
where published_date > current_date()
