-- One row per year: how many CVEs look AI/LLM related (keyword heuristic, see
-- macros/ai_regex.sql) and what share of all CVEs that is.

select
    published_year,
    count(*)                                                        as total_cves,
    sum(case when is_ai_related then 1 else 0 end)                  as ai_related_cves,
    sum(case when is_ai_related and severity in ('CRITICAL', 'HIGH')
             then 1 else 0 end)                                     as ai_high_critical_cves,
    round(100.0 * sum(case when is_ai_related then 1 else 0 end)
          / count(*), 2)                                            as ai_share_pct
from {{ ref('stg_cves') }}
group by published_year
