-- stg_cves: light, mechanical cleanup of the raw table. No aggregation here.
--
--   1. keep ONE row per CVE (the most recently modified one)
--   2. drop REJECTED CVEs (they are withdrawn, not real vulnerabilities)
--   3. keep UNSCORED CVEs (severity = 'UNSCORED') instead of dropping them:
--      NVD has a large scoring backlog for recent CVEs, and dropping them would
--      make 2024-2026 look artificially quieter than earlier years
--   4. standardise text, add published_year and the is_ai_related flag

with source as (

    select * from {{ source('nvd', 'raw_cves') }}

),

ranked as (

    select
        *,
        row_number() over (
            partition by cve_id
            order by last_modified_date desc
        ) as row_num
    from source

),

cleaned as (

    select
        cve_id,
        published_date,
        last_modified_date,
        vuln_status,
        coalesce(nullif(upper(trim(severity)), ''), 'UNSCORED') as severity,
        cvss_score,
        coalesce(nullif(lower(trim(vendor)), ''), 'unknown')    as vendor,
        coalesce(nullif(lower(trim(product)), ''), 'unknown')   as product,
        coalesce(nullif(upper(trim(cwe_id)), ''), 'unknown')    as cwe_id,
        description,
        extract(year from published_date)                       as published_year,
        regexp_contains(lower(description), r'{{ ai_regex() }}') as is_ai_related

    from ranked
    where row_num = 1
      and cve_id is not null
      and published_date is not null
      and published_date >= date '2023-01-01'
      and coalesce(lower(vuln_status), '') != 'rejected'

)

select * from cleaned
