
WITH cves AS (
    SELECT
        cve_id,
        cvss_score AS severity_score,
        LOWER(TRIM(vendor)) AS vendor,
        LOWER(TRIM(product)) AS product
    FROM {{ ref('stg_cves') }}
),

kev AS (
    SELECT DISTINCT UPPER(TRIM(cve_id)) AS cve_id
    FROM {{ source('risk_feeds', 'raw_kev') }}
),

epss AS (
    SELECT
        UPPER(TRIM(cve_id)) AS cve_id,
        epss_score
    FROM {{ source('risk_feeds', 'raw_epss') }}
    QUALIFY ROW_NUMBER() OVER (
        PARTITION BY UPPER(TRIM(cve_id))
        ORDER BY score_date DESC
    ) = 1
),

demo_assets AS (
    SELECT DISTINCT
        LOWER(TRIM(vendor)) AS vendor,
        LOWER(TRIM(product)) AS product
    FROM {{ ref('simulated_assets') }}
),

risk_signals AS (
    SELECT
        CURRENT_DATE() AS snapshot_date,
        c.cve_id,
        c.severity_score,
        e.epss_score,
        k.cve_id IS NOT NULL AS in_kev,
        a.vendor IS NOT NULL AS affects_our_assets
    FROM cves c
    LEFT JOIN kev k USING (cve_id)
    LEFT JOIN epss e USING (cve_id)
    LEFT JOIN demo_assets a
        ON c.vendor = a.vendor
       AND c.product = a.product
)

SELECT
    *,
    CASE
        WHEN affects_our_assets
             AND (in_kev OR COALESCE(epss_score, 0) >= 0.50)
            THEN 'P1'
        WHEN in_kev
             OR (
                 affects_our_assets
                 AND (
                     COALESCE(epss_score, 0) >= 0.10
                     OR COALESCE(severity_score, 0) >= 9
                 )
             )
            THEN 'P2'
        WHEN COALESCE(epss_score, 0) >= 0.05
             OR COALESCE(severity_score, 0) >= 7
            THEN 'P3'
        ELSE 'P4'
    END AS priority_tier
FROM risk_signals
