
CREATE OR REPLACE TABLE enriched_logs AS
SELECT
    l.timestamp,
    l.severity,
    l.protocol,
    l.src_ip,
    l.dst_ip,
    l.message,
    CASE
        WHEN t_src.ip IS NOT NULL OR t_dst.ip IS NOT NULL THEN TRUE
        ELSE FALSE
    END AS is_malicious,
    COALESCE(t_src.confidence_level, t_dst.confidence_level) AS confidence_level
FROM raw_logs l
LEFT JOIN threat_ips t_src ON l.src_ip = t_src.ip
LEFT JOIN threat_ips t_dst ON l.dst_ip = t_dst.ip;
