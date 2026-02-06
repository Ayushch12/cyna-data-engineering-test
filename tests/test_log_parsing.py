from ingestion.ingest_logs import parse_log_line


def test_parse_log_line_basic():
    log_line = (
        "2023-07-23 21:36:36,227 - ids_logger_1 - low_severity - TCP - "
        "61.72.88.110:57020 --> 179.34.191.24:18059 - SYN - Port scanning"
    )

    parsed = parse_log_line(log_line)

    assert parsed["severity"] == "low_severity"
    assert parsed["protocol"] == "TCP"
    assert parsed["src_ip"] == "61.72.88.110"
    assert parsed["dst_ip"] == "179.34.191.24"
    assert parsed["message"] == "Port scanning"
