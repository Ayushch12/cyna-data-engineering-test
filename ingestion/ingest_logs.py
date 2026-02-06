
import pandas as pd
from storage.duckdb_setup import get_connection


def parse_log_line(line: str):
    """
    Parse a single IDS log line into structured fields.
    Returns None if the line is malformed.
    """

    # Skip empty lines
    if not line.strip():
        return None

    parts = line.split(" - ")

    if len(parts) < 7:
        return None

    try:
        timestamp = parts[0]
        severity = parts[2]
        protocol = parts[3]

        ip_part = parts[4]
        message = parts[-1]

        src_part, dst_part = ip_part.split(" --> ")
        src_ip = src_part.split(":")[0]
        dst_ip = dst_part.split(":")[0]

        return {
            "timestamp": timestamp,
            "severity": severity,
            "protocol": protocol,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "message": message,
        }

    except Exception:
        return None


def main():
    """
    Ingest IDS logs into DuckDB.
    This step is idempotent: the raw_logs table is fully replaced each run.
    """

    log_file_path = "data/input/ids.log"

    parsed_logs = []

    with open(log_file_path, "r") as file:
        for line in file:
            parsed = parse_log_line(line.strip())
            if parsed:
                parsed_logs.append(parsed)

    if not parsed_logs:
        raise RuntimeError("No valid IDS logs found for ingestion")

    df = pd.DataFrame(parsed_logs)

    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        format="%Y-%m-%d %H:%M:%S,%f",
        errors="coerce",
    )
    df = df.dropna(subset=["timestamp"])

    # Store logs into DuckDB
    conn = get_connection()

    # Register DataFrame as a temporary DuckDB view
    conn.register("logs_df", df)

    conn.execute("""
        CREATE OR REPLACE TABLE raw_logs AS
        SELECT
            timestamp,
            severity,
            protocol,
            src_ip,
            dst_ip,
            message
        FROM logs_df
    """)

    conn.close()


if __name__ == "__main__":
    main()
