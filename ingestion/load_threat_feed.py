"""
This script loads the IPSUM threat intelligence feed
and prepares it for storage.
"""

import pandas as pd
from storage.duckdb_setup import get_connection

def load_ipsum_feed(file_path: str) -> pd.DataFrame:
    records = []

    with open(file_path, "r") as file:
        for line in file:
            line = line.strip()

            # Skip empty lines or comments
            if not line or line.startswith("#"):
                continue

            parts = line.split()

            # Basic safety check
            if len(parts) != 2:
                continue

            ip, level = parts

            records.append({
                "ip": ip,
                "confidence_level": int(level)
            })

    return pd.DataFrame(records)

def main():
    ipsum_path = "data/input/ipsum.txt"

    df = load_ipsum_feed(ipsum_path)

    print("Threat feed loaded")
    print("Rows:", len(df))
    print(df.head())

    # Store in DuckDB
    conn = get_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS threat_ips AS
        SELECT * FROM df
    """)

    print("Threat feed stored in DuckDB (table: threat_ips)")

if __name__ == "__main__":
    main()
