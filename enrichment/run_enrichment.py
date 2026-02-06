"""
Run SQL enrichment to join logs with threat intelligence.
"""

from storage.duckdb_setup import get_connection


def main():
    conn = get_connection()

    with open("enrichment/enrich_logs.sql", "r") as file:
        sql = file.read()

    conn.execute(sql)

    result = conn.execute(
        "SELECT COUNT(*) FROM enriched_logs WHERE is_malicious = TRUE"
    ).fetchone()

    print("Enrichment complete")
    print("Malicious events:", result[0])


if __name__ == "__main__":
    main()
