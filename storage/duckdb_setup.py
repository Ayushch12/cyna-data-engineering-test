
"""
DuckDB helper.

This file creates and connects to a SINGLE DuckDB database
shared by the ingestion pipeline and the Streamlit dashboard.
"""

import duckdb
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

DB_PATH = PROJECT_ROOT / "data" / "security_logs.duckdb"


def get_connection():
    """
    Create or connect to the DuckDB database using an absolute path.
    This guarantees the same DB is used by:
    - python main.py
    - streamlit run dashboards/app.py
    """
    DB_PATH.parent.mkdir(exist_ok=True)
    return duckdb.connect(str(DB_PATH))


def save_raw_logs(df):
    """
    Save raw logs into DuckDB (raw_logs table).
    """
    conn = get_connection()

    conn.execute("""
        CREATE OR REPLACE TABLE raw_logs AS
        SELECT * FROM df
    """)

    conn.close()
    print("Data stored in DuckDB (raw_logs)")
