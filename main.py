"""
Main pipeline orchestrator.

Runs the full data pipeline:
1. Log ingestion
2. Threat feed ingestion
3. Log enrichment
"""

import subprocess
import sys


def run_step(command: list[str], step_name: str):
    print(f"\n Running step: {step_name}")

    result = subprocess.run(
        command,
        stdout=sys.stdout,
        stderr=sys.stderr,
        text=True
    )

    if result.returncode != 0:
        raise RuntimeError(f"Step failed: {step_name}")

    print(f" Completed: {step_name}")


def main():
    run_step(
        [sys.executable, "-m", "ingestion.ingest_logs"],
        "Log ingestion"
    )

    run_step(
        [sys.executable, "-m", "ingestion.load_threat_feed"],
        "Threat feed ingestion"
    )

    run_step(
        [sys.executable, "-m", "enrichment.run_enrichment"],
        "Log enrichment"
    )

    print("\n Full pipeline executed successfully")


if __name__ == "__main__":
    main()
