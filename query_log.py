"""
query_log.py
------------
Example queries against gateway_log.db -- this is the whole point of
having switched from a JSONL file to SQLite. A flat file, you can only
grep. A database, you can actually ask it questions.

Run after you've generated some traffic (e.g. `python demo.py`):

    python query_log.py
"""

import sqlite3
from pathlib import Path

DB_FILE = Path(__file__).parent / "gateway_log.db"


def run(title: str, sql: str) -> None:
    print(f"\n--- {title} ---")
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql).fetchall()
        if not rows:
            print("  (no rows)")
            return
        cols = rows[0].keys()
        for row in rows:
            print("  " + "  ".join(f"{c}={row[c]}" for c in cols))


if __name__ == "__main__":
    if not DB_FILE.exists():
        print("No gateway_log.db yet -- run test_client.py or demo.py first.")
        raise SystemExit(1)

    run(
        "Every verdict, counted",
        """
        SELECT verdict, COUNT(*) AS n
        FROM events
        WHERE verdict IS NOT NULL
        GROUP BY verdict
        ORDER BY n DESC
        """,
    )

    run(
        "Every BLOCK, with reasons",
        """
        SELECT ts, tool, reasons
        FROM events
        WHERE verdict = 'BLOCK'
        ORDER BY ts
        """,
    )

    run(
        "Which tool got flagged/blocked most",
        """
        SELECT tool, COUNT(*) AS n
        FROM events
        WHERE verdict IN ('BLOCK', 'FLAG', 'SUSPICIOUS')
        GROUP BY tool
        ORDER BY n DESC
        """,
    )

    run(
        "Every event type that ran, in order, with a timestamp",
        """
        SELECT id, ts, event_type, tool
        FROM events
        ORDER BY id
        LIMIT 20
        """,
    )

    run(
        "Total events logged",
        "SELECT COUNT(*) AS total_events FROM events",
    )
