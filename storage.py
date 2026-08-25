"""
storage.py
----------
Structured, queryable event storage for the gateway -- replaces the
flat gateway_log.jsonl file from earlier versions with a real
database, and configures Python's standard `logging` module for
human-readable, real-time operational output.

Why this split:

- SQLite (gateway_log.db) is the permanent, structured audit trail.
  A JSONL file is fine to grep for a handful of events, but once you
  want to actually ask questions of it -- "how many calls got
  blocked this week," "which tool gets flagged most" -- you need a
  query engine, not text search. sqlite3 is in Python's standard
  library: no server to run, no new dependency, and it's a normal
  production pattern (see query_log.py for example queries).

- The `logging` module is what a human actually watches scroll by in
  the terminal while the gateway runs. It's separate from the audit
  trail on purpose: operational visibility ("something just got
  blocked") and permanent structured record (queryable later) are two
  different jobs, and conflating them into one file is why the old
  JSONL approach didn't scale.
"""

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_FILE = Path(__file__).parent / "gateway_log.db"

# --- operational logger: what you watch scroll by in real time ---
logger = logging.getLogger("gateway")
logger.setLevel(logging.INFO)
if not logger.handlers:
    # Guard against adding a second handler if this module gets
    # imported more than once in the same process.
    _handler = logging.StreamHandler()
    _handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")
    )
    logger.addHandler(_handler)


def init_db() -> None:
    """Create the events table (and a couple of indexes) if they don't
    exist yet. Safe to call every time the gateway starts -- CREATE
    TABLE IF NOT EXISTS is a no-op once it's already there."""
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                event_type TEXT NOT NULL,
                tool TEXT,
                verdict TEXT,
                confidence TEXT,
                reasons TEXT,
                raw_json TEXT NOT NULL
            )
            """
        )
        # Indexes make the example queries in query_log.py fast even
        # once this file has thousands of rows -- not that it matters
        # yet at demo scale, but it costs nothing and it's the right
        # habit.
        conn.execute("CREATE INDEX IF NOT EXISTS idx_event_type ON events(event_type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tool ON events(tool)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_verdict ON events(verdict)")


def log_event(event: dict) -> None:
    """Write one event to SQLite (the permanent structured record) and
    also emit a short human-readable line via `logging` (what shows up
    in the terminal). This is a drop-in replacement for the old
    gateway.py log_event() -- same call shape, same callers, different
    backend."""
    event = dict(event)  # don't mutate the caller's dict
    event["ts"] = datetime.now(timezone.utc).isoformat()

    # policy_check events use a single "reason" string; scan events use
    # a "reasons" list. Normalize to a list either way so the column
    # is consistently queryable regardless of which kind of event this is.
    reasons = event.get("reasons")
    if not reasons and event.get("reason"):
        reasons = [event["reason"]]

    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            "INSERT INTO events (ts, event_type, tool, verdict, confidence, reasons, raw_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                event["ts"],
                event.get("event"),
                event.get("tool"),
                event.get("verdict"),
                event.get("confidence"),
                json.dumps(reasons or []),
                json.dumps(event, default=str),
            ),
        )

    _emit_log_line(event)


def _emit_log_line(event: dict) -> None:
    """Turn a structured event into one readable terminal line. Things
    that actually matter (a BLOCK, a SUSPICIOUS scan result) get logged
    at WARNING so they visually stand out; routine passes are INFO."""
    kind = event.get("event", "event")
    tool = event.get("tool", "")
    verdict = event.get("verdict")

    if verdict in ("BLOCK", "SUSPICIOUS"):
        reasons = ", ".join(event.get("reasons") or []) or event.get("reason", "")
        logger.warning(f"{kind} tool={tool} verdict={verdict} reasons=[{reasons}]")
    elif verdict == "FLAG":
        logger.info(f"{kind} tool={tool} verdict={verdict} reason={event.get('reason', '')}")
    else:
        logger.info(f"{kind} tool={tool}")
