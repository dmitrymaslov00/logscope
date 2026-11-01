import sqlite3
from pathlib import Path
from logscope.models import Event, EnrichedAlert
from datetime import datetime, timezone
from contextlib import closing
import json



def _to_utc_iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        raise ValueError('naive datetime is not allowed, pass a timezone-aware value')

    utc_dt = dt.astimezone(timezone.utc)
    iso_datetime = utc_dt.isoformat()
    return iso_datetime


def init_db(db_path: Path) -> None:
    with closing(sqlite3.connect(db_path)) as conn:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    timestamp TEXT NOT NULL,
                    host TEXT NOT NULL,
                    source TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    raw TEXT NOT NULL,
                    user TEXT,
                    src_ip TEXT,
                    src_port INTEGER,
                    UNIQUE (timestamp, host, source, raw)
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY,
                    rule TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    count INTEGER NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    abuseipdb TEXT NOT NULL
                )
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp)
            """)


def insert_event(db_path: Path, event: Event) -> None:
    iso_datetime = _to_utc_iso(event.timestamp)

    with closing(sqlite3.connect(db_path)) as conn:
        with conn:
            conn.execute("""
                INSERT OR IGNORE INTO events (timestamp, host, source, event_type, raw, user, src_ip, src_port)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    iso_datetime,
                    event.host,
                    event.source,
                    event.event_type,
                    event.raw,
                    event.user,
                    event.src_ip,
                    event.src_port
                ),
            )



def query_events(db_path: Path, start: datetime, end: datetime) -> list[Event]:
    iso_start = _to_utc_iso(start)
    iso_end = _to_utc_iso(end)

    with closing(sqlite3.connect(db_path)) as conn:
        with conn:
            cursor = conn.execute("""
                SELECT timestamp, host, source, event_type, raw, user, src_ip, src_port
                FROM events WHERE timestamp >= ? AND timestamp < ?
                ORDER BY timestamp
            """,
                (
                    iso_start, iso_end
                ),
            )

            rows = cursor.fetchall()

            return [
                Event(
                    timestamp=datetime.fromisoformat(row[0]),
                    host=row[1], 
                    source=row[2], 
                    event_type=row[3], 
                    raw=row[4], 
                    user=row[5], 
                    src_ip=row[6], 
                    src_port=row[7]
                )
                
                for row in rows
            ]


def insert_enriched_alert(db_path: Path, enriched_alert: EnrichedAlert) -> None:
    iso_first_seen = _to_utc_iso(enriched_alert.alert.first_seen)
    iso_last_seen = _to_utc_iso(enriched_alert.alert.last_seen)
    abuseipdb_res = json.dumps(enriched_alert.abuseipdb, ensure_ascii=False)


    with closing(sqlite3.connect(db_path)) as conn:
        with conn:
            conn.execute("""
                INSERT INTO alerts (rule, src_ip, count, first_seen, last_seen, abuseipdb)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (
                    enriched_alert.alert.rule,
                    enriched_alert.alert.src_ip,
                    enriched_alert.alert.count,
                    iso_first_seen,
                    iso_last_seen,
                    abuseipdb_res,
                ),
            )
