import sqlite3
from pathlib import Path
from logscope.models import Event
from datetime import datetime



def init_db(db_path: Path) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                timestamp TEXT NOT NULL,
                host TEXT NOT NULL,
                source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                raw TEXT NOT NULL,
                user TEXT,
                src_ip TEXT,
                src_port INTEGER
            )
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp)
        """)


def insert_event(db_path: Path, event: Event) -> None:
    iso_datetime = event.timestamp.isoformat()

    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            INSERT INTO events (timestamp, host, source, event_type, raw, user, src_ip, src_port)
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
    iso_start = start.isoformat()
    iso_end = end.isoformat()

    with sqlite3.connect(db_path) as conn:
        cursor = conn.execute("""
            SELECT timestamp, host, source, event_type, raw, user, src_ip, src_port
            FROM events WHERE timestamp >= ? AND timestamp <= ?
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