import pytest
import sqlite3
from datetime import datetime, timezone
from logscope.storage import init_db, insert_event, query_events
from logscope.models import Event



def test_init_db_creates_table(tmp_path):
    p = tmp_path / 'test.db'
    init_db(p)

    with sqlite3.connect(p) as conn:
        cursor = conn.execute("""
            SELECT name FROM sqlite_master WHERE type='table' AND name='events'
        """)

        rows = cursor.fetchall()


    assert len(rows) == 1


def test_init_db_idempotent(tmp_path):
    p = tmp_path / 'test.db'
    init_db(p)
    init_db(p)

    with sqlite3.connect(p) as conn:
        cursor = conn.execute("""
            SELECT name FROM sqlite_master WHERE type='table' AND name='events'
        """)
    
        assert len(cursor.fetchall()) == 1
    

def test_insert_event(tmp_path):
    p = tmp_path / 'test.db'

    event = Event(
        timestamp = datetime(2026, 10, 19, 1, 41, 2, tzinfo=timezone.utc), 
        host = 'srv', 
        source = 'auth.log', 
        event_type = 'ssh_login_failed', 
        raw = 'raw', 
        user = 'root',
        src_ip = '192.168.0.1', 
        src_port = 22
    )

    init_db(p)
    insert_event(p, event)

    with sqlite3.connect(p) as conn:
        cursor = conn.execute("""
            SELECT * FROM events
        """)

        rows = cursor.fetchall()

    for row in rows:
        date = row[0]
        host = row[1]

    assert len(rows) == 1
    assert date == '2026-10-19T01:41:02+00:00'
    assert host == 'srv'


def test_insert_event_with_nulls(tmp_path):
    p = tmp_path / 'test.db'
    
    event = Event(
        timestamp = datetime(2026, 10, 19, 1, 41, 2, tzinfo=timezone.utc), 
        host = 'srv', 
        source = 'auth.log', 
        event_type = 'ssh_login_failed', 
        raw = 'raw', 
        user = None,
        src_ip = None,
        src_port = None
    )

    init_db(p)
    insert_event(p, event)

    with sqlite3.connect(p) as conn:
        cursor = conn.execute("""
            SELECT * FROM events
        """)

        rows = cursor.fetchall()

    for row in rows:
        user = row[5]
        src_ip = row[6]
        src_port = row[7]


    assert user is None
    assert src_ip is None
    assert src_port is None


def test_query_events_in_range(tmp_path):
    p = tmp_path / 'test.db'
    
    event1 = Event(
        timestamp = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc), 
        host = 'srv', 
        source = 'auth.log', 
        event_type = 'ssh_login_failed', 
        raw = 'raw', 
        user = None,
        src_ip = None,
        src_port = None
    )
    event2 = Event(
        timestamp = datetime(2026, 1, 1, 0, 0, 1, tzinfo=timezone.utc), 
        host = 'srv', 
        source = 'auth.log', 
        event_type = 'ssh_login_failed', 
        raw = 'raw', 
        user = None,
        src_ip = None,
        src_port = None
    )
    event3 = Event(
        timestamp = datetime(2026, 1, 1, 0, 0, 2, tzinfo=timezone.utc), 
        host = 'srv', 
        source = 'auth.log', 
        event_type = 'ssh_login_failed', 
        raw = 'raw', 
        user = None,
        src_ip = None,
        src_port = None
    )
    event4 = Event(
        timestamp = datetime(2026, 1, 1, 0, 0, 3, tzinfo=timezone.utc), 
        host = 'srv', 
        source = 'auth.log', 
        event_type = 'ssh_login_failed', 
        raw = 'raw', 
        user = None,
        src_ip = None,
        src_port = None
    )
    event5 = Event(
        timestamp = datetime(2026, 1, 1, 0, 0, 4, tzinfo=timezone.utc), 
        host = 'srv', 
        source = 'auth.log', 
        event_type = 'ssh_login_failed', 
        raw = 'raw', 
        user = None,
        src_ip = None,
        src_port = None
    )


    init_db(p)
    insert_event(p, event1)
    insert_event(p, event2)
    insert_event(p, event3)
    insert_event(p, event4)
    insert_event(p, event5)

    start = datetime(2026, 1, 1, 0, 0, 1, tzinfo=timezone.utc)
    end = datetime(2026, 1, 1, 0, 0, 3, tzinfo=timezone.utc)
    
    events = query_events(p, start=start, end=end)

    assert len(events) == 3


def test_query_events_empty_result(tmp_path):
    p = tmp_path / 'test.db'
    
    event = Event(
        timestamp = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc), 
        host = 'srv', 
        source = 'auth.log', 
        event_type = 'ssh_login_failed', 
        raw = 'raw', 
        user = None,
        src_ip = None,
        src_port = None
    )

    init_db(p)
    insert_event(p, event)

    start = datetime(2026, 1, 2, 0, 0, 0, tzinfo=timezone.utc)
    end = datetime(2026, 1, 3, 0, 0, 0, tzinfo=timezone.utc)

    events = query_events(p, start=start, end=end)

    assert len(events) == 0


def test_query_events_preserves_order(tmp_path):
    p = tmp_path / 'test.db'
    
    event1 = Event(
        timestamp = datetime(2026, 1, 1, 0, 0, 2, tzinfo=timezone.utc), 
        host = 'srv', 
        source = 'auth.log', 
        event_type = 'ssh_login_failed', 
        raw = 'raw', 
        user = None,
        src_ip = None,
        src_port = None
    )
    event2 = Event(
        timestamp = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc), 
        host = 'srv', 
        source = 'auth.log', 
        event_type = 'ssh_login_failed', 
        raw = 'raw', 
        user = None,
        src_ip = None,
        src_port = None
    )
    event3 = Event(
        timestamp = datetime(2026, 1, 1, 0, 0, 1, tzinfo=timezone.utc), 
        host = 'srv', 
        source = 'auth.log', 
        event_type = 'ssh_login_failed', 
        raw = 'raw', 
        user = None,
        src_ip = None,
        src_port = None
    )

    init_db(p)
    insert_event(p, event1)
    insert_event(p, event2)
    insert_event(p, event3)

    with sqlite3.connect(p) as conn:
        cursor = conn.execute("""
            SELECT * FROM events
        """)

        rows = cursor.fetchall()


    start = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    end = datetime(2026, 1, 1, 0, 0, 2, tzinfo=timezone.utc)
    
    events = query_events(p, start=start, end=end)
    
    assert len(events) == 3
    assert events[0].timestamp == datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    assert events[1].timestamp == datetime(2026, 1, 1, 0, 0, 1, tzinfo=timezone.utc)
    assert events[2].timestamp == datetime(2026, 1, 1, 0, 0, 2, tzinfo=timezone.utc)
    