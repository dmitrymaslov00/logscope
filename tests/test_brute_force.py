from logscope.rules.brute_force import detect_brute_force
from datetime import datetime, timezone, timedelta
from logscope.storage import init_db, insert_event, query_events



def test_no_events_returns_no_alerts():
    events = list()

    res = detect_brute_force(events)

    assert res == []


def test_real_alert(make_event):
    start = datetime(2026, 10, 19, 1, 41, 0, tzinfo=timezone.utc)
    
    events = []
    for num in range(5):
        events.append(make_event(
            timestamp = start + timedelta(seconds=10 * num)
        ))

    res = detect_brute_force(events)


    assert len(res) == 1
    assert res[0].src_ip == '203.0.113.5'
    assert res[0].count == 5
    assert res[0].last_seen == datetime(2026, 10, 19, 1, 41, 40, tzinfo=timezone.utc)


def test_four_failures_below_threshold_make_no_alert(make_event):
    start = datetime(2026, 10, 19, 1, 41, 0, tzinfo=timezone.utc)

    events = []
    for num in range(4):
        events.append(make_event(
            timestamp = start + timedelta(seconds=10 * num)
        ))


    res = detect_brute_force(events)


    assert len(res) == 0


def test_events_without_src_ip_are_ignored(make_event):
    start = datetime(2026, 10, 19, 1, 41, 0, tzinfo=timezone.utc)

    events = []
    for num in range(5):
        events.append(make_event(
            timestamp = start + timedelta(seconds=10 * num),
            src_ip = None
        ))


    res = detect_brute_force(events)


    assert len(res) == 0


def test_failure_exactly_at_window_edge_is_not_counted(make_event):
    start = datetime(2026, 10, 19, 1, 41, 0, tzinfo=timezone.utc)

    events = []
    for num in range(4):
        events.append(make_event(
            timestamp = start + timedelta(seconds=15 * num)
        ))

    event5 = make_event(
        timestamp = datetime(2026, 10, 19, 1, 41, 59, tzinfo=timezone.utc),
    )

    events.append(event5)

    res = detect_brute_force(events)

    assert len(res) == 1
    assert res[0].count == 5


    events2 = []
    for num in range(5):
        events2.append(make_event(
            timestamp = start + timedelta(seconds=15 * num)
        ))

    res2 = detect_brute_force(events2)
    
    assert len(res2) == 0


def test_different_ips_are_counted_separately(make_event):
    start = datetime(2026, 10, 19, 1, 41, 0, tzinfo=timezone.utc)

    events = []

    for num in range(5):
        events.append(make_event(
            timestamp = start + timedelta(seconds=10 * num),
            src_ip = '203.0.113.5'
        ))

    for num in range(3):
        events.append(make_event(
            timestamp = start + timedelta(seconds=10 * num + 5),
            src_ip = '203.0.113.9'
        ))


    res = detect_brute_force(events)

    assert len(res) == 1
    assert res[0].src_ip == '203.0.113.5'
    assert res[0].count == 5


def test_non_failed_events_are_ignored(make_event):
    start = datetime(2026, 10, 19, 1, 41, 0, tzinfo=timezone.utc)

    events = []

    for num in range(5):
        events.append(make_event(
            timestamp = start + timedelta(seconds=10 * num),
            event_type='ssh_login_success'
        ))

    res = detect_brute_force(events)
    
    assert len(res) == 0


def test_unsorted_events_still_produce_alert(make_event):
    event1 = make_event(
        timestamp = datetime(2026, 10, 19, 1, 41, 40, tzinfo=timezone.utc)
    )

    event2 = make_event(
        timestamp = datetime(2026, 10, 19, 1, 41, 0, tzinfo=timezone.utc)
    )

    event3 = make_event(
        timestamp = datetime(2026, 10, 19, 1, 41, 30, tzinfo=timezone.utc)
    )

    event4 = make_event(
        timestamp = datetime(2026, 10, 19, 1, 41, 10, tzinfo=timezone.utc)
    )

    event5 = make_event(
        timestamp = datetime(2026, 10, 19, 1, 41, 20, tzinfo=timezone.utc)
    )


    events = [event1, event2, event3, event4, event5]

    res = detect_brute_force(events)

    assert len(res) == 1
    assert res[0].first_seen == datetime(2026, 10, 19, 1, 41, 0, tzinfo=timezone.utc)
    assert res[0].last_seen == datetime(2026, 10, 19, 1, 41, 40, tzinfo=timezone.utc)


def test_rule_works_on_events_from_storage(tmp_path, make_event):
    db = tmp_path / 'test.db'
    init_db(db)
    start = datetime(2026, 10, 19, 1, 41, 0, tzinfo=timezone.utc)


    for num in range(5):
        event = make_event(
            timestamp = start + timedelta(seconds=10 * num),
            event_type='ssh_login_failed'
        )
        insert_event(db, event)

    event = make_event(
        timestamp = datetime(2026, 10, 19, 2, 41, 0, tzinfo=timezone.utc)
    )

    insert_event(db, event)


    events_from_db = query_events(db, start, end = start + timedelta(minutes=1))

    res = detect_brute_force(events_from_db)

    assert len(res) == 1
    assert res[0].count == 5
    assert res[0].first_seen == start
    assert len(events_from_db) == 5
