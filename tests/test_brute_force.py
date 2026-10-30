from logscope.rules.brute_force import detect_brute_force
from datetime import datetime, timezone, timedelta
from logscope.storage import init_db, insert_event, query_events
from logscope.rules.loader import load_rule



def test_no_events_returns_no_alerts(make_rule):
    events = list()

    r = make_rule()
    res = detect_brute_force(events, r)

    assert res == []


def test_real_alert(make_event, make_rule):
    start = datetime(2026, 10, 19, 1, 41, 0, tzinfo=timezone.utc)
    
    events = []
    for num in range(5):
        events.append(make_event(
            timestamp = start + timedelta(seconds=10 * num)
        ))

    r = make_rule()
    res = detect_brute_force(events, r)


    assert len(res) == 1
    assert res[0].src_ip == '203.0.113.5'
    assert res[0].count == 5
    assert res[0].last_seen == datetime(2026, 10, 19, 1, 41, 40, tzinfo=timezone.utc)


def test_four_failures_below_threshold_make_no_alert(make_event, make_rule):
    start = datetime(2026, 10, 19, 1, 41, 0, tzinfo=timezone.utc)

    events = []
    for num in range(4):
        events.append(make_event(
            timestamp = start + timedelta(seconds=10 * num)
        ))


    r = make_rule()
    res = detect_brute_force(events, r)


    assert len(res) == 0


def test_events_without_src_ip_are_ignored(make_event, make_rule):
    start = datetime(2026, 10, 19, 1, 41, 0, tzinfo=timezone.utc)

    events = []
    for num in range(5):
        events.append(make_event(
            timestamp = start + timedelta(seconds=10 * num),
            src_ip = None
        ))


    r = make_rule()
    res = detect_brute_force(events, r)


    assert len(res) == 0


def test_failure_exactly_at_window_edge_is_not_counted(make_event, make_rule):
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

    r = make_rule()
    res = detect_brute_force(events, r)

    assert len(res) == 1
    assert res[0].count == 5


    events2 = []
    for num in range(5):
        events2.append(make_event(
            timestamp = start + timedelta(seconds=15 * num)
        ))

    res2 = detect_brute_force(events2, r)
    
    assert len(res2) == 0


def test_different_ips_are_counted_separately(make_event, make_rule):
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


    r = make_rule()
    res = detect_brute_force(events, r)

    assert len(res) == 1
    assert res[0].src_ip == '203.0.113.5'
    assert res[0].count == 5


def test_non_failed_events_are_ignored(make_event, make_rule):
    start = datetime(2026, 10, 19, 1, 41, 0, tzinfo=timezone.utc)

    events = []

    for num in range(5):
        events.append(make_event(
            timestamp = start + timedelta(seconds=10 * num),
            event_type='ssh_login_success'
        ))

    r = make_rule()
    res = detect_brute_force(events, r)
    
    assert len(res) == 0


def test_unsorted_events_still_produce_alert(make_event, make_rule):
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
    r = make_rule()

    res = detect_brute_force(events, r)

    assert len(res) == 1
    assert res[0].first_seen == datetime(2026, 10, 19, 1, 41, 0, tzinfo=timezone.utc)
    assert res[0].last_seen == datetime(2026, 10, 19, 1, 41, 40, tzinfo=timezone.utc)


def test_rule_works_on_events_from_storage(tmp_path, make_event, make_rule):
    db = tmp_path / 'test.db'
    init_db(db)
    start = datetime(2026, 10, 19, 1, 41, 0, tzinfo=timezone.utc)

    r = make_rule()


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

    res = detect_brute_force(events_from_db, r)

    assert len(res) == 1
    assert res[0].count == 5
    assert res[0].first_seen == start
    assert len(events_from_db) == 5


def test_rule_event_type_is_used(make_event, make_rule):
    start = datetime(2026, 10, 19, 1, 41, 0, tzinfo=timezone.utc)
    events = []

    r = make_rule(
        event_type='ssh_login_success',
    )


    for num in range(5):
        events.append(make_event(
            timestamp = start + timedelta(seconds=10 * num),
            event_type='ssh_login_success'
        ))

    for num in range(3):
        events.append(make_event(
            timestamp = start + timedelta(seconds=10 * num),
        ))
    

    res = detect_brute_force(events, r)

    assert len(res) == 1
    assert res[0].count == 5


def test_rule_threshold_is_used(make_event, make_rule):
    start = datetime(2026, 10, 19, 1, 41, 0, tzinfo=timezone.utc)
    events = []
    events2 = []

    r = make_rule(
        threshold=3
    )

    for num in range(3):
        events.append(make_event(
            timestamp = start + timedelta(seconds=10 * num),
        ))

    for num in range(2):
        events2.append(make_event(
            timestamp = start + timedelta(seconds=10 * num),
        ))

    res = detect_brute_force(events, r)
    res2 = detect_brute_force(events2, r)
    
    assert len(res) == 1
    assert len(res2) == 0
    assert res[0].count == 3


def test_rule_window_seconds_is_used(make_event, make_rule):
    events = []

    r = make_rule(
        threshold=3,
        window_seconds=10
    )

    event1 = make_event(
        timestamp = datetime(2026, 10, 19, 1, 41, 0, tzinfo=timezone.utc)
    )

    event2 = make_event(
        timestamp = datetime(2026, 10, 19, 1, 41, 4, tzinfo=timezone.utc)
    )

    event3 = make_event(
        timestamp = datetime(2026, 10, 19, 1, 41, 9, tzinfo=timezone.utc)
    )

    event4 = make_event(
        timestamp = datetime(2026, 10, 19, 1, 41, 10, tzinfo=timezone.utc)
    )

    events = [event1, event2, event3, event4]
    events2 = [event1, event2, event4]


    res = detect_brute_force(events, r)
    res2 = detect_brute_force(events2, r)
    
    assert len(res) == 1
    assert len(res2) == 0
    assert res[0].count == 3


def test_alert_uses_rule_id(make_event, make_rule):
    start = datetime(2026, 10, 19, 1, 41, 0, tzinfo=timezone.utc)
    events = []

    r = make_rule(
        id='custom_rule'
    )

    for num in range(5):
        events.append(make_event(
            timestamp = start + timedelta(seconds=10 * num),
        ))

    res = detect_brute_force(events, r)

    assert len(res) == 1
    assert res[0].rule == 'custom_rule'


def test_detector_uses_rule_loaded_from_yaml(tmp_path, make_event):
    p = tmp_path / 'rule.yml'
    p.write_text('id: custom_yaml_rule\nevent_type: ssh_login_success\nthreshold: 3\nwindow_seconds: 10', encoding='utf-8')

    r = load_rule(p)

    event1 = make_event(
        event_type = 'ssh_login_success',
        timestamp = datetime(2026, 10, 19, 1, 41, 0, tzinfo=timezone.utc)
    )

    event2 = make_event(
        event_type = 'ssh_login_success',
        timestamp = datetime(2026, 10, 19, 1, 41, 4, tzinfo=timezone.utc)
    )

    event3 = make_event(
        event_type = 'ssh_login_success',
        timestamp = datetime(2026, 10, 19, 1, 41, 9, tzinfo=timezone.utc)
    )

    events = [event1, event2, event3]

    res = detect_brute_force(events, r)

    assert len(res) == 1
    assert res[0].count == 3
    assert res[0].rule == 'custom_yaml_rule'