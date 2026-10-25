from logscope.rules.brute_force import detect_brute_force
from datetime import datetime, timezone



def test_no_events_returns_no_alerts():
    events = list()

    res = detect_brute_force(events)

    assert res == []


def test_real_alert(make_event):
    event1 = make_event(
        timestamp = datetime(2026, 10, 19, 1, 41, 0, tzinfo=timezone.utc),
    )

    event2 = make_event(
        timestamp = datetime(2026, 10, 19, 1, 41, 10, tzinfo=timezone.utc),
    )

    event3 = make_event(
        timestamp = datetime(2026, 10, 19, 1, 41, 20, tzinfo=timezone.utc),
    )

    event4 = make_event(
        timestamp = datetime(2026, 10, 19, 1, 41, 30, tzinfo=timezone.utc),
    )

    event5 = make_event(
        timestamp = datetime(2026, 10, 19, 1, 41, 40, tzinfo=timezone.utc),
    )

    
    events = [event1, event2, event3, event4, event5]

    res = detect_brute_force(events)


    assert len(res) == 1
    assert res[0].src_ip == '192.168.0.1'
    assert res[0].count == 5
    assert res[0].last_seen == datetime(2026, 10, 19, 1, 41, 40, tzinfo=timezone.utc)