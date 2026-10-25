import pytest
from datetime import datetime, timezone
from dataclasses import FrozenInstanceError
from logscope.models import Event, Alert


def test_event_stores_all_fields(make_event):
    event = make_event()

    assert event.timestamp == datetime(2026, 10, 19, 1, 41, 2, tzinfo=timezone.utc)
    assert event.host == 'srv'
    assert event.source == 'auth.log'
    assert event.event_type == 'ssh_login_failed'
    assert event.raw == 'raw'
    assert event.user == 'root'
    assert event.src_ip == '192.168.0.1'
    assert event.src_port == 22


def test_optional_fields_default_to_none():
    event = Event(
        timestamp = datetime(2026, 10, 19, 1, 41, 2, tzinfo=timezone.utc),
        host = 'srv',
        source = 'auth.log',
        event_type = 'ssh_login_failed',
        raw = 'raw',
    )

    assert event.user is None
    assert event.src_ip is None
    assert event.src_port is None


def test_event_is_immutable(make_event):
    event = make_event()

    with pytest.raises(FrozenInstanceError):
        event.host = 'x'


def test_events_with_same_data_are_equal(make_event):
    event1 = make_event()
    event2 = make_event()
    event3 = make_event(host = 'qwe')

    assert event1 == event2
    assert event1 != event3


def test_alert_stores_all_fields(make_alert):
    alert = make_alert()

    assert alert.rule == 'ssh_brute_force'
    assert alert.src_ip == '192.168.0.1'
    assert alert.count == 5
    assert alert.first_seen == datetime(2026, 10, 19, 1, 41, 0, tzinfo=timezone.utc)
    assert alert.last_seen == datetime(2026, 10, 19, 1, 41, 55, tzinfo=timezone.utc)


def test_alert_is_immutable(make_alert):
    alert = make_alert()

    with pytest.raises(FrozenInstanceError):
        alert.count = 3