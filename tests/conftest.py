import pytest
from datetime import datetime, timezone
from logscope.models import Event, Alert, Rule


@pytest.fixture
def make_event():
    def _make(**overrides):

        defaults = {
            "timestamp": datetime(2026, 10, 19, 1, 41, 2, tzinfo=timezone.utc),
            "host": "srv",
            "source": "auth.log",
            "event_type": "ssh_login_failed",
            "raw": "raw",
            "user": "root",
            "src_ip": "203.0.113.5",
            "src_port": 51122
        }

        defaults.update(overrides)
        return Event(**defaults)
    
    return _make


@pytest.fixture
def make_alert():
    def _make(**overrides):
        
        defaults = {
            "rule": "ssh_brute_force",
            "src_ip": "203.0.113.5",
            "count": 5,
            "first_seen": datetime(2026, 10, 19, 1, 41, 0, tzinfo=timezone.utc),
            "last_seen": datetime(2026, 10, 19, 1, 41, 55, tzinfo=timezone.utc),
        }

        defaults.update(overrides)
        return Alert(**defaults)
    
    return _make


@pytest.fixture
def make_rule():
    def _make(**overrides):
        
        defaults = {
            "id": "ssh_brute_force",
            "event_type": "ssh_login_failed",
            "threshold": 5,
            "window_seconds": 60,
            "title": "SSH brute force",
            "description": "Multiple failed SSH logins from one IP within a short window"
        }

        defaults.update(overrides)
        return Rule(**defaults)
    
    return _make