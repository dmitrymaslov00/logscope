import pytest
from datetime import datetime, timezone
from logscope.models import Event, Alert


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
            "src_ip": "192.168.0.1",
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
            "src_ip": "192.168.0.1",
            "count": 5,
            "first_seen": datetime(2026, 10, 19, 1, 41, 0, tzinfo=timezone.utc),
            "last_seen": datetime(2026, 10, 19, 1, 41, 55, tzinfo=timezone.utc),
        }

        defaults.update(overrides)
        return Alert(**defaults)
    
    return _make

