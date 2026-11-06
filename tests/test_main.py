from logscope.__main__ import main
from datetime import datetime, timezone
from logscope.storage import query_events
import json
import sqlite3
from contextlib import closing
import responses
import pytest



def test_main_accepts_valid_rules(tmp_path, capsys):
    rules_dir = tmp_path / 'rules'
    rules_dir.mkdir()

    (rules_dir / 'rule.yml').write_text(
        """
        id: ssh_brute_force
        event_type: ssh_login_failed
        threshold: 5
        window_seconds: 60
        title: SSH brute force
        description: Many failed logins from one IP
        """, encoding='utf-8'
    )

    log_file = tmp_path / 'auth.log'
    log_file.write_text('Oct 10 00:04:11 web01 sshd[18322]: Disconnected from authenticating user root 203.0.113.77 port 52814 [preauth]\nOct 10 08:15:44 web01 sshd[19040]: Accepted publickey for deploy from 192.0.2.10 port 51234 ssh2: ED25519 SHA256:Xk3mQ9vT2pLwR7nYdA1bHcEu8sFjZoGqV4tNiMxB0Uc', encoding='utf-8')

    db = tmp_path / 'test.db'

    result = main([
        "--log", str(log_file),
        "--rules", str(rules_dir),
        "--db", str(db),
        "--year", "2026",
    ])

    captured = capsys.readouterr()

    assert result == 0
    assert captured.err == ''
    assert json.loads(captured.out) == []

    start = datetime(2026, 10, 10, 0, 4, 0, tzinfo=timezone.utc)
    end = datetime(2026, 10, 10, 8, 16, 0, tzinfo=timezone.utc)
    events = query_events(db, start, end)

    assert len(events) == 2
    assert events[0].host == 'web01'
    assert events[1].event_type == 'ssh_login_success'


def test_main_rejects_invalid_rule(tmp_path, capsys):
    rules_dir = tmp_path / 'rules'
    rules_dir.mkdir()
    (rules_dir / 'rule.yml').write_text(
        """
        id: ssh_brute_force
        event_type: ssh_login_failed
        threshold: 0
        window_seconds: 60
        title: SSH brute force
        description: Many failed logins from one IP
        """, encoding='utf-8'
    )

    result = main([
        "--log", str(tmp_path / "auth.log"),
        "--rules", str(rules_dir),
        "--db", str(tmp_path / "test.db"),
        "--year", "2026",
    ])

    captured = capsys.readouterr()

    assert result == 1
    assert 'threshold' in captured.err
    assert captured.out == ''


def test_main_rejects_missing_log(tmp_path, capsys):
    rules_dir = tmp_path / 'rules'
    rules_dir.mkdir()
    (rules_dir / 'rule.yml').write_text(
        """
        id: ssh_brute_force
        event_type: ssh_login_failed
        threshold: 5
        window_seconds: 60
        title: SSH brute force
        description: Many failed logins from one IP
        """, encoding='utf-8'
    )

    result = main([
        "--log", str(tmp_path / "none.log"),
        "--rules", str(rules_dir),
        "--db", str(tmp_path / "test.db"),
        "--year", "2026",
    ])

    captured = capsys.readouterr()

    assert result == 1
    assert captured.out == ''
    assert 'Error when loading file' in captured.err
    assert not (tmp_path / 'test.db').exists()


def test_main_outputs_detected_alert(tmp_path, capsys):
    rules_dir = tmp_path / 'rules'
    rules_dir.mkdir()

    (rules_dir / 'rule.yml').write_text(
        """
        id: ssh_brute_force
        event_type: ssh_login_failed
        threshold: 3
        window_seconds: 10
        title: SSH brute force
        description: Many failed logins from one IP
        """, encoding='utf-8'
    )

    log_file = tmp_path / 'auth.log'
    log_file.write_text(
        'Oct 10 00:04:00 web01 sshd[18322]: Failed password for root from 203.0.113.77 port 52814 ssh2\n' +
        'Oct 10 00:04:04 web01 sshd[18322]: Failed password for root from 203.0.113.77 port 52814 ssh2\n' +
        'Oct 10 00:04:09 web01 sshd[18322]: Failed password for root from 203.0.113.77 port 52814 ssh2',
    encoding='utf-8')

    db = tmp_path / 'test.db'

    result = main([
        "--log", str(log_file),
        "--rules", str(rules_dir),
        "--db", str(db),
        "--year", "2026",
    ])

    captured = capsys.readouterr()


    assert result == 0
    assert captured.err == ''

    json_out = json.loads(captured.out)
    assert len(json_out) == 1
    alert = json_out[0]
    assert alert["rule"] == 'ssh_brute_force'
    assert alert["src_ip"] == '203.0.113.77'
    assert alert["count"] == 3
    assert alert["first_seen"] == '2026-10-10T00:04:00+00:00'
    assert alert["last_seen"] == '2026-10-10T00:04:09+00:00'
    assert alert["abuseipdb"] == {}

    with closing(sqlite3.connect(db)) as conn:
        with conn:
            cursor = conn.execute("""
                SELECT rule, src_ip, count, first_seen, last_seen, abuseipdb
                from alerts
            """)

            rows = cursor.fetchall()

    assert len(rows) == 1
    row = rows[0]

    assert row[0] == 'ssh_brute_force'
    assert row[1] == '203.0.113.77'
    assert row[2] == 3
    assert row[3] == '2026-10-10T00:04:00+00:00'
    assert row[4] == '2026-10-10T00:04:09+00:00'
    assert json.loads(row[5]) == {}


@pytest.fixture
def fake_key(monkeypatch):
    monkeypatch.setenv('ABUSEIPDB_API_KEY', 'fake-key')


API_OK = {"data": {"abuseConfidenceScore": 50, "totalReports": 222,
                   "countryCode": "DE", "isp": "Deutsche Telekom"}}


@responses.activate
def test_main_enriches_and_stores_alert(tmp_path, capsys, fake_key):
    rules_dir = tmp_path / 'rules'
    rules_dir.mkdir()

    (rules_dir / 'rule.yml').write_text(
        """
        id: ssh_brute_force
        event_type: ssh_login_failed
        threshold: 3
        window_seconds: 10
        title: SSH brute force
        description: Many failed logins from one IP
        """, encoding='utf-8'
    )

    log_file = tmp_path / 'auth.log'
    log_file.write_text(
        'Oct 10 00:04:00 web01 sshd[18322]: Failed password for root from 203.0.113.77 port 52814 ssh2\n' +
        'Oct 10 00:04:04 web01 sshd[18322]: Failed password for root from 203.0.113.77 port 52814 ssh2\n' +
        'Oct 10 00:04:09 web01 sshd[18322]: Failed password for root from 203.0.113.77 port 52814 ssh2',
    encoding='utf-8')

    db = tmp_path / 'test.db'

    responses.add(
        responses.GET,
        'https://api.abuseipdb.com/api/v2/check',
        json=API_OK, 
        status=200
    )
    
    result = main([
        "--log", str(log_file),
        "--rules", str(rules_dir),
        "--db", str(db),
        "--year", "2026",
        "--enrich"
    ])

    captured = capsys.readouterr()


    assert result == 0
    assert captured.err == ''
    assert len(responses.calls) == 1

    json_out = json.loads(captured.out)
    assert len(json_out) == 1
    alert = json_out[0]
    assert alert["rule"] == 'ssh_brute_force'
    assert alert["src_ip"] == '203.0.113.77'
    assert alert["count"] == 3
    assert alert["first_seen"] == '2026-10-10T00:04:00+00:00'
    assert alert["last_seen"] == '2026-10-10T00:04:09+00:00'
    assert alert["abuseipdb"] == {
        "score": 50,
        "reports": 222,
        "country": "DE",
        "isp": "Deutsche Telekom",
    }

    with closing(sqlite3.connect(db)) as conn:
        with conn:
            cursor = conn.execute("""
                SELECT rule, src_ip, count, first_seen, last_seen, abuseipdb
                from alerts
            """)

            rows = cursor.fetchall()

    assert len(rows) == 1
    row = rows[0]

    assert row[0] == 'ssh_brute_force'
    assert row[1] == '203.0.113.77'
    assert row[2] == 3
    assert row[3] == '2026-10-10T00:04:00+00:00'
    assert row[4] == '2026-10-10T00:04:09+00:00'
    assert json.loads(row[5]) == {
        "score": 50,
        "reports": 222,
        "country": "DE",
        "isp": "Deutsche Telekom",
    }


@responses.activate
def test_main_preserves_enrichment_error(tmp_path, capsys, fake_key):
    rules_dir = tmp_path / 'rules'
    rules_dir.mkdir()

    (rules_dir / 'rule.yml').write_text(
        """
        id: ssh_brute_force
        event_type: ssh_login_failed
        threshold: 3
        window_seconds: 10
        title: SSH brute force
        description: Many failed logins from one IP
        """, encoding='utf-8'
    )

    log_file = tmp_path / 'auth.log'
    log_file.write_text(
        'Oct 10 00:04:00 web01 sshd[18322]: Failed password for root from 203.0.113.77 port 52814 ssh2\n' +
        'Oct 10 00:04:04 web01 sshd[18322]: Failed password for root from 203.0.113.77 port 52814 ssh2\n' +
        'Oct 10 00:04:09 web01 sshd[18322]: Failed password for root from 203.0.113.77 port 52814 ssh2',
    encoding='utf-8')

    db = tmp_path / 'test.db'

    responses.add(
        responses.GET,
        'https://api.abuseipdb.com/api/v2/check',
        status=429
    )
    
    result = main([
        "--log", str(log_file),
        "--rules", str(rules_dir),
        "--db", str(db),
        "--year", "2026",
        "--enrich"
    ])

    captured = capsys.readouterr()


    assert result == 0
    assert captured.err == ''
    assert len(responses.calls) == 1

    json_out = json.loads(captured.out)
    assert len(json_out) == 1
    alert = json_out[0]
    assert alert["rule"] == 'ssh_brute_force'
    assert alert["src_ip"] == '203.0.113.77'
    assert alert["count"] == 3
    assert alert["first_seen"] == '2026-10-10T00:04:00+00:00'
    assert alert["last_seen"] == '2026-10-10T00:04:09+00:00'
    assert alert["abuseipdb"] == {"error": "Too many requests"}

    with closing(sqlite3.connect(db)) as conn:
        with conn:
            cursor = conn.execute("""
                SELECT rule, src_ip, count, first_seen, last_seen, abuseipdb
                from alerts
            """)

            rows = cursor.fetchall()

    assert len(rows) == 1
    row = rows[0]

    assert row[0] == 'ssh_brute_force'
    assert row[1] == '203.0.113.77'
    assert row[2] == 3
    assert row[3] == '2026-10-10T00:04:00+00:00'
    assert row[4] == '2026-10-10T00:04:09+00:00'
    assert json.loads(row[5]) == {"error": "Too many requests"}


def test_main_rejects_enrichment_without_api_key(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv('ABUSEIPDB_API_KEY', raising=False)
    
    result = main([
        "--log", 'auth.log',
        "--rules", 'rules_dir',
        "--db", str(tmp_path / 'test.db'),
        "--year", '2026',
        "--enrich"
    ])

    captured = capsys.readouterr()


    assert result == 1
    assert 'ABUSEIPDB_API_KEY' in captured.err
    assert captured.out == ''
    assert not (tmp_path / 'test.db').exists()