from logscope.__main__ import main
from datetime import datetime, timezone
from logscope.storage import query_events
import json



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