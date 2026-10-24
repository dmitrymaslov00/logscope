import pytest
from datetime import datetime, timezone
from logscope.parsers.auth_log import parse_line, parse_file
from logscope.models import EVENT_OTHER, EVENT_SSH_INVALID_USER, EVENT_SSH_LOGIN_FAILED, EVENT_SSH_LOGIN_SUCCESS
import inspect


def test_extracts_header():
    event = parse_line('Oct 19 01:41:02 srv sshd[1]: Accepted password', 2026)

    assert event.host == 'srv'
    assert event.timestamp == datetime(2026, 10, 19, 1, 41, 2, tzinfo=timezone.utc)


def test_single_digit_day():
    event = parse_line('Oct  1 01:41:02 srv sshd[1]: test', 2026)

    assert event.timestamp.day == 1


def test_year_param():
    event1 = parse_line('Oct 19 01:41:02 srv sshd[1]: test', 2025)
    event2 = parse_line('Oct 19 01:41:02 srv sshd[1]: test', 2026)

    assert event1.timestamp.year == 2025
    assert event2.timestamp.year == 2026


def test_timestamp_is_utc():
    event = parse_line('Oct 19 01:41:02 srv sshd[1]: test', 2026)

    assert event.timestamp.tzinfo is timezone.utc


def test_garbage_returns_none():
    event = parse_line('hello', 2026)

    assert event is None


def test_strips_newline():
    event = parse_line('Oct 19 01:41:02 srv sshd[1]: test\n', 2026)

    assert event.raw == 'Oct 19 01:41:02 srv sshd[1]: test'


def test_failed_password():
    event = parse_line('Oct 19 01:41:02 srv sshd[1]: Failed password for admin from 203.0.113.5 port 22 ssh2', 2026)

    assert event.event_type == EVENT_SSH_LOGIN_FAILED
    assert event.user == 'admin'
    assert event.src_ip == '203.0.113.5'
    assert event.src_port == 22


def test_failed_password_invalid_user():
    event = parse_line('Oct 19 01:41:02 srv sshd[1]: Failed password for invalid user qwe from 203.0.113.5 port 22 ssh2', 2026)

    assert event.event_type == EVENT_SSH_LOGIN_FAILED
    assert event.user == 'qwe'
    assert event.src_ip == '203.0.113.5'
    assert event.src_port == 22


def test_invalid_user_standalone():
    event = parse_line('Oct 19 01:41:02 srv sshd[1]: Invalid user jjj from 203.0.113.5 port 22', 2026)

    assert event.event_type == EVENT_SSH_INVALID_USER
    assert event.user == 'jjj'
    assert event.src_ip == '203.0.113.5'
    assert event.src_port == 22


def test_accepted_password():
    event = parse_line('Oct 19 01:41:02 srv sshd[1]: Accepted password for root from 203.0.113.5 port 22 ssh2', 2026)

    assert event.event_type == EVENT_SSH_LOGIN_SUCCESS
    assert event.user == 'root'
    assert event.src_ip == '203.0.113.5'
    assert event.src_port == 22


def test_accepted_publickey():
    event = parse_line('Oct 19 01:41:02 srv sshd[1]: Accepted publickey for root from 203.0.113.5 port 22 ssh2: ED25519 SHA256:abc', 2026)

    assert event.event_type == EVENT_SSH_LOGIN_SUCCESS
    assert event.user == 'root'
    assert event.src_ip == '203.0.113.5'
    assert event.src_port == 22


def test_unknown_rest_is_other():
    event = parse_line('Oct 19 01:41:02 srv sshd[1]: hello', 2026)

    assert event.event_type == EVENT_OTHER
    assert event.user is None
    assert event.src_ip is None
    assert event.src_port is None


def test_valid_ipv4():
    event = parse_line('Oct 19 01:41:02 srv sshd[1]: Accepted publickey for root from 203.0.113.5 port 22 ssh2: ED25519 SHA256:abc', 2026)

    assert event.src_ip == '203.0.113.5'


def test_valid_ipv6():
    event = parse_line('Oct 19 01:41:02 srv sshd[1]: Accepted publickey for root from 2001:db8::1 port 22 ssh2: ED25519 SHA256:abc', 2026)

    assert event.src_ip == '2001:db8::1'


def test_invalid_ip_returns_none():
    event = parse_line('Oct 19 01:41:02 srv sshd[1]: Failed password for admin from 999.999.999.999 port 22 ssh2', 2026)

    assert event.src_ip is None
    assert event.user == 'admin'
    assert event.event_type == EVENT_SSH_LOGIN_FAILED


def test_parse_file_yields_events(tmp_path):
    p = tmp_path / 'auth.log'
    p.write_text('Oct 19 01:41:02 srv sshd[1]: Accepted publickey for root from 203.0.113.5 port 22 ssh2: ED25519 SHA256:abc\nOct 19 01:41:02 srv sshd[1]: Failed password for admin from 999.999.999.999 port 22 ssh2\nOct 19 01:41:02 srv sshd[1]: hello', encoding='utf-8')

    res = list(parse_file(p, 2026))

    assert len(res) == 3
    assert res[0].event_type == EVENT_SSH_LOGIN_SUCCESS
    assert res[0].user == 'root'


def test_parse_file_skips_garbage(tmp_path):
    p = tmp_path / 'auth.log'
    p.write_text('Oct 19 01:41:02 srv sshd[1]: Accepted publickey for root from 203.0.113.5 port 22 ssh2: ED25519 SHA256:abc\nnot a log 1234553\nOct 19 01:41:02 srv sshd[1]: Failed password for admin from 999.999.999.999 port 22 ssh2', encoding='utf-8')

    res = list(parse_file(p, 2026))

    assert len(res) == 2


def test_parse_file_default_year_from_mtime(tmp_path):
    p = tmp_path / 'auth.log'
    p.write_text('Oct 19 01:41:02 srv sshd[1]: Accepted publickey for root from 203.0.113.5 port 22 ssh2: ED25519 SHA256:abc', encoding='utf-8')

    expected_year = datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc).year
    event = next(parse_file(p))

    assert event.timestamp.year == expected_year


def test_parse_file_is_generator(tmp_path):
    p = tmp_path / 'auth.log'
    p.write_text('Oct 19 01:41:02 srv sshd[1]: Accepted publickey for root from 203.0.113.5 port 22 ssh2: ED25519 SHA256:abc', encoding='utf-8')

    res = parse_file(p, 2026)

    assert inspect.isgenerator(res)