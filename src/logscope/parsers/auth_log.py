from logscope.models import Event, EVENT_OTHER, EVENT_SSH_INVALID_USER, EVENT_SSH_LOGIN_FAILED, EVENT_SSH_LOGIN_SUCCESS
from datetime import datetime, timezone
import re
import ipaddress
from pathlib import Path
from collections.abc import Iterator


HEADER_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<rest>.*)$"
)

PATTERN_FAILED_INVALID = re.compile(r"^sshd\[\d+\]: Failed password for invalid user (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+) ssh2$")
PATTERN_FAILED = re.compile(r"^sshd\[\d+\]: Failed password for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+) ssh2$")
PATTERN_INVALID_STANDALONE = re.compile(r"^sshd\[\d+\]: Invalid user (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
PATTERN_ACCEPTED_PASSWORD = re.compile(r"^sshd\[\d+\]: Accepted (?:password|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+) ssh2$")
PATTERN_ACCEPTED_PUBLICKEY = re.compile(r"^sshd\[\d+\]: Accepted publickey for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+) ssh2:")


MONTHS: dict[str, int] = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


def parse_line(line: str, year: int) -> Event | None:
    m = HEADER_RE.match(line)

    if m is None:
        return None

    month_num = MONTHS.get(m.group('month'))

    if month_num is None:
        return None

    hours, minutes, seconds = map(int, m.group('time').split(':'))

    day = int(m.group('day'))

    try:
        date = datetime(year, month_num, day, hours, minutes, seconds, tzinfo=timezone.utc)
    except ValueError:
        return None

    rest = m.group('rest')

    m_invalid = PATTERN_FAILED_INVALID.match(rest)
    m_failed = PATTERN_FAILED.match(rest)
    m_standalone = PATTERN_INVALID_STANDALONE.match(rest)
    m_accepted_password = PATTERN_ACCEPTED_PASSWORD.match(rest)
    m_accepted_publickey = PATTERN_ACCEPTED_PUBLICKEY.match(rest)


    if m_invalid:
        user = m_invalid.group('user')
        src_ip = validate_ip(m_invalid.group('ip'))
        src_port = int(m_invalid.group('port'))
        event_type = EVENT_SSH_LOGIN_FAILED

    elif m_failed:
        user = m_failed.group('user')
        src_ip = validate_ip(m_failed.group('ip'))
        src_port = int(m_failed.group('port'))
        event_type = EVENT_SSH_LOGIN_FAILED

    elif m_standalone:
        user = m_standalone.group('user')
        src_ip = validate_ip(m_standalone.group('ip'))
        src_port = int(m_standalone.group('port'))
        event_type = EVENT_SSH_INVALID_USER

    elif m_accepted_password:
        user = m_accepted_password.group('user')
        src_ip = validate_ip(m_accepted_password.group('ip'))
        src_port = int(m_accepted_password.group('port'))
        event_type = EVENT_SSH_LOGIN_SUCCESS

    elif m_accepted_publickey:
            user = m_accepted_publickey.group('user')
            src_ip = validate_ip(m_accepted_publickey.group('ip'))
            src_port = int(m_accepted_publickey.group('port'))
            event_type = EVENT_SSH_LOGIN_SUCCESS

    else:
        user = None
        src_ip = None
        src_port = None
        event_type = EVENT_OTHER


    return Event(
        timestamp = date,
        host = m.group('host'),
        source = 'auth.log',
        event_type = event_type,
        raw = line.rstrip('\r\n'),
        user = user,
        src_ip = src_ip,
        src_port = src_port
    )


def parse_file(path: str | Path, year: int | None = None) -> Iterator[Event]:
    if year is None:
        mtime = Path(path).stat().st_mtime
        year = datetime.fromtimestamp(mtime, tz=timezone.utc).year

    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            res = parse_line(line, year)
            if res is None:
                continue
            else:
                yield res
                


def validate_ip(ip: str) -> str | None:
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        return None

