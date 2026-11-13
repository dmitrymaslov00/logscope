from logscope.models import Event
import json
import ipaddress
from datetime import datetime, timezone
from pathlib import Path
from collections.abc import Iterator



def parse_line(line: str) -> Event | None:
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None

    if not isinstance(data, dict):
        return None

    if data.get("EventID") != 3:
        return None

    host = data.get("Computer")

    if not isinstance(host, str):
        return None

    if host.strip() == '':
        return None

    user = data.get("User")

    if user is not None and not isinstance(user, str):
        return None

    src_ip = data.get("SourceIp")

    if not isinstance(src_ip, str):
        return None

    try:
        src_ip = str(ipaddress.ip_address(src_ip))
    except ValueError:
        return None

    src_port = data.get("SourcePort")

    if isinstance(src_port, bool) or not isinstance(src_port, int):
        return None

    if src_port not in range(0, 65536):
        return None

    dt = data.get("UtcTime")

    if not isinstance(dt, str):
        return None

    if dt.endswith('Z'):
        dt = dt[:-1] + '+00:00'

    try:
        dt = datetime.fromisoformat(dt)
    except ValueError:
        return None

    if dt.tzinfo is None:
        return None

    timestamp = dt.astimezone(timezone.utc)


    return Event(
        timestamp=timestamp,
        host=host,
        source='sysmon',
        event_type='sysmon_network_connection',
        raw=line.rstrip('\r\n'),
        user=user,
        src_ip=src_ip,
        src_port=src_port
    )


def parse_file(path: str | Path) -> Iterator[Event]:
    with open(path, encoding='utf-8') as f:
        for line in f:
            event = parse_line(line)
            if event is not None:
                yield event