from logscope.models import Event, Alert, EVENT_SSH_LOGIN_FAILED
from collections import defaultdict
from datetime import timedelta


def detect_brute_force(events: list[Event], threshold: int = 5, window_seconds: int = 60) -> list[Alert]:
    by_ip = defaultdict(list)
    alerts = []
    window = timedelta(seconds=window_seconds)

    for e in events:
        if e.event_type == EVENT_SSH_LOGIN_FAILED and e.src_ip is not None:
            by_ip[e.src_ip].append(e)

    for ip, ip_events in by_ip.items():
        ip_events.sort(key=lambda e: e.timestamp)

        for i in range(len(ip_events)):
            cnt = 0
            for e in ip_events[i:]:
                if e.timestamp - ip_events[i].timestamp < window:
                    cnt += 1
                else:
                    break

            if cnt >= threshold:
                alerts.append(Alert(
                    rule='ssh_brute_force',
                    src_ip=ip,
                    count=cnt,
                    first_seen=ip_events[i].timestamp,
                    last_seen=ip_events[i + cnt - 1].timestamp
                ))
                break
    
    return alerts