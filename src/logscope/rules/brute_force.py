from logscope.models import Event, Alert, Rule
from collections import defaultdict
from datetime import timedelta


def detect_brute_force(events: list[Event], rule: Rule) -> list[Alert]:
    by_ip = defaultdict(list)
    alerts = []
    window = timedelta(seconds=rule.window_seconds)

    for e in events:
        if e.event_type == rule.event_type and e.src_ip is not None:
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

            if cnt >= rule.threshold:
                alerts.append(Alert(
                    rule=rule.id,
                    src_ip=ip,
                    count=cnt,
                    first_seen=ip_events[i].timestamp,
                    last_seen=ip_events[i + cnt - 1].timestamp
                ))
                break
    
    return alerts