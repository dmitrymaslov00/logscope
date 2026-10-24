from dataclasses import dataclass
from datetime import datetime



EVENT_SSH_LOGIN_FAILED = 'ssh_login_failed'
EVENT_SSH_LOGIN_SUCCESS = 'ssh_login_success'
EVENT_SSH_INVALID_USER = 'ssh_invalid_user'
EVENT_OTHER = 'other'



@dataclass(frozen=True, slots=True)
class Event:
    timestamp: datetime
    host: str
    source: str
    event_type: str
    raw: str
    user: str | None = None
    src_ip: str | None = None
    src_port: int | None = None


@dataclass(frozen=True, slots=True)
class Alert:
    rule: str
    src_ip: str
    count: int
    first_seen: datetime
    last_seen: datetime