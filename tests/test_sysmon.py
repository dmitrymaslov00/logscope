from logscope.parsers.sysmon import parse_line, parse_file
import json
from datetime import datetime, timezone
from pathlib import Path



def test_parse_line_creates_network_event():
    data = json.dumps({"EventID": 3, "UtcTime": "2026-11-13T10:00:00Z", "Computer": "win01", "User": "LAB\\alice", "SourceIp": "192.0.2.10", "SourcePort": 51000, "DestinationIp": "203.0.113.20", "DestinationPort": 443})

    res = parse_line(data)

    assert res is not None
    assert res.timestamp == datetime(2026, 11, 13, 10, 0, 0, tzinfo=timezone.utc)
    assert res.host == 'win01'
    assert res.source == 'sysmon'
    assert res.event_type == 'sysmon_network_connection'
    assert res.user == 'LAB\\alice'
    assert res.src_ip == '192.0.2.10'
    assert res.src_port == 51000
    assert res.raw == data


def test_parse_line_rejects_invalid_json():
    data = 'not json'

    res = parse_line(data)

    assert res is None


def test_parse_line_rejects_invalid_fields():
    valid_data = {"EventID": 3, "UtcTime": "2026-11-13T10:00:00Z", "Computer": "win01", "User": "LAB\\alice", "SourceIp": "192.0.2.10", "SourcePort": 51000, "DestinationIp": "203.0.113.20", "DestinationPort": 443}

    data = valid_data.copy()
    data["EventID"] = 1
    assert parse_line(json.dumps(data)) is None

    data = valid_data.copy()
    data["Computer"] = ""
    assert parse_line(json.dumps(data)) is None

    data = valid_data.copy()
    data["SourceIp"] = "999.999.999.999"
    assert parse_line(json.dumps(data)) is None

    data = valid_data.copy()
    data["SourcePort"] = 65536
    assert parse_line(json.dumps(data)) is None

    data = valid_data.copy()
    data["UtcTime"] = "2026-11-13T10:00:00"
    assert parse_line(json.dumps(data)) is None


def test_parse_file_reads_sample():
    file = Path(__file__).parent / "data" / "sysmon_sample.jsonl"

    res = list(parse_file(file))

    assert len(res) == 2
    assert res[0].timestamp == datetime(2026, 11, 13, 10, 0, 0, tzinfo=timezone.utc)
    assert res[1].timestamp == datetime(2026, 11, 13, 12, 3, 0, tzinfo=timezone.utc)
    assert res[0].src_port == 51000
    assert res[1].src_port == 51009