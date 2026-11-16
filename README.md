# LogScope Mini-SIEM

A Python CLI tool for log analysis. Supports two log sources: Sysmon JSONL and SSH auth.log. Detects suspicious activity using YAML-based rules, saves events and alerts in SQLite.

## Features

- SSH authentication log parsing
- Sysmon network connection parsing (Event ID 3)
- YAML-based detection rules
- SQLite event and alert storage
- Optional IP enrichment via AbuseIPDB
- JSON alert output

## Data Flow

1. Load and validate YAML rules
2. Parse the input log into `Event` objects
3. Store events in SQLite
4. Apply each rule to the parsed events
5. Optionally enrich alert IP addresses via AbuseIPDB
6. Store alerts in SQLite and print them as JSON

## Project Structure

- `src/logscope/parsers` - auth_log and sysmon parsers
- `src/logscope/rules` - threshold-based detection and YAML rule loading
- `src/logscope/models.py` - dataclasses (Event, Alert, Rule, EnrichedAlert)
- `src/logscope/storage.py` - SQLite event and alert storage
- `src/logscope/enrichment.py` - IP enrichment via ioc-enricher
- `src/logscope/__main__.py` - CLI entry point and processing pipeline
- `tests/` - tests and sample logs

## Installation

Requires Python 3.10+ and Git (for ioc-enricher dependency). Commands below are for macOS/Linux

```bash
git clone https://github.com/dmitrymaslov00/logscope.git
cd logscope
python3 -m venv .env
source .env/bin/activate
python3 -m pip install -e ".[dev]"
```

## Usage

### Detection rule

Create a rules directory and save the following rule as `rules/ssh_brute_force.yml`:

```yaml
id: ssh_brute_force
event_type: ssh_login_failed
threshold: 3
window_seconds: 60
```

### SSH authentication logs

```bash
python3 -m logscope \
  --log tests/data/auth_sample.log \
  --rules rules/ \
  --db logscope.db \
  --year 2026
```

The database is created automatically. Alerts are printed as JSON

### Optional IP enrichment

```bash
export ABUSEIPDB_API_KEY="your_api_key"
```

Add `--enrich` to the command above to enrich alert IP addresses via AbuseIPDB. This requires an API key and an internet connection

### Sysmon JSONL

Only flattened Sysmon JSONL events with Event ID 3 are supported. Each line must contain one JSON object. Create a separate `rules/sysmon_network_burst.yml` file using the rule above, with these values:

- `id: sysmon_network_burst`
- `event_type: sysmon_network_connection`
- `threshold: 2`
- `window_seconds: 10800`

```bash
python3 -m logscope \
  --log tests/data/sysmon_sample.jsonl \
  --rules rules/ \
  --db logscope.db \
  --source sysmon
```

Sysmon events include the year in their timestamps, so `--year` is not required.

## Tests

```bash
python3 -m pytest
```

Tests cover log parsing, YAML rule validation, threshold-based detection, SQLite storage, enrichment, and CLI workflows.

## Limitations and Design Decisions

### Limitations

- Only SSH auth.log and flattened Sysmon JSONL with Event ID 3 are supported
- Detection is limited to counting events of one type per source IP within a time window
- The entire input file is parsed into memory, real-time processing is not supported
- Repeated runs can create duplicate alerts

### Design Decisions

- A shared `Event` dataclass allows different sources to use the same detector and storage
- YAML rules allow detection parameters to be changed without editing Python code
- SQLite requires no separate database server
- Enrichment is optional, and the API key is read from an environment variable