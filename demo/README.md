# Demo

Use a new database path for each demo run to avoid duplicate alerts. Run all commands from the repository root after completing the installation steps.

## SSH

```bash
python3 -m logscope \
  --log tests/data/auth_sample.log \
  --rules demo/rules/ \
  --db demo/ssh.db \
  --year 2026
```

Expected results:

- 23 events stored in SQLite
- 2 alerts for rule `ssh_brute_force`
- Source IPs: `198.51.100.23` and `203.0.113.77`
- Each alert has `count: 3` and `abuseipdb: {}`

## Sysmon

```bash
python3 -m logscope \
  --log tests/data/sysmon_sample.jsonl \
  --rules demo/rules/ \
  --db demo/sysmon.db \
  --source sysmon
```

Expected results:

- 2 events stored in SQLite
- 1 alert for rule `sysmon_network_burst`
- Source IP: `192.0.2.10`
- Alert has `count: 2` and `abuseipdb: {}`

## Database Verification

```bash
sqlite3 -header -column demo/ssh.db \
  "SELECT source, event_type, COUNT(*) AS total FROM events GROUP BY source, event_type;"

sqlite3 -header -column demo/ssh.db \
  "SELECT rule, src_ip, count, first_seen, last_seen, abuseipdb FROM alerts;"
```

For Sysmon, run the same queries against `demo/sysmon.db`. Database verification requires the sqlite3 CLI.

## Tests

```bash
python3 -m pytest
```

102 passed