import argparse
from logscope.rules.loader import load_rules, RuleError
from logscope.parsers.auth_log import parse_file
from logscope.storage import init_db, insert_event, insert_enriched_alert
from logscope.rules.brute_force import detect_brute_force
from logscope.enrichment import enrich_alert
from logscope.models import EnrichedAlert
from pathlib import Path
import sys
import sqlite3
import json
import os



def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='logscope mini-siem: parse logs, detect threats and enrich alerts')
    parser.add_argument('-l', '--log', help = 'path to the log file', required=True, type=Path)
    parser.add_argument('-r', '--rules', help = 'path to the rules directory', required=True, type=Path)
    parser.add_argument('-d', '--db', help = 'path to the SQLite database', required=True, type=Path)
    parser.add_argument('-y', '--year', help = 'year of log events', required=True, type=int)
    parser.add_argument('-e', '--enrich', help = 'enrich alert IP addresses via AbuseIPDB', action='store_true')
    args = parser.parse_args(argv)

    api_key = None

    if args.enrich:
        api_key = os.environ.get('ABUSEIPDB_API_KEY')
        if not api_key:
            print('ABUSEIPDB_API_KEY is not set', file=sys.stderr)
            return 1


    try:
        rules = load_rules(args.rules)
    except RuleError as e:
        print(f'RuleError when loading rules from {args.rules}: {e}', file=sys.stderr)
        return 1

    if len(rules) == 0:
        print(f'Error: Imported 0 rules from {args.rules}', file=sys.stderr)
        return 1

    try:
        parsed_events = list(parse_file(args.log, year=args.year))
    except OSError as e:
        print(f'Error when loading file {args.log}: {e}', file=sys.stderr)
        return 1
    
    try:
        init_db(args.db)
        for e in parsed_events:
            insert_event(args.db, e)
    except sqlite3.Error as e:
        print(f'SQLite error: {e}', file=sys.stderr)
        return 1

    alerts = []
    for r in rules:
        alerts.extend(detect_brute_force(parsed_events, r))

    out = []
    for a in alerts:
        if args.enrich:
            enriched_alert = enrich_alert(a, api_key)
        else:
            enriched_alert = EnrichedAlert(
                alert=a,
                abuseipdb={}
            )

        out.append({
            "rule": a.rule,
            "src_ip": a.src_ip,
            "count": a.count,
            "first_seen": a.first_seen.isoformat(),
            "last_seen": a.last_seen.isoformat(),
            "abuseipdb": enriched_alert.abuseipdb
        })

        try:
            insert_enriched_alert(args.db, enriched_alert)
        except sqlite3.Error as e:
            print(f'SQLite3 error when inserting enriched alert: {e}', file=sys.stderr)
            return 1


    print(json.dumps(out), file=sys.stdout)

 
    return 0

    
if __name__ == '__main__':
    sys.exit(main())