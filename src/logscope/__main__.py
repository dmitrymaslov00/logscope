import argparse
from logscope.rules.loader import load_rules, RuleError
from pathlib import Path
import sys



def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='logscope mini-siem: parse logs, detect threats and enrich alerts')
    parser.add_argument('-l', '--log', help = 'path to the log file', required=True, type=Path)
    parser.add_argument('-r', '--rules', help = 'path to the rules directory', required=True, type=Path)
    parser.add_argument('-d', '--db', help = 'path to the SQLite database', required=True, type=Path)
    parser.add_argument('-y', '--year', help = 'year of log events', required=True, type=int)
    args = parser.parse_args(argv)

    try:
        rules = load_rules(args.rules)
    except RuleError as e:
        print(f'RuleError when loading rules from {args.rules}: {e}', file=sys.stderr)
        return 1

    if len(rules) == 0:
        print(f'Error: Imported 0 rules from {args.rules}', file=sys.stderr)
        return 1
    
    return 0

    
if __name__ == '__main__':
    sys.exit(main())