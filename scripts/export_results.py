"""Export vote results to CSV or JSON from the database.

Usage examples:
  python scripts/export_results.py --format csv --out results.csv
  python scripts/export_results.py --format json --out results.json

Defaults: reads `database.db` in repo root and writes timestamped file if --out omitted.
"""
import argparse
import csv
import json
from datetime import datetime
import sqlite3


def read_counts(db_path):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute('SELECT c.id, c.name, COUNT(v.id) as votes FROM candidates c LEFT JOIN votes v ON v.candidate_id = c.id GROUP BY c.id ORDER BY votes DESC')
    rows = cur.fetchall()
    conn.close()
    return [{'id': r[0], 'name': r[1], 'count': r[2]} for r in rows]


def write_csv(rows, out_path):
    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['id', 'name', 'count'])
        for r in rows:
            w.writerow([r['id'], r['name'], r['count']])


def write_json(rows, out_path):
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(rows, f, indent=2)


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument('--db', default='database.db')
    p.add_argument('--format', choices=['csv', 'json'], default='csv')
    p.add_argument('--out', help='Output file path (optional)')
    args = p.parse_args(argv)

    rows = read_counts(args.db)
    ts = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    out = args.out
    if not out:
        out = f'results_{ts}.{args.format}'

    if args.format == 'csv':
        write_csv(rows, out)
    else:
        write_json(rows, out)

    print(f'Wrote {len(rows)} rows to {out}')


if __name__ == '__main__':
    main()
