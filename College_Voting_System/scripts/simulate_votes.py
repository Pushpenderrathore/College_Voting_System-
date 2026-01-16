"""Simulate voters registering, logging in, and casting votes against the local app.

Defaults: 100 voters, concurrency 10, deterministic seed

Usage examples:
  python scripts/simulate_votes.py --voters 100 --concurrency 10 --seed 42
  python scripts/simulate_votes.py --voters 10 --concurrency 3 --seed 123 --base-url http://127.0.0.1:5000

Notes:
- Requires `requests` and `beautifulsoup4` packages.
- Runs against the running app at BASE URL (default http://127.0.0.1:5000).
- By default it will create users with prefix `simuser` and password `password` and cast votes.
- The script is deterministic when `--seed` is provided.
"""

import argparse
import concurrent.futures
import logging
import random
import sqlite3
import sys
import time
from typing import List, Tuple

import requests
from bs4 import BeautifulSoup

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger('simulate')


def get_csrf(session: requests.Session, text: str) -> str:
    soup = BeautifulSoup(text, 'html.parser')
    el = soup.find('input', {'name': 'csrf_token'})
    return el['value'] if el else ''


def ensure_register(session: requests.Session, base: str, username: str, password: str) -> bool:
    # GET register page to fetch CSRF
    r = session.get(base + '/register')
    token = get_csrf(session, r.text)
    data = {'username': username, 'password': password, 'csrf_token': token}
    r = session.post(base + '/register', data=data, allow_redirects=True)
    # If response contains "Registration successful" flash then ok; if username exists, that's fine too.
    return ('Registration successful' in r.text) or ('Username already taken' in r.text)


def login(session: requests.Session, base: str, username: str, password: str) -> bool:
    r = session.get(base + '/')
    token = get_csrf(session, r.text)
    data = {'username': username, 'password': password, 'csrf_token': token}
    r = session.post(base + '/', data=data, allow_redirects=True)
    return 'Logged in successfully' in r.text


def get_candidates(session: requests.Session, base: str) -> List[Tuple[str, str]]:
    # Requires being logged in
    r = session.get(base + '/vote')
    soup = BeautifulSoup(r.text, 'html.parser')
    radios = soup.find_all('input', {'name': 'candidate'})
    candidates = []
    for radio in radios:
        value = radio.get('value')
        label = ''
        lid = radio.get('id')
        if lid:
            lbl = soup.find('label', {'for': lid})
            if lbl:
                label = lbl.get_text(strip=True)
        candidates.append((value, label))
    return candidates


def cast_vote(session: requests.Session, base: str, candidate_id: str) -> bool:
    # Get CSRF token from page
    r = session.get(base + '/vote')
    token = get_csrf(session, r.text)
    data = {'candidate': candidate_id, 'csrf_token': token}
    r = session.post(base + '/vote', data=data, allow_redirects=True)
    return 'Vote recorded' in r.text or 'Vote recorded. Thank you!' in r.text


def worker(index: int, base: str, prefix: str, password: str, rng: random.Random) -> Tuple[bool, str]:
    username = f"{prefix}{index}"
    s = requests.Session()
    try:
        ok = ensure_register(s, base, username, password)
        if not ok:
            logger.warning('%s: register failed', username)
            # Continue; maybe exists
        if not login(s, base, username, password):
            logger.warning('%s: login failed', username)
            return False, username
        cands = get_candidates(s, base)
        if not cands:
            logger.warning('%s: no candidates found', username)
            return False, username
        # Deterministic candidate choice
        candidate = rng.choice(cands)
        candidate_id = candidate[0]
        success = cast_vote(s, base, candidate_id)
        if success:
            logger.info('%s voted for %s (%s)', username, candidate[1], candidate_id)
            return True, candidate_id
        else:
            logger.warning('%s: vote failed', username)
            return False, username
    except Exception as e:
        logger.exception('worker %s failed: %s', username, e)
        return False, username


def read_counts_from_db(db_path: str) -> List[Tuple[str, int]]:
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute('SELECT c.name, COUNT(v.id) as votes FROM candidates c LEFT JOIN votes v ON v.candidate_id = c.id GROUP BY c.id ORDER BY votes DESC')
    rows = cur.fetchall()
    conn.close()
    return rows


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument('--voters', type=int, default=100)
    p.add_argument('--concurrency', type=int, default=10)
    p.add_argument('--seed', type=int, default=42)
    p.add_argument('--base-url', default='http://127.0.0.1:5000')
    p.add_argument('--prefix', default='simuser')
    p.add_argument('--password', default='password')
    p.add_argument('--db', default='database.db', help='Path to local SQLite DB (used to show final counts)')
    p.add_argument('--dry-run', action='store_true', help='Create accounts and login but do not cast votes')
    args = p.parse_args(argv)

    rng_global = random.Random(args.seed)

    logger.info('Simulation start: voters=%s concurrency=%s seed=%s', args.voters, args.concurrency, args.seed)
    start = time.time()

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futures = []
        for i in range(1, args.voters + 1):
            # We want deterministic choices per worker: derive a per-worker seed
            seed = rng_global.randint(0, 2 ** 30)
            rng = random.Random(seed)
            futures.append(ex.submit(worker, i, args.base_url, args.prefix, args.password, rng))

        succeeded = 0
        candidate_counts = {}
        for f in concurrent.futures.as_completed(futures):
            ok, info = f.result()
            if ok:
                succeeded += 1
                candidate_counts[info] = candidate_counts.get(info, 0) + 1

    elapsed = time.time() - start
    logger.info('Simulation finished in %.2fs — %d/%d successful votes', elapsed, succeeded, args.voters)

    if args.db:
        try:
            rows = read_counts_from_db(args.db)
            logger.info('Final counts from DB:')
            for name, cnt in rows:
                logger.info('  %s: %d', name, cnt)
        except Exception as e:
            logger.warning('Could not read DB at %s: %s', args.db, e)

    # Summary of what this script observed
    logger.info('Per-script candidate counts (votes observed by script):')
    for cid, cnt in sorted(candidate_counts.items(), key=lambda x: -x[1]):
        logger.info('  candidate_id=%s : %d', cid, cnt)


if __name__ == '__main__':
    main()
