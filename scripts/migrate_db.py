"""Safe DB migration script for College Voting System

- Creates a backup of `database.db` as `database.db.bak`.
- Migrates `users`, `candidates`, and `votes` tables to the schema expected by the current app:
  users -> (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT, voted INTEGER DEFAULT 0)
  candidates -> (id INTEGER PRIMARY KEY, name TEXT UNIQUE)
  votes -> (id INTEGER PRIMARY KEY, voter_id INTEGER, candidate_id INTEGER, timestamp TEXT, UNIQUE(voter_id))
- Tries to preserve existing data by mapping usernames and candidate names to new IDs.

Usage: python scripts/migrate_db.py
"""
import sqlite3
import shutil
import os
from datetime import datetime

DB = 'database.db'
BAK = DB + '.bak'

if not os.path.exists(DB):
    print('No database found at', DB)
    raise SystemExit(1)

print('Backing up', DB, '->', BAK)
shutil.copyfile(DB, BAK)

conn = sqlite3.connect(DB)
cur = conn.cursor()

# Helper to get current columns for a table
def cols(table):
    cur.execute("PRAGMA table_info('{}')".format(table))
    return [r[1] for r in cur.fetchall()]

print('Current tables and columns:')
for t in ['users', 'candidates', 'votes', 'audit']:
    try:
        print('-', t, '->', cols(t))
    except Exception as e:
        print('-', t, '-> error reading columns:', e)

# Migrate users table if needed
u_cols = cols('users')
if 'id' not in u_cols or 'voted' not in u_cols or 'username' not in u_cols:
    print('\nMigrating users table...')
    # Create new users table
    cur.execute('''CREATE TABLE IF NOT EXISTS users_new (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT,
        voted INTEGER DEFAULT 0
    )''')
    # Copy data over (keep username, password, role). If there are duplicate usernames will fail.
    try:
        cur.execute("SELECT username, password, role FROM users")
        for username, password, role in cur.fetchall():
            # Protect against NULL username
            if not username:
                continue
            cur.execute('INSERT OR IGNORE INTO users_new (username, password, role, voted) VALUES (?,?,?,?)',
                        (username, password, role, 0))
    except Exception as e:
        print('Warning while copying users:', e)
    # Replace table
    cur.execute('DROP TABLE users')
    cur.execute('ALTER TABLE users_new RENAME TO users')
    conn.commit()
    print('Users migrated')
else:
    print('\nUsers table looks up-to-date')

# Migrate candidates table if needed
c_cols = cols('candidates')
if 'id' not in c_cols or 'name' not in c_cols or len(c_cols) == 1:
    print('\nMigrating candidates table...')
    cur.execute('''CREATE TABLE IF NOT EXISTS candidates_new (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE
    )''')
    try:
        # If old table had only name column, copy names; otherwise attempt to copy id/name where possible
        if 'name' in c_cols:
            cur.execute('SELECT name FROM candidates')
            for (name,) in cur.fetchall():
                if not name:
                    continue
                cur.execute('INSERT OR IGNORE INTO candidates_new (name) VALUES (?)', (name,))
        else:
            cur.execute('SELECT * FROM candidates')
            for row in cur.fetchall():
                # Try to guess a name in the row
                name = None
                for val in row:
                    if isinstance(val, str) and val.strip():
                        name = val.strip(); break
                if name:
                    cur.execute('INSERT OR IGNORE INTO candidates_new (name) VALUES (?)', (name,))
    except Exception as e:
        print('Warning while copying candidates:', e)
    cur.execute('DROP TABLE candidates')
    cur.execute('ALTER TABLE candidates_new RENAME TO candidates')
    conn.commit()
    print('Candidates migrated')
else:
    print('\nCandidates table looks up-to-date')

# Migrate votes table
v_cols = cols('votes')
if 'voter_id' not in v_cols or 'candidate_id' not in v_cols:
    print('\nMigrating votes table...')
    cur.execute('''CREATE TABLE IF NOT EXISTS votes_new (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        voter_id INTEGER,
        candidate_id INTEGER,
        timestamp TEXT,
        UNIQUE(voter_id)
    )''')
    # Attempt to map old votes: common patterns are (voter username, candidate name) or (voter id, candidate id)
    try:
        cur.execute('SELECT * FROM votes')
        rows = cur.fetchall()
        for row in rows:
            # If old table columns were (voter, candidate) probably both strings
            if len(row) >= 2:
                v, c = row[0], row[1]
                voter_id = None
                candidate_id = None
                # Try to resolve voter -> id by username
                if isinstance(v, str):
                    cur.execute('SELECT id FROM users WHERE username = ?', (v,))
                    r = cur.fetchone()
                    voter_id = r[0] if r else None
                else:
                    # maybe it's numeric id
                    voter_id = int(v) if v else None
                # Resolve candidate similarly
                if isinstance(c, str):
                    cur.execute('SELECT id FROM candidates WHERE name = ?', (c,))
                    r = cur.fetchone()
                    candidate_id = r[0] if r else None
                else:
                    candidate_id = int(c) if c else None
                # Insert if we could resolve
                if voter_id and candidate_id:
                    cur.execute('INSERT OR IGNORE INTO votes_new (voter_id, candidate_id, timestamp) VALUES (?,?,?)',
                                (voter_id, candidate_id, datetime.utcnow().isoformat()))
    except Exception as e:
        print('Warning while copying votes:', e)
    cur.execute('DROP TABLE votes')
    cur.execute('ALTER TABLE votes_new RENAME TO votes')
    conn.commit()
    print('Votes migrated')
else:
    print('\nVotes table looks up-to-date')

print('\nMigration complete. If your site still errors, check the server logs for details and restart the app.')

# Add feedback table if it doesn't exist
try:
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='feedback'")
    if not cur.fetchone():
        print('\nAdding feedback table...')
        cur.execute('''CREATE TABLE feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            rating INTEGER,
            comments TEXT,
            timestamp TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(user_id)
        )''')
        conn.commit()
        print('Feedback table added')
    else:
        print('\nFeedback table already exists')
        # Check if UNIQUE constraint exists
        cur.execute("PRAGMA index_list(feedback)")
        indexes = cur.fetchall()
        has_unique = any('user_id' in idx[1] for idx in indexes)
        if not has_unique:
            print('Adding UNIQUE constraint to feedback.user_id...')
            # To add UNIQUE, we need to recreate the table
            cur.execute("ALTER TABLE feedback RENAME TO feedback_old")
            cur.execute('''CREATE TABLE feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                rating INTEGER,
                comments TEXT,
                timestamp TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE(user_id)
            )''')
            cur.execute("INSERT INTO feedback (id, user_id, rating, comments, timestamp) SELECT id, user_id, rating, comments, timestamp FROM feedback_old")
            cur.execute("DROP TABLE feedback_old")
            conn.commit()
            print('UNIQUE constraint added to feedback table')
except Exception as e:
    print('Error checking/adding feedback table:', e)

conn.close()
