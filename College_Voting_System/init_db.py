import sqlite3
from werkzeug.security import generate_password_hash
from datetime import datetime

db = sqlite3.connect("database.db")
cur = db.cursor()
cur.execute("PRAGMA foreign_keys = ON")

# Users with unique username and voted flag
cur.execute("CREATE TABLE IF NOT EXISTS users("
            "id INTEGER PRIMARY KEY, "
            "username TEXT UNIQUE, "
            "password TEXT, "
            "role TEXT, "
            "voted INTEGER DEFAULT 0)")

# Candidates with unique names
cur.execute("CREATE TABLE IF NOT EXISTS candidates("
            "id INTEGER PRIMARY KEY, "
            "name TEXT UNIQUE)")

# Votes link users and candidates; enforce one vote per user via UNIQUE(voter_id)
cur.execute("CREATE TABLE IF NOT EXISTS votes("
            "id INTEGER PRIMARY KEY, "
            "voter_id INTEGER, "
            "candidate_id INTEGER, "
            "timestamp TEXT, "
            "FOREIGN KEY(voter_id) REFERENCES users(id) ON DELETE CASCADE, "
            "FOREIGN KEY(candidate_id) REFERENCES candidates(id) ON DELETE CASCADE, "
            "UNIQUE(voter_id))")

# Simple audit table
cur.execute("CREATE TABLE IF NOT EXISTS audit("
            "id INTEGER PRIMARY KEY, "
            "action TEXT, "
            "user TEXT, "
            "details TEXT, "
            "timestamp TEXT)")

# Seed data
try:
    cur.execute("INSERT INTO users(username, password, role) VALUES (?,?,?)",
                ('admin', generate_password_hash('admin'), 'admin'))
except sqlite3.IntegrityError:
    pass

try:
    cur.execute("INSERT INTO users(username, password, role) VALUES (?,?,?)",
                ('student1', generate_password_hash('123'), 'voter'))
except sqlite3.IntegrityError:
    pass

for cand in ('Alice','Bob','Charlie'):
    try:
        cur.execute("INSERT INTO candidates(name) VALUES (?)", (cand,))
    except sqlite3.IntegrityError:
        pass

cur.execute("INSERT INTO audit(action,user,details,timestamp) VALUES (?,?,?,?)",
            ('init','system','database initialized', datetime.utcnow().isoformat()))

db.commit()
db.close()