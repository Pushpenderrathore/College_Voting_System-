import os
import tempfile
import sqlite3
from datetime import datetime

import pytest
from werkzeug.security import generate_password_hash

import importlib.util
import pathlib
# Load local app module explicitly (avoid importing wrong global 'app')
_root = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("voting_app", str(_root / "app.py"))
voting_app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(voting_app)

@pytest.fixture
def client(tmp_path, monkeypatch):
    db_file = tmp_path / 'test.db'
    # Initialize minimal schema
    conn = sqlite3.connect(str(db_file))
    cur = conn.cursor()
    cur.execute("CREATE TABLE users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, role TEXT, voted INTEGER DEFAULT 0)")
    cur.execute("CREATE TABLE candidates(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE)")
    cur.execute("CREATE TABLE votes(id INTEGER PRIMARY KEY AUTOINCREMENT, voter_id INTEGER, candidate_id INTEGER, timestamp TEXT, UNIQUE(voter_id))")
    cur.execute("CREATE TABLE audit(id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT, user TEXT, details TEXT, timestamp TEXT)")
    # Seed admin and one user
    cur.execute("INSERT INTO users(username,password,role) VALUES (?,?,?)", ('admin', generate_password_hash('admin'), 'admin'))
    cur.execute("INSERT INTO users(username,password,role) VALUES (?,?,?)", ('bob', generate_password_hash('pass'), 'voter'))
    conn.commit()
    conn.close()

    # Point app to this db
    monkeypatch.setattr(voting_app, 'DATABASE', str(db_file))
    voting_app.app.config['TESTING'] = True
    # Disable CSRF for easier testing
    voting_app.app.config['WTF_CSRF_ENABLED'] = False

    with voting_app.app.test_client() as c:
        yield c


def test_promote_and_demote(client):
    # Login as admin
    rv = client.post('/', data={'username': 'admin', 'password': 'admin'}, follow_redirects=True)
    assert b'Logged in successfully' in rv.data
    # Promote bob
    # Find bob id
    db = sqlite3.connect(voting_app.DATABASE)
    cur = db.cursor()
    cur.execute("SELECT id FROM users WHERE username = ?", ('bob',))
    bob_id = cur.fetchone()[0]
    db.close()

    rv = client.post(f'/admin/users/{bob_id}/promote', follow_redirects=True)
    assert b'promoted to admin' in rv.data

    # Check db
    db = sqlite3.connect(voting_app.DATABASE)
    cur = db.cursor()
    cur.execute("SELECT role FROM users WHERE username = ?", ('bob',))
    assert cur.fetchone()[0] == 'admin'
    # Audit entry
    cur.execute("SELECT action, details FROM audit WHERE action = 'promote_user' ORDER BY id DESC LIMIT 1")
    row = cur.fetchone()
    assert row is not None
    db.close()

    # Demote bob back
    rv = client.post(f'/admin/users/{bob_id}/demote', follow_redirects=True)
    assert b'demoted to voter' in rv.data
    db = sqlite3.connect(voting_app.DATABASE)
    cur = db.cursor()
    cur.execute("SELECT role FROM users WHERE username = ?", ('bob',))
    assert cur.fetchone()[0] == 'voter'
    db.close()


def test_cannot_demote_self_or_last_admin(client):
    # Login as admin
    rv = client.post('/', data={'username': 'admin', 'password': 'admin'}, follow_redirects=True)
    assert b'Logged in successfully' in rv.data
    # Attempt to demote self
    db = sqlite3.connect(voting_app.DATABASE)
    cur = db.cursor()
    cur.execute("SELECT id FROM users WHERE username = ?", ('admin',))
    admin_id = cur.fetchone()[0]
    db.close()

    rv = client.post(f'/admin/users/{admin_id}/demote', follow_redirects=True)
    assert b'You cannot demote yourself' in rv.data or b'Cannot demote the last admin' in rv.data


def test_undo_promote(client):
    # Login and promote bob
    rv = client.post('/', data={'username': 'admin', 'password': 'admin'}, follow_redirects=True)
    db = sqlite3.connect(voting_app.DATABASE)
    cur = db.cursor()
    cur.execute("SELECT id FROM users WHERE username = ?", ('bob',))
    bob_id = cur.fetchone()[0]
    db.close()
    rv = client.post(f'/admin/users/{bob_id}/promote', follow_redirects=True)
    assert b'promoted to admin' in rv.data

    # Find audit entry id
    db = sqlite3.connect(voting_app.DATABASE)
    cur = db.cursor()
    cur.execute("SELECT id FROM audit WHERE action = 'promote_user' ORDER BY id DESC LIMIT 1")
    aid = cur.fetchone()[0]
    db.close()

    rv = client.post(f'/admin/audit/{aid}/undo', follow_redirects=True)
    assert b'Undid promotion' in rv.data
    # bob should be voter again
    db = sqlite3.connect(voting_app.DATABASE)
    cur = db.cursor()
    cur.execute("SELECT role FROM users WHERE username = ?", ('bob',))
    assert cur.fetchone()[0] == 'voter'
    db.close()
