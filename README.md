# College Voting System

A simple college voting application built with Flask. This fork includes realtime admin updates (Socket.IO), improved UI (Bootstrap), authentication improvements, and security hardening (CSRF, rate-limiting). This README explains how to set up, run, and manage the database safely.

---

## 🚀 Quick Start

1. Create and activate a virtual environment (recommended):

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Initialize the database (destructive if DB exists):

```bash
python init_db.py
```

4. Run the dev server:

```bash
python app.py
# or (recommended) when using Socket.IO:
python app.py
```

5. Open the app in your browser: http://127.0.0.1:5000

- Seeded admin account: **username:** `admin`, **password:** `admin`

---

## 🔧 Features

- User registration and login
- Admin dashboard with real-time results (Socket.IO)
- Candidate management (add/delete/reset)
- Vote protection (one vote per user)
- User feedback system (rating and comments)
- Password reset (token via server logs; replace with email sending in production)
- CSRF protection and rate limiting (optional package)
- Bootstrapped UI with responsive layout and improved CSS

---

## 📁 Database notes

### Reset (destructive)

To reset the DB to the initial seeded state (warning: **this deletes all data**):

```bash
rm database.db
python init_db.py
```

On Windows PowerShell:

```powershell
Remove-Item database.db
python init_db.py
```

### Safe migration (preserve existing data)

If you previously ran an older version of the app, your `database.db` might have a different schema. If you want to preserve existing users/candidates/votes, follow these steps (run from project root):

1. Back up the DB first:

```bash
cp database.db database.db.bak
# Windows
copy database.db database.db.bak
```

2. Use the sqlite3 CLI (or a DB browser) to create new tables and copy data. Example SQL (conceptual):

```sql
BEGIN;

-- create new tables
CREATE TABLE users_new (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT, voted INTEGER DEFAULT 0);
CREATE TABLE candidates_new (id INTEGER PRIMARY KEY, name TEXT UNIQUE);
CREATE TABLE votes_new (id INTEGER PRIMARY KEY, voter_id INTEGER, candidate_id INTEGER, timestamp TEXT, FOREIGN KEY (voter_id) REFERENCES users_new(id), FOREIGN KEY (candidate_id) REFERENCES candidates_new(id), UNIQUE(voter_id));

-- copy candidates
INSERT INTO candidates_new(name) SELECT name FROM candidates;

-- copy users (set voted flag if user appears in old votes)
INSERT INTO users_new(username, password, role, voted)
SELECT u.username, u.password, u.role, CASE WHEN v.voter IS NOT NULL THEN 1 ELSE 0 END
FROM users u LEFT JOIN (SELECT DISTINCT voter FROM votes) v ON v.voter = u.username;

-- copy votes mapping names to ids
INSERT INTO votes_new(voter_id, candidate_id, timestamp)
SELECT uu.id, cc.id, datetime('now')
FROM votes v JOIN users_new uu ON v.voter = uu.username JOIN candidates_new cc ON v.candidate = cc.name;

-- swap tables
DROP TABLE votes;
DROP TABLE users;
DROP TABLE candidates;
ALTER TABLE users_new RENAME TO users;
ALTER TABLE candidates_new RENAME TO candidates;
ALTER TABLE votes_new RENAME TO votes;

COMMIT;
```

Note: the exact SQL may need adjustments depending on your existing schema. If your DB is important, keep the backup and ask for help; I can generate an automated migration script for your DB specifically.

---

## ✅ Requirements

A minimal requirements file is included (`requirements.txt`). Install with:

```bash
pip install -r requirements.txt
```

Optional extras for production: `eventlet` or `gevent` for better Socket.IO performance, and an SMTP server for password reset emails.

---

## 🧪 Tests

There are no automated tests yet. If you'd like, I can add unit and integration tests (pytest + a test database) and a GitHub Actions workflow.

---

## 🔐 Security & Production Notes

- In production, set `SESSION_COOKIE_SECURE=True` and run the app behind HTTPS.
- Configure a real email provider for password reset flows.
- Use production-grade servers for Socket.IO (e.g., eventlet) and configure proper logging and monitoring.
- Replace the console-logged password reset link with an email send using an SMTP provider or transactional email service.

---

## 🧰 Development tips

- Debugging: run the server in a terminal and watch logs for socket and login messages.
- If you add packages, update `requirements.txt` (e.g., `pip freeze > requirements.txt`).

---

If you'd like, I can now:

- Add automated tests and a GitHub Actions workflow,
- Replace the password-reset console logging with real email sending,
- Or migrate SSE → WebSockets fully with presence indicators and Chart.js graphs.

Tell me which one you want next and I’ll start implementing it. 🚀

---

## 🚀 Deployment (Docker + Render) ✅

This repo now includes a `Dockerfile`, `Procfile`, and a sample `render.yaml` that you can use to deploy the app for free on Render (use the `free` plan).

Quick start (local Docker):

1. Build the image:

```bash
docker build -t college-voting-system .
```

2. Run locally (set a secret key and DB path):

```bash
docker run -p 8000:8000 -e SECRET_KEY=supersecret -e DATABASE_URL=sqlite:///database.db college-voting-system
```

3. Push to GitHub and connect the repo to Render. Render will use `render.yaml` and build the Docker image. In the Render dashboard, set `SECRET_KEY` (and add a managed Postgres and its `DATABASE_URL` if you prefer not to use SQLite).

Notes:
- Socket.IO: The `Dockerfile` installs `eventlet` and the start command uses `gunicorn -k eventlet` for WebSocket support.
- Health: use the `/ _health` endpoint to verify the service is up.
- For production use, replace the bundled SQLite DB with a managed Postgres DB and set `DATABASE_URL` accordingly.

If you'd like, I can also add a GitHub Actions workflow to build and push the Docker image, or create a sample Render DB config. Let me know which you prefer.
