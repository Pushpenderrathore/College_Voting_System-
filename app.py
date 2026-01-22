from flask import (
    Flask, render_template, request, redirect,
    session, url_for, flash, Response, g
)
import os, json, csv, io
from datetime import datetime, timedelta

import psycopg2
import psycopg2.pool
import psycopg2.extras

from psycopg2.errors import UniqueViolation
from psycopg2.pool import SimpleConnectionPool


from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf, CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO
from itsdangerous import URLSafeTimedSerializer

# ------------------------------------------------------------------------------
# APP SETUP
# ------------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE= not app.debug,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

csrf = CSRFProtect(app)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri=os.environ.get("REDIS_URL", "memory://")
)

socketio = SocketIO(
    app,
    async_mode="threading",
    cors_allowed_origins="*"
)

# socketio = SocketIO(app, async_mode="threading") optional "eventlet"
serializer = URLSafeTimedSerializer(app.secret_key)

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set")
try:
    db_pool = SimpleConnectionPool(
        minconn=1,
        maxconn=10,
        dsn=DATABASE_URL,
        cursor_factory=psycopg2.extras.RealDictCursor
    )
except psycopg2.OperationalError as e:
    print("⚠️ Database not reachable. Running without DB pool.")
    db_pool = None

import atexit

if db_pool:
    atexit.register(db_pool.closeall)


# ------------------------------------------------------------------------------
# DB HELPERS
# ------------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        if db_pool:
            g.db = db_pool.getconn()
        else:
            g.db = psycopg2.connect(
                DATABASE_URL,
                cursor_factory=psycopg2.extras.RealDictCursor
            )
    return g.db

@app.teardown_appcontext
def close_db(_=None):
    db = g.pop("db", None)
    if db:
        if db_pool:
            db_pool.putconn(db)
        else:
            db.close()


# ------------------------------------------------------------------------------
# DATABASE INIT
# ------------------------------------------------------------------------------

def init_database():
    db = psycopg2.connect(DATABASE_URL)
    cur = db.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        voted BOOLEAN DEFAULT FALSE
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS candidates (
        id SERIAL PRIMARY KEY,
        name TEXT UNIQUE NOT NULL
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS votes (
        id SERIAL PRIMARY KEY,
        voter_id INTEGER UNIQUE REFERENCES users(id) ON DELETE CASCADE,
        candidate_id INTEGER REFERENCES candidates(id) ON DELETE CASCADE,
        timestamp TIMESTAMP NOT NULL
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit (
        id SERIAL PRIMARY KEY,
        action TEXT,
        username TEXT,
        details TEXT,
        timestamp TIMESTAMP
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS feedback (
        id SERIAL PRIMARY KEY,
        user_id INTEGER UNIQUE REFERENCES users(id) ON DELETE CASCADE,
        rating INTEGER,
        comments TEXT,
        timestamp TIMESTAMP
    )""")

    cur.execute("""
    INSERT INTO users (username, password, role)
    VALUES (%s, %s, %s)
    ON CONFLICT (username) DO NOTHING
    """, ("admin", generate_password_hash("admin123"), "admin"))

    for c in ["Alice", "Bob", "Charlie"]:
        cur.execute("""
        INSERT INTO candidates (name)
        VALUES (%s)
        ON CONFLICT (name) DO NOTHING
        """, (c,))

    db.commit()
    cur.close()
    db.close()

init_database()

# ------------------------------------------------------------------------------
# CSRF
# ------------------------------------------------------------------------------

@app.context_processor
def inject_csrf():
    return dict(csrf_token=generate_csrf)

@app.errorhandler(CSRFError)
def csrf_error(_):
    flash("Invalid CSRF token", "danger")
    return redirect(url_for("login"))

# ------------------------------------------------------------------------------
# HELPERS
# ------------------------------------------------------------------------------

def audit(action, details=""):
    db = get_db()
    cur = db.cursor()
    cur.execute("""
        INSERT INTO audit (action, username, details, timestamp)
        VALUES (%s, %s, %s, %s)
    """, (
        action,
        session.get("username", "system"),
        details,
        datetime.utcnow()
    ))


def get_user(username):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE username=%s", (username,))
    return cur.fetchone()

def get_results():
    db = get_db()
    cur = db.cursor()
    cur.execute("""
        SELECT c.id, c.name, COUNT(v.id) AS count
        FROM candidates c
        LEFT JOIN votes v ON v.candidate_id = c.id
        GROUP BY c.id
        ORDER BY count DESC
    """)
    rows = cur.fetchall()
    total = sum(r["count"] for r in rows)
    return [
        {**r, "percent": round((r["count"] / total) * 100, 2) if total else 0}
        for r in rows
    ]

# ------------------------------------------------------------------------------
# AUTH
# ------------------------------------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        db = get_db()
        cur = db.cursor()
        try:
            cur.execute("""
                INSERT INTO users (username, password, role)
                VALUES (%s, %s, 'voter')
            """, (
                request.form["username"],
                generate_password_hash(request.form["password"])
            ))
            db.commit()
            flash("Registered successfully. Please login.", "success")
            return redirect(url_for("login"))   # ✅ FIX
        except UniqueViolation:
            db.rollback()
            flash("Username already exists", "danger")

    return render_template("register.html")


@app.route("/reset-request", methods=["GET", "POST"])
def reset_request():
    if request.method == "POST":
        username = request.form.get("username")

        # optional: verify user exists
        user = get_user(username)
        if not user:
            flash("User not found", "danger")
            return redirect(url_for("reset_request"))

        token = serializer.dumps(username, salt="reset")

        reset_link = url_for(
            "reset_password",
            token=token,
            _external=True   # important for full URL
        )

        # DEV / COLLEGE MODE
        # Show reset link instead of sending email
        flash(f"Password reset link (dev mode): {reset_link}", "info")

        # Optional: log to console
        app.logger.info("Password reset link for %s: %s", username, reset_link)

    return render_template("reset_request.html")


@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        username = serializer.loads(token, salt="reset", max_age=3600)
    except Exception:
        flash("Invalid or expired token", "danger")
        return redirect(url_for("reset_request"))

    if request.method == "POST":
        db = get_db()
        cur = db.cursor()
        cur.execute("""
            UPDATE users SET password=%s WHERE username=%s
        """, (generate_password_hash(request.form["password"]), username))
        db.commit()
        flash("Password reset successful", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html")

@app.route("/", methods=["GET", "POST"])
@limiter.limit("5/minute")
def login():
    if request.method == "POST":
        user = get_user(request.form["username"])
        if user and check_password_hash(user["password"], request.form["password"]):
            session.update(
                user_id=user["id"],
                username=user["username"],
                role=user["role"]
            )
            return redirect(url_for("admin" if user["role"] == "admin" else "vote"))
        flash("Invalid credentials", "danger")
    return render_template("login.html")

@app.route("/_health")
def health():
    return {"status": "ok"}

# ------------------------------------------------------------------------------
# VOTING
# ------------------------------------------------------------------------------

@app.route("/vote", methods=["GET", "POST"])
def vote():
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT voted FROM users WHERE id=%s", (session["user_id"],))
    voted = cur.fetchone()["voted"]

    if request.method == "POST" and not voted:
        try:
            cur.execute("""
                INSERT INTO votes (voter_id, candidate_id, timestamp)
                VALUES (%s, %s, %s)
            """, (session["user_id"], request.form["candidate"], datetime.utcnow()))
            cur.execute("UPDATE users SET voted=TRUE WHERE id=%s", (session["user_id"],))
            audit("vote", f"candidate={request.form['candidate']}")
            db.commit()
            
            flash("Vote recorded", "success")
            voted = True
        except UniqueViolation:
            db.rollback()
            flash("You already voted", "danger")

    cur.execute("SELECT id, name FROM candidates ORDER BY name")
    return render_template("vote.html", candidates=cur.fetchall(), has_voted=voted)

# ------------------------------------------------------------------------------
# FEEDBACK (FIXED)
# ------------------------------------------------------------------------------

@app.route("/feedback", methods=["GET"])
def feedback_page():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("feedback.html")


@app.route("/feedback", methods=["POST"])
def feedback():
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()
    cur = db.cursor()

    cur.execute("SELECT 1 FROM feedback WHERE user_id=%s", (session["user_id"],))
    if cur.fetchone():
        flash("You already submitted feedback", "info")
        return redirect(url_for("vote"))

    cur.execute("""
        INSERT INTO feedback (user_id, rating, comments, timestamp)
        VALUES (%s, %s, %s, %s)
    """, (
        session["user_id"],
        request.form["rating"],
        request.form["comments"],
        datetime.utcnow()
    ))
    audit("feedback")
    db.commit()
    flash("Feedback submitted", "success")
    return redirect(url_for("vote"))

# ------------------------------------------------------------------------------
# ADMIN
# ------------------------------------------------------------------------------

@app.route("/admin")
def admin():
    if session.get("role") != "admin":
        return redirect(url_for("login"))
    return render_template("admin.html", results=get_results())

from functools import wraps
from flask import abort

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            abort(403)
        return fn(*args, **kwargs)
    return wrapper

@app.route("/admin/users")
@admin_required
def admin_users():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, username, role, voted FROM users ORDER BY username")
    users = cur.fetchall()

    admins = sum(1 for u in users if u["role"] == "admin")
    voted = sum(1 for u in users if u["voted"])
    not_voted = sum(1 for u in users if not u["voted"])

    return render_template(
        "admin_users.html",
        users=users,
        admins=admins,
        voted=voted,
        not_voted=not_voted
    )



@app.route("/admin/users/<int:user_id>/promote", methods=["POST"])
@admin_required
def promote_user(user_id):
    db = get_db()
    cur = db.cursor()

    cur.execute("SELECT username, role FROM users WHERE id=%s", (user_id,))
    user = cur.fetchone()
    if not user or user["role"] == "admin":
        return redirect(url_for("admin_users"))

    cur.execute("UPDATE users SET role='admin' WHERE id=%s", (user_id,))
    audit("promote_user", f"user={user['username']}")
    db.commit()

    flash(f"{user['username']} promoted to admin", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/demote", methods=["POST"])
@admin_required
def demote_user(user_id):
    if session.get("user_id") == user_id:
        flash("You cannot demote yourself", "danger")
        return redirect(url_for("admin_users"))

    db = get_db()
    cur = db.cursor()

    cur.execute("SELECT username, role FROM users WHERE id=%s", (user_id,))
    user = cur.fetchone()
    if not user or user["role"] != "admin":
        return redirect(url_for("admin_users"))

    cur.execute("UPDATE users SET role='voter' WHERE id=%s", (user_id,))
    audit("demote_user", f"user={user['username']}")
    db.commit()

    flash(f"{user['username']} demoted", "warning")
    return redirect(url_for("admin_users"))

@app.route("/admin/feedback")
@admin_required
def admin_feedback():
    db = get_db()
    cur = db.cursor()
    cur.execute("""
        SELECT u.username, f.rating, f.comments, f.timestamp
        FROM feedback f
        JOIN users u ON u.id = f.user_id
        ORDER BY f.timestamp DESC
    """)
    feedback = cur.fetchall()
    return render_template("admin_feedback.html", feedback=feedback)

@app.route("/admin/audit")
@admin_required
def admin_audit():
    db = get_db()
    cur = db.cursor()
    cur.execute("""
        SELECT id, action, username, details, timestamp
        FROM audit
        ORDER BY timestamp DESC
        LIMIT 500
    """)
    audits = cur.fetchall()
    return render_template("admin_audit.html", audits=audits)

@app.route("/add_candidate", methods=["POST"])
@admin_required
def add_candidate():
    name = request.form["name"].strip()
    db = get_db()
    cur = db.cursor()

    try:
        cur.execute("INSERT INTO candidates (name) VALUES (%s)", (name,))
        audit("add_candidate", f"name={name}")
        db.commit()
        socketio.emit("results_update", get_results())
        flash("Candidate added", "success")
    except UniqueViolation:
        db.rollback()
        flash("Candidate already exists", "danger")

    return redirect(url_for("admin"))

@app.route("/delete_candidate/<int:cid>", methods=["POST"])
@admin_required
def delete_candidate(cid):
    db = get_db()
    cur = db.cursor()

    cur.execute("SELECT name FROM candidates WHERE id=%s", (cid,))
    c = cur.fetchone()
    if not c:
        return redirect(url_for("admin"))

    cur.execute("DELETE FROM candidates WHERE id=%s", (cid,))
    audit("delete_candidate", f"name={c['name']}")
    db.commit()

    socketio.emit("results_update", get_results())
    flash("Candidate deleted", "warning")
    return redirect(url_for("admin"))

@app.route("/undo_audit/<int:audit_id>", methods=["POST"])
@admin_required
def undo_audit(audit_id):
    db = get_db()
    cur = db.cursor()

    cur.execute("""
        SELECT action, details
        FROM audit
        WHERE id=%s
    """, (audit_id,))
    a = cur.fetchone()
    if not a:
        return redirect(url_for("admin_audit"))

    action = a["action"]
    details = a["details"] or ""

    if action == "promote_user":
        username = details.split("=")[1]
        cur.execute("UPDATE users SET role='voter' WHERE username=%s", (username,))

    elif action == "demote_user":
        username = details.split("=")[1]
        cur.execute("UPDATE users SET role='admin' WHERE username=%s", (username,))

    elif action == "add_candidate":
        name = details.split("=")[1]
        cur.execute("DELETE FROM candidates WHERE name=%s", (name,))

    elif action == "delete_candidate":
        name = details.split("=")[1]
        cur.execute(
            "INSERT INTO candidates (name) VALUES (%s) ON CONFLICT DO NOTHING",
            (name,)
        )
    else:
        flash("This action cannot be undone", "danger")
        return redirect(url_for("admin_audit"))

    cur.execute("DELETE FROM audit WHERE id=%s", (audit_id,))
    audit("undo", f"reverted={action}")
    db.commit()

    socketio.emit("results_update", get_results())
    flash("Action undone", "success")
    return redirect(url_for("admin_audit"))

@app.route("/admin/export")
def export_results():
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    results = get_results()
    fmt = request.args.get("format", "csv")

    if fmt == "json":
        return Response(json.dumps(results), mimetype="application/json")

    out = io.StringIO()
    w = csv.writer(out)
    if results:
        w.writerow(results[0].keys())
        for r in results:
            w.writerow(r.values())

    return Response(out.getvalue(), mimetype="text/csv")

@app.route("/reset_votes", methods=["POST"])
@admin_required
def reset_votes():
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM votes")
    cur.execute("UPDATE users SET voted=FALSE WHERE role!='admin'")
    audit("reset_votes")
    db.commit()
    socketio.emit("results_update", get_results())
    flash("Votes reset", "success")
    return redirect(url_for("admin"))


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out", "info")
    return redirect(url_for("login"))

if __name__ == "__main__":
    socketio.run(
        app,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=True
    )

