from flask import (
    Flask, render_template, request, redirect,
    session, url_for, flash, Response, g
)
import os, json, csv, io
from datetime import datetime, timedelta

import psycopg2
import psycopg2.extras
from psycopg2.errors import UniqueViolation


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
    SESSION_COOKIE_SECURE=not app.debug,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

csrf = CSRFProtect(app)
limiter = Limiter(app=app, key_func=get_remote_address)
socketio = SocketIO(app, async_mode="eventlet")
serializer = URLSafeTimedSerializer(app.secret_key)

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set")

# ------------------------------------------------------------------------------
# DB HELPERS
# ------------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = psycopg2.connect(
            DATABASE_URL,
            cursor_factory=psycopg2.extras.RealDictCursor
        )
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db:
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
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS candidates (
        id SERIAL PRIMARY KEY,
        name TEXT UNIQUE NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS votes (
        id SERIAL PRIMARY KEY,
        voter_id INTEGER UNIQUE REFERENCES users(id) ON DELETE CASCADE,
        candidate_id INTEGER REFERENCES candidates(id) ON DELETE CASCADE,
        timestamp TIMESTAMP NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit (
        id SERIAL PRIMARY KEY,
        action TEXT,
        username TEXT,
        details TEXT,
        timestamp TIMESTAMP
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS feedback (
        id SERIAL PRIMARY KEY,
        user_id INTEGER UNIQUE REFERENCES users(id) ON DELETE CASCADE,
        rating INTEGER,
        comments TEXT,
        timestamp TIMESTAMP
    )
    """)

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

with app.app_context():
    init_database()

# ------------------------------------------------------------------------------
# CSRF
# ------------------------------------------------------------------------------

@app.context_processor
def inject_csrf():
    return dict(csrf_token=generate_csrf)

@app.errorhandler(CSRFError)
def csrf_error(e):
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
    """, (action, session.get("username"), details, datetime.utcnow()))
    db.commit()

def get_user(username):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE username = %s", (username,))
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
        {**r, "percent": round((r["count"]/total)*100, 2) if total else 0}
        for r in rows
    ]

# ------------------------------------------------------------------------------
# AUTH ROUTES
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
            """, (request.form["username"],
                  generate_password_hash(request.form["password"])))
            db.commit()
            flash("Registered successfully", "success")
        except psycopg2.errors.UniqueViolation:
            db.rollback()
            flash("Username exists", "danger")
    return render_template("register.html")

@app.route("/reset-request", methods=["GET", "POST"])
def reset_request():
    if request.method == "POST":
        token = serializer.dumps(request.form["username"], salt="reset")
    return render_template("reset_request.html")

@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):
    username = serializer.loads(token, salt="reset", max_age=3600)
    if request.method == "POST":
        db = get_db()
        cur = db.cursor()
        cur.execute("""
            UPDATE users SET password=%s WHERE username=%s
        """, (generate_password_hash(request.form["password"]), username))
        db.commit()
        flash("Password reset", "success")
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
            return redirect(url_for("admin" if user["role"]=="admin" else "vote"))
        flash("Invalid login", "danger")
    return render_template("login.html")

@app.route("/_health")
def health():
    return {"status": "ok"}

# ------------------------------------------------------------------------------
# VOTING + FEEDBACK
# ------------------------------------------------------------------------------

@app.route("/vote", methods=["GET","POST"])
def vote():
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT voted FROM users WHERE id=%s", (session["user_id"],))
    voted = cur.fetchone()["voted"]

    if request.method=="POST" and not voted:
        try:
            cur.execute("""
                INSERT INTO votes (voter_id,candidate_id,timestamp)
                VALUES (%s,%s,%s)
            """,(session["user_id"],request.form["candidate"],datetime.utcnow()))
    
            
            cur.execute("UPDATE users SET voted=TRUE WHERE id=%s",(session["user_id"],))
            audit("vote", f"candidate={request.form['candidate']}")
            db.commit()
            socketio.emit("results_update", get_results())
            flash("Vote recorded","success")
            voted = True

        except UniqueViolation:
            db.rollback()
            flash("You already voted", "danger")


    cur.execute("SELECT id,name FROM candidates ORDER BY name")
    return render_template("vote.html",
        candidates=cur.fetchall(),
        has_voted=voted
    )

@app.route("/feedback", methods=["POST"])
def feedback():
    db = get_db()
    cur = db.cursor()

    cur.execute("SELECT 1 FROM feedback WHERE user_id=%s", (session["user_id"],))
    if cur.fetchone():
        flash("You already submitted feedback", "info")
        return redirect(url_for("vote"))

    cur.execute("""
        INSERT INTO feedback (user_id,rating,comments,timestamp)
        VALUES (%s,%s,%s,%s)
    """,(session["user_id"],request.form["rating"],
         request.form["comments"],datetime.utcnow()))

    audit("feedback")
    db.commit()
    flash("Feedback submitted","success")
    return redirect(url_for("vote"))


# ------------------------------------------------------------------------------
# ADMIN
# ------------------------------------------------------------------------------

@app.route("/admin")
def admin():
    if session.get("role")!="admin":
        return redirect(url_for("login"))
    return render_template("admin.html", results=get_results())

@app.route("/admin/export")
def export_results():
    fmt=request.args.get("format","csv")
    results=get_results()
    if fmt=="json":
        return Response(json.dumps(results),mimetype="application/json")
    out=io.StringIO()
    w=csv.writer(out)
    if not results:
        return Response("", mimetype="text/csv")
    for r in results: w.writerow(r.values())
    return Response(out.getvalue(),mimetype="text/csv")

@app.route("/reset_votes",methods=["POST"])
def reset_votes():
    db=get_db()
    cur=db.cursor()
    cur.execute("DELETE FROM votes")
    cur.execute("UPDATE users SET voted=FALSE WHERE role!='admin'")
    audit("reset_votes")
    db.commit()
    socketio.emit("results_update", get_results())
    flash("Votes reset","success")
    return redirect(url_for("admin"))

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out","info")
    return redirect(url_for("login"))
