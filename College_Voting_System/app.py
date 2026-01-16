from flask import Flask, render_template, request, redirect, session, url_for, flash, Response, stream_with_context, g
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import time
import json
import csv
import io

# Security and realtime extensions
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf, CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)
app.secret_key = "secret123"
# Enable debug logging
app.logger.setLevel('DEBUG')

# Session & security settings (adjust for prod)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,  # set True in production with HTTPS
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

# Initialize helpers
csrf = CSRFProtect(app)
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])
socketio = SocketIO(app, async_mode='threading')
serializer = URLSafeTimedSerializer(app.secret_key)

DATABASE = "database.db"

@app.context_processor
def inject_csrf():
    # Provide a callable csrf_token() for templates
    return dict(csrf_token=generate_csrf)

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    app.logger.warning('CSRF error: %s', getattr(e, 'description', str(e)))
    flash('Invalid form submission (missing or invalid CSRF token). Please try again.', 'danger')
    return redirect(url_for('login'))

def get_db():
    if 'db' not in g:
        conn = sqlite3.connect(DATABASE, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA foreign_keys = ON')
        g.db = conn
    return g.db

@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# Helpers
def get_user_by_username(username):
    db = get_db()
    cur = db.cursor()
    app.logger.debug('Querying user by username: %s', username)
    cur.execute("SELECT id, username, password, role, voted FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    if not row:
        app.logger.debug('User not found: %s', username)
        return None
    # Normalize to a simple dict to avoid differences in row access
    user = {'id': row[0], 'username': row[1], 'password': row[2], 'role': row[3], 'voted': row[4]}
    app.logger.debug('Found user: %s (id=%s, role=%s)', user['username'], user['id'], user['role'])
    return user

def get_results():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT c.id, c.name, COUNT(v.id) as count FROM candidates c LEFT JOIN votes v ON v.candidate_id = c.id GROUP BY c.id ORDER BY count DESC")
    rows = cur.fetchall()
    total = sum([r['count'] for r in rows])
    results = []
    for r in rows:
        percent = round((r['count'] / total * 100), 2) if total > 0 else 0
        results.append({'id': r['id'], 'name': r['name'], 'count': r['count'], 'percent': percent})
    return results

# --- Authentication improvements: password reset (console based email for now) ---
@app.route('/reset-request', methods=['GET','POST'])
def reset_request():
    if request.method == 'POST':
        username = request.form.get('username')
        u = get_user_by_username(username)
        if u:
            token = serializer.dumps(u['username'], salt='password-reset')
            reset_link = url_for('reset_password', token=token, _external=True)
            # In production send email; for now log and flash
            app.logger.info('Password reset link for %s: %s', username, reset_link)
            flash('Password reset link created and logged on the server (check logs).', 'info')
            return redirect(url_for('login'))
        flash('User not found', 'danger')
    return render_template('reset_request.html')

@app.route('/reset/<token>', methods=['GET','POST'])
def reset_password(token):
    try:
        username = serializer.loads(token, salt='password-reset', max_age=3600)
    except Exception:
        flash('Invalid or expired token', 'danger')
        return redirect(url_for('reset_request'))
    if request.method == 'POST':
        password = request.form.get('password')
        if not password:
            flash('Password required', 'warning')
            return render_template('reset_password.html', token=token)
        db = get_db()
        cur = db.cursor()
        cur.execute("UPDATE users SET password = ? WHERE username = ?", (generate_password_hash(password), username))
        db.commit()
        flash('Password updated. Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', token=token)

@limiter.limit('10 per minute')
@app.route('/', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        try:
            user = request.form.get('username')
            pwd = request.form.get('password')
            app.logger.debug('Login attempt for username: %s', user)
            if not user or not pwd:
                flash('Please provide username and password', 'warning')
                return render_template('login.html')
            u = get_user_by_username(user)
            if not u:
                app.logger.debug('Login failed: user not found for %s', user)
            else:
                pwd_ok = check_password_hash(u['password'], pwd)
                app.logger.debug('Password check for %s: %s', user, pwd_ok)
            if u and check_password_hash(u['password'], pwd):
                session.clear()
                session.permanent = True
                session['user_id'] = u['id']
                session['username'] = u['username']
                session['role'] = u['role']
                app.logger.debug('Login successful for %s (id=%s)', u['username'], u['id'])
                flash('Logged in successfully', 'success')
                if u['role'] == 'admin':
                    return redirect(url_for('admin'))
                return redirect(url_for('vote'))
            flash('Invalid username or password', 'danger')
        except Exception as e:
            app.logger.exception('Login processing failed')
            flash('An internal error occurred while logging in. Please try again.', 'danger')
            return render_template('login.html')
    return render_template('login.html')

# Debug JSON endpoint to check login logic without establishing session
@app.route('/debug/login_test', methods=['POST'])
def debug_login_test():
    if not app.debug:
        return {'error': 'disabled'}, 403
    user = request.form.get('username') or (request.json or {}).get('username')
    pwd = request.form.get('password') or (request.json or {}).get('password')
    app.logger.debug('Debug login test for username=%s', user)
    if not user:
        return {'ok': False, 'reason': 'no username provided'}
    u = get_user_by_username(user)
    if not u:
        return {'ok': False, 'user_found': False}
    pwd_ok = check_password_hash(u['password'], pwd) if pwd else False
    return {'ok': True, 'user_found': True, 'password_ok': pwd_ok, 'role': u['role']}


# Simple health endpoint for quick checks
@app.route('/_health')
def health():
    return {'status': 'ok', 'user': session.get('username')}


@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash('Please provide username and password', 'warning')
            return render_template('register.html')
        db = get_db()
        cur = db.cursor()
        try:
            cur.execute("INSERT INTO users(username, password, role) VALUES (?,?,?)",
                        (username, generate_password_hash(password), 'voter'))
            db.commit()
            flash('Registration successful. You can now log in.', 'success')
            return redirect(url_for('login'), 303)
        except sqlite3.IntegrityError:
            flash('Username already taken', 'danger')
    return render_template('register.html')

@app.route('/vote', methods=['GET','POST'])
def vote():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT voted FROM users WHERE id = ?", (session['user_id'],))
    u = cur.fetchone()
    has_voted = bool(u['voted'])
    if request.method == 'POST' and not has_voted:
        candidate_id = request.form.get('candidate')
        if not candidate_id:
            flash('Please select a candidate', 'warning')
            return redirect(url_for('vote'))
        try:
            cur.execute("INSERT INTO votes(voter_id, candidate_id, timestamp) VALUES (?,?,?)",
                        (session['user_id'], int(candidate_id), datetime.utcnow().isoformat()))
            cur.execute("UPDATE users SET voted = 1 WHERE id = ?", (session['user_id'],))
            cur.execute("INSERT INTO audit(action, user, details, timestamp) VALUES (?,?,?,?)",
                        ('vote', session.get('username'), f'voted for candidate_id={candidate_id}', datetime.utcnow().isoformat()))
            db.commit()
            flash('Vote recorded. Thank you!', 'success')
            return redirect(url_for('vote'))
        except sqlite3.IntegrityError:
            flash('You have already voted', 'danger')
            return redirect(url_for('vote'))
    cur.execute("SELECT id, name FROM candidates ORDER BY name")
    cands = cur.fetchall()
    return render_template('vote.html', candidates=cands, has_voted=has_voted)

@app.route('/admin/export')
def export_results():
    if session.get('role') != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('login'))
    fmt = request.args.get('format', 'csv').lower()
    results = get_results()
    ts = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    if fmt == 'json':
        resp = Response(json.dumps(results, indent=2), mimetype='application/json')
        resp.headers['Content-Disposition'] = f'attachment; filename=results_{ts}.json'
        return resp
    # Default: CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['id', 'name', 'count', 'percent'])
    for r in results:
        writer.writerow([r['id'], r['name'], r['count'], r['percent']])
    resp = Response(output.getvalue(), mimetype='text/csv')
    resp.headers['Content-Disposition'] = f'attachment; filename=results_{ts}.csv'
    return resp

@app.route('/admin')
def admin():
    if session.get('role') != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('login'))
    results = get_results()
    return render_template('admin.html', results=results)

@app.route('/admin/users')
def admin_users():
    if session.get('role') != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('login'))
    db = get_db()
    cur = db.cursor()
    cur.execute('SELECT id, username, role, voted FROM users ORDER BY username')
    users = cur.fetchall()
    return render_template('admin_users.html', users=users)

@app.route('/admin/audit')
def admin_audit():
    if session.get('role') != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('login'))
    db = get_db()
    cur = db.cursor()
    cur.execute('SELECT id, action, user, details, timestamp FROM audit ORDER BY id DESC LIMIT 500')
    audits = cur.fetchall()
    return render_template('admin_audit.html', audits=audits)

@app.route('/admin/audit/<int:audit_id>/undo', methods=['POST'])
def undo_audit(audit_id):
    if session.get('role') != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('login'))
    db = get_db()
    cur = db.cursor()
    cur.execute('SELECT id, action, user, details FROM audit WHERE id = ?', (audit_id,))
    row = cur.fetchone()
    if not row:
        flash('Audit entry not found', 'warning')
        return redirect(url_for('admin_audit'))
    action = row[1]
    details = row[3] or ''

    try:
        if action == 'promote_user':
            # details: promoted username (id=...)
            parts = details.split()
            username = parts[1] if len(parts) > 1 else None
            if not username:
                flash('Cannot undo: username not found in audit', 'danger')
                return redirect(url_for('admin_audit'))
            cur.execute('SELECT id, role FROM users WHERE username = ?', (username,))
            u = cur.fetchone()
            if not u or u[1] != 'admin':
                flash('User is not an admin; nothing to undo', 'info')
                return redirect(url_for('admin_audit'))
            # Demote (unless it's last admin or self)
            cur.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
            admins = cur.fetchone()[0]
            if admins <= 1:
                flash('Cannot undo: would remove last admin', 'danger')
                return redirect(url_for('admin_audit'))
            if username == session.get('username'):
                flash('Cannot undo self-demotion', 'danger')
                return redirect(url_for('admin_audit'))
            cur.execute('UPDATE users SET role = ? WHERE username = ?', ('voter', username))
            cur.execute('INSERT INTO audit(action, user, details, timestamp) VALUES (?,?,?,?)',
                        ('undo_promote_user', session.get('username'), f'undo promote {username}', datetime.utcnow().isoformat()))
            db.commit()
            flash(f'Undid promotion: {username} is now voter', 'success')
            return redirect(url_for('admin_audit'))

        if action == 'demote_user':
            parts = details.split()
            username = parts[1] if len(parts) > 1 else None
            if not username:
                flash('Cannot undo: username not found in audit', 'danger')
                return redirect(url_for('admin_audit'))
            cur.execute('SELECT id, role FROM users WHERE username = ?', (username,))
            u = cur.fetchone()
            if not u or u[1] == 'admin':
                flash('User is already admin; nothing to undo', 'info')
                return redirect(url_for('admin_audit'))
            cur.execute('UPDATE users SET role = ? WHERE username = ?', ('admin', username))
            cur.execute('INSERT INTO audit(action, user, details, timestamp) VALUES (?,?,?,?)',
                        ('undo_demote_user', session.get('username'), f'undo demote {username}', datetime.utcnow().isoformat()))
            db.commit()
            flash(f'Undid demotion: {username} is now admin', 'success')
            return redirect(url_for('admin_audit'))

        if action == 'add_candidate':
            # details likely contains the candidate name
            # try to parse 'added {name}'
            name = None
            if 'added' in details:
                name = details.split('added',1)[1].strip()
            if not name:
                flash('Cannot undo: candidate name not found', 'danger')
                return redirect(url_for('admin_audit'))
            # delete the candidate if exists
            cur.execute('DELETE FROM candidates WHERE name = ?', (name,))
            cur.execute('INSERT INTO audit(action, user, details, timestamp) VALUES (?,?,?,?)',
                        ('undo_add_candidate', session.get('username'), f'undo add {name}', datetime.utcnow().isoformat()))
            db.commit()
            flash(f'Undo add candidate: {name} removed', 'success')
            return redirect(url_for('admin_audit'))

        if action == 'delete_candidate':
            # details format: 'deleted id=NN name=NAME'
            name = None
            if 'name=' in details:
                parts = details.split('name=',1)
                name = parts[1].strip()
            if not name:
                flash('Cannot undo: candidate name not available', 'danger')
                return redirect(url_for('admin_audit'))
            try:
                cur.execute('INSERT INTO candidates(name) VALUES (?)', (name,))
                cur.execute('INSERT INTO audit(action, user, details, timestamp) VALUES (?,?,?,?)',
                            ('undo_delete_candidate', session.get('username'), f'undo delete {name}', datetime.utcnow().isoformat()))
                db.commit()
                try:
                    socketio.emit('results_update', get_results(), broadcast=True)
                except Exception:
                    app.logger.exception('Socket emit failed on undo_delete_candidate')
                flash(f'Candidate {name} restored', 'success')
            except sqlite3.IntegrityError:
                flash('Candidate already exists', 'info')
            return redirect(url_for('admin_audit'))

    except Exception as e:
        app.logger.exception('Undo failed')
        flash('An error occurred while undoing', 'danger')
    return redirect(url_for('admin_audit'))

@app.route('/admin/users/<int:user_id>/promote', methods=['POST'])
def promote_user(user_id):
    if session.get('role') != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('login'))
    db = get_db()
    cur = db.cursor()
    cur.execute('SELECT username, role FROM users WHERE id = ?', (user_id,))
    row = cur.fetchone()
    if not row:
        flash('User not found', 'warning')
        return redirect(url_for('admin_users'))
    username, role = row[0], row[1]
    if role == 'admin':
        flash('User is already an admin', 'info')
        return redirect(url_for('admin_users'))
    cur.execute('UPDATE users SET role = ? WHERE id = ?', ('admin', user_id))
    cur.execute('INSERT INTO audit(action, user, details, timestamp) VALUES (?,?,?,?)',
                ('promote_user', session.get('username'), f'promoted {username} (id={user_id})', datetime.utcnow().isoformat()))
    db.commit()
    flash(f'User {username} promoted to admin', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/demote', methods=['POST'])
def demote_user(user_id):
    if session.get('role') != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('login'))
    # Prevent demotion to leave zero admins; prevent self-demotion
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT username, role FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    if not row:
        flash('User not found', 'warning')
        return redirect(url_for('admin_users'))
    username, role = row[0], row[1]
    if username == session.get('username'):
        flash('You cannot demote yourself', 'warning')
        return redirect(url_for('admin_users'))
    cur.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
    admins = cur.fetchone()[0]
    if admins <= 1:
        flash('Cannot demote the last admin', 'danger')
        return redirect(url_for('admin_users'))
    if role != 'admin':
        flash('User is not an admin', 'info')
        return redirect(url_for('admin_users'))
    cur.execute('UPDATE users SET role = ? WHERE id = ?', ('voter', user_id))
    cur.execute('INSERT INTO audit(action, user, details, timestamp) VALUES (?,?,?,?)',
                ('demote_user', session.get('username'), f'demoted {username} (id={user_id})', datetime.utcnow().isoformat()))
    db.commit()
    flash(f'User {username} demoted to voter', 'success')
    return redirect(url_for('admin_users'))

@app.route('/add_candidate', methods=['POST'])
def add_candidate():
    if session.get('role') != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('login'))
    name = request.form.get('name')
    if not name:
        flash('Name required', 'warning')
        return redirect(url_for('admin'))
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("INSERT INTO candidates(name) VALUES (?)", (name,))
        cur.execute("INSERT INTO audit(action, user, details, timestamp) VALUES (?,?,?,?)",
                    ('add_candidate', session.get('username'), f'added {name}', datetime.utcnow().isoformat()))
        db.commit()
        # Emit realtime update
        try:
            socketio.emit('results_update', get_results(), broadcast=True)
        except Exception:
            app.logger.exception('Socket emit failed on add_candidate')
        flash('Candidate added', 'success')
    except sqlite3.IntegrityError:
        flash('Candidate name must be unique', 'danger')
    return redirect(url_for('admin'))

@app.route('/delete_candidate/<int:candidate_id>', methods=['POST'])
def delete_candidate(candidate_id):
    if session.get('role') != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('login'))
    db = get_db()
    cur = db.cursor()
    # Get name for audit/backfill
    cur.execute("SELECT name FROM candidates WHERE id = ?", (candidate_id,))
    row = cur.fetchone()
    name = row['name'] if row else None
    cur.execute("DELETE FROM candidates WHERE id = ?", (candidate_id,))
    cur.execute("INSERT INTO audit(action, user, details, timestamp) VALUES (?,?,?,?)",
                ('delete_candidate', session.get('username'), f'deleted id={candidate_id} name={name}', datetime.utcnow().isoformat()))
    db.commit()
    try:
        socketio.emit('results_update', get_results(), broadcast=True)
    except Exception:
        app.logger.exception('Socket emit failed on delete_candidate')
    flash('Candidate deleted', 'success')
    return redirect(url_for('admin'))

@app.route('/reset_votes', methods=['POST'])
def reset_votes():
    if session.get('role') != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('login'))
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM votes")
    cur.execute("UPDATE users SET voted = 0 WHERE role <> 'admin'")
    cur.execute("INSERT INTO audit(action, user, details, timestamp) VALUES (?,?,?,?)",
                ('reset_votes', session.get('username'), 'reset all votes', datetime.utcnow().isoformat()))
    db.commit()
    try:
        socketio.emit('results_update', get_results(), broadcast=True)
    except Exception:
        app.logger.exception('Socket emit failed on reset_votes')
    flash('All votes have been reset', 'success')
    return redirect(url_for('admin'))

# Deprecated SSE endpoint — Socket.IO is used for real-time updates
@app.route('/stream')
def stream():
    return {'error': 'SSE endpoint deprecated. Use Socket.IO client'}, 410

# SocketIO event handlers (if you want presence or other events)
@socketio.on('connect')
def on_connect():
    app.logger.debug('Socket connected: %s', request.sid if hasattr(request, 'sid') else 'unknown')

@socketio.on('disconnect')
def on_disconnect():
    app.logger.debug('Socket disconnected')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    socketio.run(app, debug=True)
