from flask import Blueprint, render_template, jsonify, request, session, redirect, url_for
import os
import src.core.detector as detector
import src.core.database as database

dashboard_bp = Blueprint('dashboard', __name__)

# Note: In a production app, we'd use a more secure way to handle passwords.
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

def is_authenticated():
    return session.get('authenticated') == True

@dashboard_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form.get('password')
        if password == ADMIN_PASSWORD:
            session['authenticated'] = True
            return redirect(url_for('dashboard.dashboard'))
        return render_template('login.html', error="Invalid password")
    return render_template('login.html')

@dashboard_bp.route('/logout')
def logout():
    session.pop('authenticated', None)
    return redirect(url_for('dashboard.login'))

@dashboard_bp.route('/dashboard')
def dashboard():
    if not is_authenticated():
        return redirect(url_for('dashboard.login'))
    return render_template('dashboard.html')

@dashboard_bp.route('/api/incidents')
def api_incidents():
    if not is_authenticated():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(detector.incident_log)

@dashboard_bp.route('/api/status')
def api_status():
    # Status is public-ish but let's restrict it if needed. 
    # For the dashboard to show status before login, we might need this public.
    # But usually dashboard.html loads it.
    locked = os.path.exists(database.LOCKDOWN_FILE)
    return jsonify({
        "locked": locked,
        "total_incidents": len(detector.incident_log),
    })

@dashboard_bp.route('/api/unlock', methods=['POST'])
def api_unlock():
    if not is_authenticated():
        return jsonify({"error": "Unauthorized"}), 401
        
    if os.path.exists(database.LOCKDOWN_FILE):
        os.remove(database.LOCKDOWN_FILE)
        from src import socketio
        socketio.emit('system_unlocked', {})
        print("\n[Dashboard] ✅ System unlocked by owner via dashboard.")
        return jsonify({"status": "unlocked"})
    return jsonify({"status": "not_locked"})
