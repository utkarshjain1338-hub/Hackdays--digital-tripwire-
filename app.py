from flask import Flask, request, render_template, abort, jsonify
from flask_socketio import SocketIO
import database
import anomaly_detector
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'digital-tripwire-secret'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Wire the SocketIO instance into the anomaly detector
anomaly_detector.set_socketio(socketio)

# Ensure DB is initialized
database.init_db()

@app.before_request
def before():
    # Tag the current thread with the requester's IP for anomaly tracking
    database.set_request_ip(request.remote_addr)
    # Kill switch: block all traffic if system is locked down
    if os.path.exists('.system_lockdown') and request.path not in ('/api/unlock', '/dashboard', '/socket.io/'):
        abort(403, description="SYSTEM SECURED: A severe security threat was detected and the system has been automatically locked down.")

# ── Cashier Store ──────────────────────────────────────────────
@app.route('/', methods=['GET', 'POST'])
def index():
    db = database.get_db()
    cursor = db.cursor()
    search_query = request.form.get('search', '')
    if search_query:
        # INTENTIONALLY VULNERABLE for honeypot demonstration
        query = f"SELECT * FROM inventory WHERE name LIKE '%{search_query}%'"
        try:
            cursor.execute(query)
            results = cursor.fetchall()
        except Exception as e:
            results = []
            print(f"Error executing query: {e}")
    else:
        cursor.execute("SELECT * FROM inventory")
        results = cursor.fetchall()
    db.close()
    return render_template('index.html', items=results, search_query=search_query)

# ── Owner Dashboard ────────────────────────────────────────────
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/incidents')
def api_incidents():
    return jsonify(anomaly_detector.incident_log)

@app.route('/api/status')
def api_status():
    locked = os.path.exists('.system_lockdown')
    return jsonify({
        "locked": locked,
        "total_incidents": len(anomaly_detector.incident_log),
    })

@app.route('/api/unlock', methods=['POST'])
def api_unlock():
    if os.path.exists('.system_lockdown'):
        os.remove('.system_lockdown')
        socketio.emit('system_unlocked', {})
        print("\n[Dashboard] ✅ System unlocked by owner via dashboard.")
        return jsonify({"status": "unlocked"})
    return jsonify({"status": "not_locked"})

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000, allow_unsafe_werkzeug=True)
