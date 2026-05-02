from flask import Blueprint, render_template, jsonify, request
import os
import src.core.detector as detector

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@dashboard_bp.route('/api/incidents')
def api_incidents():
    return jsonify(detector.incident_log)

@dashboard_bp.route('/api/status')
def api_status():
    locked = os.path.exists('.system_lockdown')
    return jsonify({
        "locked": locked,
        "total_incidents": len(detector.incident_log),
    })

@dashboard_bp.route('/api/unlock', methods=['POST'])
def api_unlock():
    # Note: socketio.emit is handled in src/__init__.py or passed via a helper if needed.
    # For now, let's assume we handle the file deletion here and the frontend polling or 
    # a shared socketio instance.
    if os.path.exists('.system_lockdown'):
        os.remove('.system_lockdown')
        from src import socketio
        socketio.emit('system_unlocked', {})
        print("\n[Dashboard] ✅ System unlocked by owner via dashboard.")
        return jsonify({"status": "unlocked"})
    return jsonify({"status": "not_locked"})
