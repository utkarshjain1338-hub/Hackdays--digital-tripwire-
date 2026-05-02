from flask import Flask, request, abort
from flask_socketio import SocketIO
import os
import src.core.database as database
import src.core.detector as detector

socketio = SocketIO()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'digital-tripwire-secret'
    
    socketio.init_app(app, cors_allowed_origins="*", async_mode='threading')
    
    # Wire the SocketIO instance into the anomaly detector
    detector.set_socketio(socketio)
    
    # Ensure DB is initialized
    database.init_db()
    
    @app.before_request
    def before():
        # Tag the current thread with the requester's IP for anomaly tracking
        database.set_request_ip(request.remote_addr)
        # Kill switch: block all traffic if system is locked down
        if os.path.exists('.system_lockdown') and request.path not in ('/api/unlock', '/dashboard', '/socket.io/'):
            abort(403, description="SYSTEM SECURED: A severe security threat was detected and the system has been automatically locked down.")

    # Register Blueprints
    from src.routes.store import store_bp
    from src.routes.dashboard import dashboard_bp
    
    app.register_blueprint(store_bp)
    app.register_blueprint(dashboard_bp)
    
    return app
