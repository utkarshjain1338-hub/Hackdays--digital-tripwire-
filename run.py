from src import create_app, socketio
import os

app = create_app()

if __name__ == '__main__':
    # Start the system lockdown monitor in a background thread if needed,
    # or just rely on the Flask app's behavior.
    # The monitor.py can be run separately or integrated here.
    
    print("\n" + "="*50)
    print("🛡️  DIGITAL TRIPWIRE SYSTEM ACTIVE")
    print("Honeypot Store: http://127.0.0.1:5000/")
    print("Owner Dashboard: http://127.0.0.1:5000/dashboard")
    print("="*50 + "\n")
    
    socketio.run(app, debug=True, port=5000, allow_unsafe_werkzeug=True)
