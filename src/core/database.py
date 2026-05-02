import sqlite3
import threading
import os
from src.core.alerter import analyze_suspicious_query
import src.core.detector as detector

# Thread-local storage to get the current request IP
_current_ip = threading.local()

def set_request_ip(ip):
    _current_ip.value = ip

def get_request_ip():
    return getattr(_current_ip, 'value', '127.0.0.1')

def trace_callback(query):
    """
    SQLite trace callback. Executed on every SQL statement.
    Acts as the 'Digital Tripwire' AND behavioral monitor.
    """
    upper_query = query.upper()
    ip = get_request_ip()

    # Log ALL queries through the anomaly detector
    detector.log_query(ip, query)

    # Check if the honeypot bait table was accessed
    if 'VAULT_SECRETS' in upper_query:
        print(f"\n[!] DIGITAL TRIPWIRE TRIPPED: Unauthorized access to 'vault_secrets' detected!")
        # AUTO SHUTDOWN KILL SWITCH
        with open('.system_lockdown', 'w') as f:
            f.write('LOCKED')
        # Register honeypot incident in the dashboard
        detector.add_honeypot_incident(ip, query)
        threading.Thread(target=analyze_suspicious_query, args=(query,)).start()

def get_db():
    """
    Get a database connection configured with the trace callback.
    """
    db_path = os.path.join(os.path.dirname(__file__), '../../honeypot.db')
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Attach the watchdog trigger
    conn.set_trace_callback(trace_callback)
    return conn

def init_db():
    """
    Initialize the database with normal tables and the honeypot table.
    We don't attach the trace callback here to avoid triggering it during setup.
    """
    db_path = os.path.join(os.path.dirname(__file__), '../../honeypot.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create normal business table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS inventory (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            price REAL NOT NULL
        )
    ''')
    
    # Create honeypot table (The Bait)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vault_secrets (
            id INTEGER PRIMARY KEY,
            service TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    
    # Populate if empty
    cursor.execute("SELECT COUNT(*) FROM inventory")
    if cursor.fetchone()[0] == 0:
        inventory_items = [
            ('Apple', 50, 0.50),
            ('Banana', 100, 0.25),
            ('Orange', 75, 0.60),
            ('Premium Soap', 20, 2.50),
            ('Shampoo', 15, 5.00)
        ]
        cursor.executemany("INSERT INTO inventory (name, quantity, price) VALUES (?, ?, ?)", inventory_items)
        
        # Populate the honeypot with very enticing (but fake) data
        secrets = [
            ('Stripe Payment API', 'admin', 'sk_live_9384729384729384'),
            ('Bank Portal', 'ceo@shop.local', 'P@ssw0rd123!'),
            ('Customer DB Backup', 'root', 'super_secret_root_pass_do_not_share')
        ]
        cursor.executemany("INSERT INTO vault_secrets (service, username, password) VALUES (?, ?, ?)", secrets)
        
    conn.commit()
    conn.close()
    print("Database initialized successfully.")

if __name__ == '__main__':
    init_db()
