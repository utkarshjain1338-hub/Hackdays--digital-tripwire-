import sqlite3
import threading
from ai_alerter import analyze_suspicious_query

def trace_callback(query):
    """
    SQLite trace callback. Executed on every SQL statement.
    This acts as our 'Digital Tripwire'.
    """
    upper_query = query.upper()
    
    # We only care if the bait table is accessed
    if 'VAULT_SECRETS' in upper_query:
        # Launch the AI analysis in a separate thread so we don't block the database operation
        print(f"\n[!] DIGITAL TRIPWIRE TRIPPED: Unauthorized access to 'vault_secrets' detected!")
        # AUTO SHUTDOWN KILL SWITCH
        with open('.system_lockdown', 'w') as f:
            f.write('LOCKED')
        threading.Thread(target=analyze_suspicious_query, args=(query,)).start()

def get_db():
    """
    Get a database connection configured with the trace callback.
    """
    conn = sqlite3.connect('honeypot.db', check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Attach the watchdog trigger
    conn.set_trace_callback(trace_callback)
    return conn

def init_db():
    """
    Initialize the database with normal tables and the honeypot table.
    We don't attach the trace callback here to avoid triggering it during setup.
    """
    conn = sqlite3.connect('honeypot.db')
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
