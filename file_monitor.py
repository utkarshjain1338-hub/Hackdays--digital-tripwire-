import time
import os
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from ai_alerter import analyze_suspicious_query

class OSBypassMonitor(FileSystemEventHandler):
    def on_moved(self, event):
        if 'honeypot.db' in event.src_path:
            self.trigger_lockdown(f"OS_LEVEL_BYPASS: Database file moved to {event.dest_path}")
            
    def on_deleted(self, event):
        if 'honeypot.db' in event.src_path:
            self.trigger_lockdown("OS_LEVEL_BYPASS: Database file deleted by unauthorized process!")
            
    def on_created(self, event):
        # Detect if someone is making a copy of the database file
        if event.src_path.endswith('.db') and 'honeypot' not in event.src_path:
            self.trigger_lockdown(f"OS_LEVEL_BYPASS: Potential unauthorized database copy created: {event.src_path}")

    def trigger_lockdown(self, reason):
        if not os.path.exists('.system_lockdown'):
            print(f"\n[OS Monitor] 🚨 CRITICAL: OS-level bypass detected!")
            print(f"[OS Monitor] Reason: {reason}")
            
            # Instantly lock down the system
            with open('.system_lockdown', 'w') as f:
                f.write('LOCKED_OS_LEVEL')
            
            # Trigger the AI incident response pipeline
            threading.Thread(target=analyze_suspicious_query, args=(reason,)).start()

def start_monitor():
    path = "."
    event_handler = OSBypassMonitor()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=False)
    observer.start()
    print("[OS Monitor] Defense-in-Depth active. Watching filesystem for OS-level database bypasses...")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    start_monitor()
