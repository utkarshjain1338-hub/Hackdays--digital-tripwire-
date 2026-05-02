import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class LockdownHandler(FileSystemEventHandler):
    """
    Monitor the .system_lockdown file to trigger system-level alerts
    or hardware-level responses (simulated).
    """
    def on_created(self, event):
        if '.system_lockdown' in event.src_path:
            print("\n" + "!" * 60)
            print("CRITICAL: SYSTEM LOCKDOWN INITIATED")
            print("Digital Tripwire triggered. All non-admin traffic blocked.")
            print("!" * 60 + "\n")

    def on_deleted(self, event):
        if '.system_lockdown' in event.src_path:
            print("\n" + "=" * 60)
            print("INFO: SYSTEM UNLOCKED")
            print("Access has been restored by the system administrator.")
            print("=" * 60 + "\n")

def start_monitor():
    path = "."
    event_handler = LockdownHandler()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=False)
    observer.start()
    print("[Monitor] 📡 OS-level file monitor started. Watching for lockdown triggers...")
    return observer

if __name__ == "__main__":
    obs = start_monitor()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        obs.stop()
    obs.join()
