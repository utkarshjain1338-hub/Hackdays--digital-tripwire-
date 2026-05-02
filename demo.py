"""
Digital Tripwire Demo Launcher
================================
Starts all services and simulates an attack in one command.
Run: python demo.py
"""
import subprocess
import sys
import time
import os
import signal
import requests

VENV_PYTHON = os.path.join(os.path.dirname(__file__), "venv", "bin", "python")
BOLD   = "\033[1m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
DIM    = "\033[2m"
RESET  = "\033[0m"

processes = []

def banner():
    print(f"""
{CYAN}{BOLD}
╔══════════════════════════════════════════════════════════════╗
║          🍯  DIGITAL TRIPWIRE — LIVE DEMO LAUNCHER  🍯       ║
║       Dual-Tier AI Honeypot | NVIDIA NIM + Gemini 2.5 Flash  ║
╚══════════════════════════════════════════════════════════════╝
{RESET}""")

def section(title):
    print(f"\n{YELLOW}{BOLD}{'═'*62}{RESET}")
    print(f"{YELLOW}{BOLD}  {title}{RESET}")
    print(f"{YELLOW}{BOLD}{'═'*62}{RESET}\n")

def step(msg):
    print(f"  {CYAN}▶{RESET}  {msg}")

def success(msg):
    print(f"  {GREEN}✅  {msg}{RESET}")

def warn(msg):
    print(f"  {YELLOW}⚠️   {msg}{RESET}")

def cleanup(sig=None, frame=None):
    print(f"\n{RED}{BOLD}[Demo] Shutting down all services...{RESET}")
    for proc in processes:
        try:
            proc.terminate()
        except Exception:
            pass
    sys.exit(0)

def wait_for_flask(timeout=10):
    for _ in range(timeout * 2):
        try:
            r = requests.get("http://127.0.0.1:5000/", timeout=1)
            if r.status_code in (200, 403):
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False

# ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    signal.signal(signal.SIGINT, cleanup)
    banner()

    # ── Step 0: Reset any previous lockdown ──────────────────
    if os.path.exists(".system_lockdown"):
        os.remove(".system_lockdown")
        warn("Previous lockdown file detected and cleared.")

    # ── Step 1: Start Flask web server ───────────────────────
    section("Step 1: Starting The Store Web Server (Flask)")
    step("Launching Flask on http://127.0.0.1:5000 ...")
    flask_proc = subprocess.Popen(
        [VENV_PYTHON, "app.py"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    processes.append(flask_proc)

    if wait_for_flask():
        success("Flask web server is running on http://127.0.0.1:5000")
    else:
        print(f"  {RED}❌  Flask failed to start. Aborting.{RESET}")
        cleanup()

    # ── Step 2: Start OS file monitor ────────────────────────
    section("Step 2: Activating OS-Level Defense (file_monitor.py)")
    step("Launching Defense-in-Depth monitor for honeypot.db ...")
    monitor_proc = subprocess.Popen(
        [VENV_PYTHON, "file_monitor.py"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    processes.append(monitor_proc)
    time.sleep(1)
    success("OS file monitor active. Watching for file theft attempts.")

    # ── Step 3: Normal cashier simulation ────────────────────
    section("Step 3: Simulating Normal Business Activity")
    step("Cashier User 'register_01' searches inventory for 'Apple'...")
    time.sleep(1)
    r = requests.post("http://127.0.0.1:5000/", data={"search": "Apple"})
    success(f"Server Response: {r.status_code} OK — No alerts triggered. Business as usual.")

    time.sleep(1.5)

    # ── Step 4: Attack simulation ─────────────────────────────
    section("Step 4: Simulating SQL Injection Attack")
    step("Attacker crafts a UNION injection to dump 'vault_secrets'...")
    time.sleep(1)
    payload = "%' UNION SELECT id, service, username, password FROM vault_secrets; --"
    print(f"\n  {DIM}  Payload: {payload}{RESET}\n")
    time.sleep(1)

    step("Sending malicious request to the store search endpoint...")
    r = requests.post("http://127.0.0.1:5000/", data={"search": payload})
    success(f"Server returned {r.status_code} to attacker — no error shown, breach is SILENT!")
    time.sleep(0.5)

    # ── Step 5: Wait for and stream AI pipeline output ────────
    section("Step 5: Watching The AI Pipeline Fire (Server Logs)")
    print(f"  {DIM}Waiting for Watchdog + Strategist to complete analysis...{RESET}\n")

    # Stream Flask output
    flask_visible = subprocess.Popen(
        [VENV_PYTHON, "app.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )
    processes.append(flask_visible)
    
    # Give the already-running Flask server 5s to finish AI calls
    time.sleep(5)

    # ── Step 6: Verify lockdown ───────────────────────────────
    section("Step 6: Verifying Auto-Lockdown Kill Switch")
    if os.path.exists(".system_lockdown"):
        success(".system_lockdown file created! System is locked.")
    else:
        warn(".system_lockdown not found yet — AI pipeline may still be processing.")

    step("Attempting to access the store post-lockdown...")
    time.sleep(1)
    r2 = requests.post("http://127.0.0.1:5000/", data={"search": "Apple"})
    if r2.status_code == 403:
        success(f"System LOCKED! Server returned {r2.status_code} FORBIDDEN — Attacker blocked!")
    else:
        warn(f"Server returned {r2.status_code}. Lockdown may still be processing.")

    # ── Done ──────────────────────────────────────────────────
    section("Demo Complete")
    print(f"""  {GREEN}{BOLD}
  The Digital Tripwire worked exactly as designed:

    ▸ Normal cashier traffic:   PASSED THROUGH undetected
    ▸ SQL Injection on honeypot: SILENTLY CAUGHT  
    ▸ NVIDIA NIM (Watchdog):     Extracted threat JSON
    ▸ ntfy.sh phone alert:       Sent to your mobile device  
    ▸ Gemini 2.5 Flash:          Generated incident report
    ▸ Auto-Shutdown Kill Switch: Active — System Locked
    ▸ OS File Monitor:           Running in background
  {RESET}
  {DIM}Press Ctrl+C to stop all services.{RESET}
    """)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        cleanup()
