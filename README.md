# 🍯 Digital Tripwire — AI-Powered Honeypot for Local Businesses

**Protect your sensitive data with an automated, dual-tier AI defense system.**

Digital Tripwire is a "Honeypot" system designed to trap attackers and insider threats. It plants fake, enticing data ("The Bait") inside your database. Since no legitimate user ever needs to access this data, any interaction with it is a 100% confirmed security breach.

The system features a **Dual-Tier AI Pipeline**:
1.  **Watchdog (NVIDIA NIM - Llama 3.1 8B):** Instantly classifies the threat and extracts technical details.
2.  **Strategist (Google Gemini 2.0 Flash):** Generates a plain-English emergency report, lockdown steps, and a code patch for the business owner.

---

## 🏗 Project Structure

The project has been reorganized into a modular, professional Python package:

```text
Honeypot/
├── run.py                 # Main entry point to launch the system
├── src/
│   ├── __init__.py        # Flask App Factory & SocketIO setup
│   ├── core/              # Core Logic (The Engines)
│   │   ├── database.py    # SQLite Tripwire & DB management
│   │   ├── detector.py    # Behavioral Anomaly Detection (Watchdog)
│   │   ├── alerter.py     # AI Analysis & Phone Notifications (Strategist)
│   │   └── monitor.py     # OS-Level File System Defense
│   ├── routes/            # Web Interfaces (Blueprints)
│   │   ├── store.py       # Public Storefront (The Honeypot)
│   │   └── dashboard.py   # Owner Dashboard & Internal APIs
│   └── templates/         # HTML Templates
├── scripts/               # Utility Scripts
│   ├── demo.py            # One-command full system demo
│   └── simulate_attack.py # Manual attack simulation
├── .env                   # Configuration & API Keys
└── requirements.txt       # Dependencies
```

---

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.8+
- [ntfy](https://ntfy.sh/) app installed on your phone (optional, for alerts)

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/utkarshjain1338-hub/Hackdays--digital-tripwire-
cd Honeypot

# Setup virtual environment
python -m venv venv
source venv/bin/activate  # Or source venv/bin/activate.fish for fish shell

# Install dependencies
pip install -r requirements.txt
```

### 3. Configuration
1. Create a `.env` file from the template:
   ```bash
   cp .env.example .env
   ```
2. Open `.env` and add your `GEMINI_API_KEY` and `NVIDIA_API_KEY`.
3. (Optional) Subscribe to the ntfy topic `digital_tripwire_7a9f21` on your phone.

### 4. Running the Demo
Launch the entire system, simulate normal behavior, and then a full SQL injection attack with one command:
```bash
python scripts/demo.py
```

---

## 🛡 How It Works

### The Tripwire
We use SQLite's `set_trace_callback()` to hook into every SQL query. If a query touches the `vault_secrets` table, the tripwire fires instantly.

### The Kill Switch
The moment a breach is detected, the system creates a `.system_lockdown` file. Our Flask app checks for this file before every request; if found, it blocks all non-admin traffic with a `403 Forbidden` error.

### Dual-Tier AI
- **NIM (Watchdog):** Fast, structured JSON extraction of threat data.
- **Gemini (Strategist):** Deep reasoning to explain the threat to a non-technical owner and provide actionable recovery steps.

### OS-Level Defense
A background process monitors the filesystem. If anyone tries to copy or move the database file directly (bypassing the web app), the system triggers the same alert and lockdown pipeline.

---

## 📈 Future Roadmap
- **Local AI:** Support for Ollama to run models entirely on-device with zero API costs.
- **Multi-DB Support:** Expand protection to PostgreSQL and MySQL via a proxy layer.
- **WhatsApp/SMS:** Direct alerts to standard messaging platforms.
- **Compliance Reporting:** Auto-generated GDPR/HIPAA breach notification reports.

---

## 📄 License
This project is open-source and intended for educational and security-demonstration purposes.
