"""
Behavioral Anomaly Detection Engine
=====================================
Tracks per-IP query behavior and flags insider threats using
Z-score analysis and rule-based detection. Fires SocketIO events
when anomalies are detected.
"""
import time
from collections import defaultdict, deque
from datetime import datetime
import statistics

# ── In-memory stores ──────────────────────────────────────────
# Per-IP circular buffer of (timestamp, table, query_type, row_count)
_query_log = defaultdict(lambda: deque(maxlen=500))

# Per-IP query count per minute (rolling)
_rate_log = defaultdict(list)

# Global incident log (shown in dashboard)
incident_log = []

# SocketIO instance injected by app.py at startup
_socketio = None

ANOMALY_COOLDOWN = {}  # ip -> last_anomaly_time (rate-limit anomaly alerts)
COOLDOWN_SECONDS = 30

# ── Config ─────────────────────────────────────────────────────
VOLUME_SPIKE_FACTOR = 3.0   # alert if current rate > 3x normal
AFTER_HOURS_START = 23      # 11 PM
AFTER_HOURS_END = 5         # 5 AM
MASS_EXPORT_THRESHOLD = 500 # rows returned in one query


def set_socketio(sio):
    global _socketio
    _socketio = sio


def _is_rate_limited(ip):
    now = time.time()
    last = ANOMALY_COOLDOWN.get(ip, 0)
    if now - last < COOLDOWN_SECONDS:
        return True
    ANOMALY_COOLDOWN[ip] = now
    return False


def _get_query_type(query):
    q = query.strip().upper()
    if q.startswith("SELECT"): return "SELECT"
    if q.startswith("INSERT"): return "INSERT"
    if q.startswith("UPDATE"): return "UPDATE"
    if q.startswith("DELETE"): return "DELETE"
    return "OTHER"


def _extract_table(query):
    """Best-effort table name extraction."""
    tokens = query.upper().split()
    for kw in ("FROM", "INTO", "UPDATE", "TABLE"):
        if kw in tokens:
            idx = tokens.index(kw)
            if idx + 1 < len(tokens):
                return tokens[idx + 1].strip(";(),").lower()
    return "unknown"


def log_query(ip, query, row_count=0):
    """
    Called on every SQL query. Logs it and checks for anomalies.
    Returns (is_anomaly: bool, reason: str)
    """
    now = time.time()
    table = _extract_table(query)
    qtype = _get_query_type(query)
    hour = datetime.now().hour

    # Store the event
    _query_log[ip].append({
        "ts": now,
        "table": table,
        "type": qtype,
        "query": query[:200],
        "row_count": row_count,
    })
    _rate_log[ip].append(now)

    # Prune rate log to last 60 seconds
    _rate_log[ip] = [t for t in _rate_log[ip] if now - t < 60]

    # Emit live query event to dashboard
    if _socketio:
        _socketio.emit("new_query", {
            "ip": ip,
            "table": table,
            "type": qtype,
            "query": query[:120],
            "ts": datetime.now().strftime("%H:%M:%S"),
            "risk": "critical" if "vault_secrets" in query.lower() else "normal",
        })

    # ── Anomaly Rules ──────────────────────────────────────────

    # Rule 1: After-hours access
    if hour >= AFTER_HOURS_START or hour < AFTER_HOURS_END:
        reason = f"After-hours database access at {datetime.now().strftime('%H:%M')} from {ip}"
        return _fire_anomaly(ip, query, reason, "AFTER_HOURS")

    # Rule 2: Mass export (high row count)
    if row_count >= MASS_EXPORT_THRESHOLD:
        reason = f"Mass data export: {row_count} rows returned in one query from {ip}"
        return _fire_anomaly(ip, query, reason, "MASS_EXPORT")

    # Rule 3: Volume spike (Z-score based)
    history = _query_log[ip]
    if len(history) >= 20:
        current_rate = len(_rate_log[ip])  # queries in last 60s
        # Build historical per-minute rates (sample from deque)
        past_rates = []
        window_start = now - 600  # last 10 minutes
        bucket = defaultdict(int)
        for evt in history:
            if evt["ts"] > window_start:
                minute_key = int((evt["ts"] - window_start) // 60)
                bucket[minute_key] += 1
        past_rates = list(bucket.values())

        if len(past_rates) >= 3:
            avg = statistics.mean(past_rates)
            if avg > 0 and current_rate > avg * VOLUME_SPIKE_FACTOR:
                reason = f"Volume spike from {ip}: {current_rate} queries/min (avg: {avg:.1f})"
                return _fire_anomaly(ip, query, reason, "VOLUME_SPIKE")

    # Rule 4: Table enumeration (many distinct tables in short time)
    recent = [e for e in history if now - e["ts"] < 10]
    distinct_tables = set(e["table"] for e in recent)
    if len(distinct_tables) >= 5:
        reason = f"Table enumeration from {ip}: {len(distinct_tables)} tables probed in 10 seconds"
        return _fire_anomaly(ip, query, reason, "TABLE_ENUM")

    return False, ""


def _fire_anomaly(ip, query, reason, rule_id):
    """Registers an anomaly incident and emits a SocketIO alert."""
    if _is_rate_limited(ip):
        return False, ""

    print(f"\n[Anomaly] ⚠️  {rule_id}: {reason}")

    incident = {
        "id": len(incident_log) + 1,
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "rule": rule_id,
        "reason": reason,
        "query": query[:300],
        "type": "anomaly",
        "ai_report": None,
    }
    incident_log.append(incident)

    if _socketio:
        _socketio.emit("anomaly_detected", {
            "incident": incident,
        })

    return True, reason


def add_honeypot_incident(ip, query, ai_report="Pending AI analysis..."):
    """Called by database.py when the honeypot table is accessed."""
    incident = {
        "id": len(incident_log) + 1,
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "rule": "HONEYPOT_TRIPPED",
        "reason": "Honeypot table 'vault_secrets' was accessed — confirmed breach attempt.",
        "query": query[:300],
        "type": "critical",
        "ai_report": ai_report,
    }
    incident_log.append(incident)

    if _socketio:
        _socketio.emit("honeypot_tripped", {"incident": incident})
