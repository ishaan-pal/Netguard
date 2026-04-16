import sqlite3
import json
from datetime import datetime

DB_PATH = "netguard.db"

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ip         TEXT UNIQUE,
            mac        TEXT,
            hostname   TEXT,
            os         TEXT,
            vendor     TEXT,
            first_seen TEXT,
            last_seen  TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            device_ip       TEXT,
            final_score     INTEGER,
            ai_score        INTEGER,
            rule_score      INTEGER,
            severity        TEXT,
            explanation     TEXT,
            remediation     TEXT,
            rule_reasons    TEXT,
            ports           TEXT,
            port_analysis   TEXT,
            dangerous_ports TEXT,
            shodan_tags     TEXT,
            shodan_summary  TEXT,
            cves            TEXT,
            timestamp       TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            device_ip TEXT,
            severity  TEXT,
            message   TEXT,
            is_read   INTEGER DEFAULT 0,
            timestamp TEXT
        )
    """)

    # scan_sessions — one row per full scan cycle
    c.execute("""
        CREATE TABLE IF NOT EXISTS scan_sessions (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            subnet     TEXT,
            started_at TEXT,
            ended_at   TEXT
        )
    """)
    # Migrate existing DB — add subnet column if missing
    try:
        c.execute("ALTER TABLE scan_sessions ADD COLUMN subnet TEXT")
    except Exception:
        pass  # Column already exists

    # Links devices to sessions — drives get_live_devices()
    c.execute("""
        CREATE TABLE IF NOT EXISTS session_devices (
            session_id INTEGER,
            device_ip  TEXT,
            PRIMARY KEY (session_id, device_ip)
        )
    """)

    conn.commit()
    conn.close()


def upsert_device(device: dict):
    conn = get_conn()
    now  = datetime.now().isoformat()
    conn.execute("""
        INSERT INTO devices (ip, mac, hostname, os, vendor, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
            mac=excluded.mac, hostname=excluded.hostname,
            os=excluded.os, vendor=excluded.vendor,
            last_seen=excluded.last_seen
    """, (
        device["ip"], device.get("mac", ""), device.get("hostname", ""),
        device.get("os", ""), json.dumps(device.get("vendor", {})), now, now
    ))
    conn.commit()
    conn.close()


def save_scan(device_ip: str, result: dict):
    conn = get_conn()
    conn.execute("""
        INSERT INTO scans
        (device_ip, final_score, ai_score, rule_score, severity,
         explanation, remediation, rule_reasons, ports, port_analysis,
         dangerous_ports, shodan_tags, shodan_summary, cves, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        device_ip,
        result["final_score"],
        result["ai_score"],
        result["rule_score"],
        result["severity"],
        result["explanation"],
        result["remediation"],
        json.dumps(result.get("rule_reasons",    [])),
        json.dumps(result.get("ports",           [])),
        json.dumps(result.get("port_analysis",   [])),
        json.dumps(result.get("dangerous_ports", [])),
        json.dumps(result.get("shodan_tags",     [])),
        result.get("shodan_summary", ""),
        json.dumps(result.get("cves",            [])),
        datetime.now().isoformat()
    ))
    conn.commit()
    conn.close()


def save_alert(device_ip: str, severity: str, message: str):
    conn = get_conn()
    conn.execute(
        "INSERT INTO alerts (device_ip, severity, message, timestamp) VALUES (?,?,?,?)",
        (device_ip, severity, message, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()


def start_scan_session(subnet: str = "") -> int:
    """Create a new scan session. Called at start of every scan cycle."""
    conn   = get_conn()
    cursor = conn.execute(
        "INSERT INTO scan_sessions (subnet, started_at) VALUES (?, ?)",
        (subnet, datetime.now().isoformat())
    )
    session_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return session_id


def end_scan_session(session_id: int):
    """Mark session complete. get_live_devices() uses completed sessions only."""
    conn = get_conn()
    conn.execute(
        "UPDATE scan_sessions SET ended_at = ? WHERE id = ?",
        (datetime.now().isoformat(), session_id)
    )
    conn.commit()
    conn.close()


def tag_device_to_session(device_ip: str, session_id: int):
    """Link a discovered device to its scan session."""
    conn = get_conn()
    conn.execute(
        "INSERT OR IGNORE INTO session_devices (session_id, device_ip) VALUES (?,?)",
        (session_id, device_ip)
    )
    conn.commit()
    conn.close()


def get_live_devices(subnet: str = "") -> list:
    """
    Return ONLY devices found in the most recent completed scan session
    for the given subnet.

    This means:
    - If a device disconnects it won't appear next scan
    - If the user switches networks all old devices disappear
    - Dashboard always reflects current network state only
    """
    conn = get_conn()

    # Find most recent completed session for this subnet
    if subnet:
        row = conn.execute("""
            SELECT id FROM scan_sessions
            WHERE ended_at IS NOT NULL AND subnet = ?
            ORDER BY ended_at DESC LIMIT 1
        """, (subnet,)).fetchone()
    else:
        row = conn.execute("""
            SELECT id FROM scan_sessions
            WHERE ended_at IS NOT NULL
            ORDER BY ended_at DESC LIMIT 1
        """).fetchone()

    if not row:
        conn.close()
        return []

    session_id = row["id"]

    rows = conn.execute("""
        SELECT d.*,
               s.final_score, s.severity, s.explanation, s.remediation,
               s.ports, s.port_analysis, s.dangerous_ports,
               s.shodan_tags, s.shodan_summary, s.rule_reasons, s.cves,
               s.timestamp as last_scanned
        FROM devices d
        INNER JOIN session_devices sd ON sd.device_ip = d.ip
        LEFT JOIN scans s ON s.device_ip = d.ip
            AND s.timestamp = (
                SELECT MAX(timestamp) FROM scans WHERE device_ip = d.ip
            )
        WHERE sd.session_id = ?
    """, (session_id,)).fetchall()

    conn.close()
    return [dict(r) for r in rows]


def get_device_history(ip: str) -> list:
    """Return last 20 scan scores for a device — used for trend graph."""
    conn = get_conn()
    rows = conn.execute("""
        SELECT final_score, severity, timestamp FROM scans
        WHERE device_ip = ? ORDER BY timestamp DESC LIMIT 20
    """, (ip,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_unread_alerts() -> list:
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM alerts WHERE is_read = 0 ORDER BY timestamp DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def mark_alerts_read():
    conn = get_conn()
    conn.execute("UPDATE alerts SET is_read = 1")
    conn.commit()
    conn.close()

def get_device_by_ip(ip: str) -> dict | None:
    """Return the devices row for a single IP, or None if not found."""
    conn = get_conn()
    row  = conn.execute(
        "SELECT * FROM devices WHERE ip = ?", (ip,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None
