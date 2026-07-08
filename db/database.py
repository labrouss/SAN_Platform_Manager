"""
import sys as _sys, os as _os
from pathlib import Path as _Path
_here = _Path(__file__).resolve().parent
# Walk up to find app root (directory containing db/ and services/)
_root = _here
for _ in range(3):
    if (_root / 'db').is_dir() and (_root / 'services').is_dir():
        break
    _root = _root.parent
if str(_root) not in _sys.path:
    _sys.path.insert(0, str(_root))

database.py -- SQLite schema, migrations, and data-access helpers.
All persistence goes through this module; no other file touches SQLite directly.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# -- paths ----------------------------------------------------------------------
APP_DIR = Path.home() / ".san-platform"
APP_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = APP_DIR / "san_platform.db"

# -- connection helper ----------------------------------------------------------
def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

@contextmanager
def get_db():
    conn = _get_conn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

# -- schema ---------------------------------------------------------------------
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY);

CREATE TABLE IF NOT EXISTS app_settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    email         TEXT UNIQUE NOT NULL,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'OPERATOR',
    is_active     INTEGER NOT NULL DEFAULT 1,
    last_login_at TEXT,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS switches (
    id           TEXT PRIMARY KEY,
    ip_address   TEXT UNIQUE NOT NULL,
    hostname     TEXT,
    display_name TEXT,
    notes        TEXT,
    serial_number TEXT,
    model        TEXT,
    nxos_version TEXT,
    is_active    INTEGER NOT NULL DEFAULT 1,
    last_seen_at TEXT,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vsans (
    id          TEXT PRIMARY KEY,
    switch_id   TEXT NOT NULL REFERENCES switches(id) ON DELETE CASCADE,
    vsan_id     INTEGER NOT NULL,
    name        TEXT,
    state       TEXT DEFAULT 'active',
    synced_at   TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    UNIQUE(switch_id, vsan_id)
);
CREATE INDEX IF NOT EXISTS idx_vsans_switch ON vsans(switch_id);

CREATE TABLE IF NOT EXISTS fc_aliases (
    id          TEXT PRIMARY KEY,
    switch_id   TEXT NOT NULL REFERENCES switches(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    wwn         TEXT NOT NULL,
    description TEXT,
    synced_at   TEXT,
    is_orphaned INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    UNIQUE(switch_id, wwn),
    UNIQUE(switch_id, name)
);
CREATE INDEX IF NOT EXISTS idx_fc_aliases_switch ON fc_aliases(switch_id);

CREATE TABLE IF NOT EXISTS zones (
    id          TEXT PRIMARY KEY,
    switch_id   TEXT NOT NULL REFERENCES switches(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    vsan_id     INTEGER NOT NULL,
    description TEXT,
    is_draft    INTEGER NOT NULL DEFAULT 1,
    synced_at   TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    UNIQUE(switch_id, name, vsan_id)
);
CREATE INDEX IF NOT EXISTS idx_zones_switch_vsan ON zones(switch_id, vsan_id);

CREATE TABLE IF NOT EXISTS zone_members (
    id          TEXT PRIMARY KEY,
    zone_id     TEXT NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
    member_type TEXT NOT NULL DEFAULT 'PWWN',
    value       TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    UNIQUE(zone_id, value)
);

CREATE TABLE IF NOT EXISTS zone_sets (
    id           TEXT PRIMARY KEY,
    switch_id    TEXT NOT NULL REFERENCES switches(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    vsan_id      INTEGER NOT NULL,
    is_active    INTEGER NOT NULL DEFAULT 0,
    is_draft     INTEGER NOT NULL DEFAULT 1,
    activated_at TEXT,
    synced_at    TEXT,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    UNIQUE(switch_id, name, vsan_id)
);
CREATE INDEX IF NOT EXISTS idx_zone_sets_switch ON zone_sets(switch_id, vsan_id, is_active);

CREATE TABLE IF NOT EXISTS zone_set_members (
    zone_set_id TEXT NOT NULL REFERENCES zone_sets(id) ON DELETE CASCADE,
    zone_id     TEXT NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
    added_at    TEXT NOT NULL,
    PRIMARY KEY(zone_set_id, zone_id)
);

CREATE TABLE IF NOT EXISTS zoning_snapshots (
    id           TEXT PRIMARY KEY,
    switch_id    TEXT NOT NULL REFERENCES switches(id) ON DELETE CASCADE,
    vsan_id      INTEGER NOT NULL,
    trigger      TEXT NOT NULL DEFAULT 'MANUAL',
    payload      TEXT NOT NULL,
    diff_summary TEXT,
    triggered_by TEXT,
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snapshots_switch ON zoning_snapshots(switch_id, vsan_id, created_at);

CREATE TABLE IF NOT EXISTS port_metrics (
    id             TEXT PRIMARY KEY,
    timestamp      TEXT NOT NULL,
    switch_id      TEXT NOT NULL REFERENCES switches(id) ON DELETE CASCADE,
    interface_name TEXT NOT NULL,
    tx_bytes       INTEGER NOT NULL DEFAULT 0,
    rx_bytes       INTEGER NOT NULL DEFAULT 0,
    crc_errors     INTEGER NOT NULL DEFAULT 0,
    link_failures  INTEGER NOT NULL DEFAULT 0,
    tx_rate_bps    REAL,
    rx_rate_bps    REAL,
    rx_power_dbm   REAL,
    tx_power_dbm   REAL,
    temperature    REAL,
    voltage        REAL,
    current_ma     REAL
);
CREATE INDEX IF NOT EXISTS idx_metrics_switch_iface ON port_metrics(switch_id, interface_name, timestamp);
"""

def init_db() -> None:
    """Create all tables and seed default admin user."""
    import hashlib
    with get_db() as conn:
        conn.executescript(SCHEMA_SQL)
        # Always ensure admin user exists with correct credentials.
        # Using INSERT OR IGNORE then UPDATE so existing data is preserved
        # but admin password is always reset to default on fresh installs.
        now = _now()
        pw_hash = hashlib.sha256(b"Admin1234!").hexdigest()
        existing = conn.execute("SELECT id FROM users WHERE username=?", ("admin",)).fetchone()
        if existing is None:
            conn.execute(
                "INSERT INTO users(id,email,username,password_hash,role,is_active,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), "admin@san.local", "admin", pw_hash, "ADMIN", 1, now, now)
            )
        else:
            # Reset password to default in case it got corrupted in a previous run
            conn.execute(
                "UPDATE users SET password_hash=?, is_active=1, updated_at=? WHERE username=?",
                (pw_hash, now, "admin")
            )
        # Seed default settings
        defaults = {
            "simulate_mode": "false",
            "poll_interval_sec": "60",
            "jwt_secret": "san-platform-default-secret",
            "theme": "dark",
        }
        for k, v in defaults.items():
            conn.execute("INSERT OR IGNORE INTO app_settings(key,value) VALUES(?,?)", (k, v))


# -- helpers --------------------------------------------------------------------
def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return dict(row)

# -- SETTINGS -------------------------------------------------------------------
def get_setting(key: str, default: str = "") -> str:
    with get_db() as conn:
        row = conn.execute("SELECT value FROM app_settings WHERE key=?", (key,)).fetchone()
        return row[0] if row else default

def set_setting(key: str, value: str) -> None:
    with get_db() as conn:
        conn.execute("INSERT OR REPLACE INTO app_settings(key,value) VALUES(?,?)", (key, value))

def get_all_settings() -> dict[str, str]:
    with get_db() as conn:
        rows = conn.execute("SELECT key,value FROM app_settings").fetchall()
        return {r[0]: r[1] for r in rows}

# -- USERS ----------------------------------------------------------------------
def get_user_by_username(username: str) -> dict | None:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE username=? AND is_active=1", (username,)).fetchone()
        return row_to_dict(row) if row else None

def get_all_users() -> list[dict]:
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM users ORDER BY username").fetchall()
        return [row_to_dict(r) for r in rows]

def create_user(email: str, username: str, pw_hash: str, role: str) -> dict:
    now = _now()
    uid = str(uuid.uuid4())
    with get_db() as conn:
        conn.execute(
            "INSERT INTO users(id,email,username,password_hash,role,is_active,created_at,updated_at) VALUES(?,?,?,?,?,1,?,?)",
            (uid, email, username, pw_hash, role, now, now)
        )
        row = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        return row_to_dict(row)

def update_user(uid: str, **kwargs) -> dict | None:
    allowed = {"email", "password_hash", "role", "is_active", "last_login_at"}
    fields = {k: v for k, v in kwargs.items() if k in allowed}
    if not fields:
        return None
    fields["updated_at"] = _now()
    sets = ", ".join(f"{k}=?" for k in fields)
    vals = list(fields.values()) + [uid]
    with get_db() as conn:
        conn.execute(f"UPDATE users SET {sets} WHERE id=?", vals)
        row = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        return row_to_dict(row) if row else None

def delete_user(uid: str) -> bool:
    with get_db() as conn:
        conn.execute("DELETE FROM users WHERE id=?", (uid,))
        return True

# -- SWITCHES -------------------------------------------------------------------
def get_all_switches() -> list[dict]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT s.*, "
            " (SELECT COUNT(*) FROM fc_aliases WHERE switch_id=s.id) AS alias_count,"
            " (SELECT COUNT(*) FROM zones WHERE switch_id=s.id) AS zone_count,"
            " (SELECT COUNT(*) FROM zone_sets WHERE switch_id=s.id) AS zone_set_count,"
            " (SELECT COUNT(*) FROM port_metrics WHERE switch_id=s.id) AS metric_count"
            " FROM switches s WHERE s.is_active=1 ORDER BY s.hostname"
        ).fetchall()
        return [row_to_dict(r) for r in rows]

def get_switch(switch_id: str) -> dict | None:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM switches WHERE id=?", (switch_id,)).fetchone()
        return row_to_dict(row) if row else None

def create_switch(ip: str, hostname: str = "", display_name: str = "", model: str = "",
                  serial: str = "", notes: str = "") -> dict:
    now = _now()
    sid = str(uuid.uuid4())
    with get_db() as conn:
        conn.execute(
            "INSERT INTO switches(id,ip_address,hostname,display_name,model,serial_number,notes,is_active,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,1,?,?)",
            (sid, ip, hostname or None, display_name or None, model or None, serial or None, notes or None, now, now)
        )
        row = conn.execute("SELECT * FROM switches WHERE id=?", (sid,)).fetchone()
        return row_to_dict(row)

def update_switch(switch_id: str, **kwargs) -> dict | None:
    allowed = {"hostname", "display_name", "model", "nxos_version", "is_active",
               "notes", "last_seen_at", "serial_number"}
    fields = {k: v for k, v in kwargs.items() if k in allowed}
    if not fields:
        return None
    fields["updated_at"] = _now()
    sets = ", ".join(f"{k}=?" for k in fields)
    vals = list(fields.values()) + [switch_id]
    with get_db() as conn:
        conn.execute(f"UPDATE switches SET {sets} WHERE id=?", vals)
        row = conn.execute("SELECT * FROM switches WHERE id=?", (switch_id,)).fetchone()
        return row_to_dict(row) if row else None

def delete_switch(switch_id: str) -> bool:
    with get_db() as conn:
        conn.execute("DELETE FROM switches WHERE id=?", (switch_id,))
        return True

# -- VSANS ------------------------------------------------------------------------
def get_vsans(switch_id: str) -> list[dict]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM vsans WHERE switch_id=? ORDER BY vsan_id", (switch_id,)
        ).fetchall()
        return [row_to_dict(r) for r in rows]


def replace_vsans(switch_id: str, vsans: list[dict]) -> list[dict]:
    """Replace all VSANs for a switch with a freshly-synced list (upsert by vsan_id)."""
    now = _now()
    with get_db() as conn:
        existing = {r["vsan_id"]: r["id"] for r in
                    conn.execute("SELECT id, vsan_id FROM vsans WHERE switch_id=?", (switch_id,)).fetchall()}
        seen_ids = set()
        for v in vsans:
            vid = int(v["vsan_id"])
            if vid in existing:
                conn.execute(
                    "UPDATE vsans SET name=?, state=?, synced_at=?, updated_at=? WHERE id=?",
                    (v.get("name"), v.get("state", "active"), now, now, existing[vid])
                )
                seen_ids.add(existing[vid])
            else:
                new_id = str(uuid.uuid4())
                conn.execute(
                    "INSERT INTO vsans(id,switch_id,vsan_id,name,state,synced_at,created_at,updated_at) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    (new_id, switch_id, vid, v.get("name"), v.get("state", "active"), now, now, now)
                )
                seen_ids.add(new_id)
    return get_vsans(switch_id)


# -- FC ALIASES -----------------------------------------------------------------
def get_aliases(switch_id: str) -> list[dict]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM fc_aliases WHERE switch_id=? ORDER BY name", (switch_id,)
        ).fetchall()
        return [row_to_dict(r) for r in rows]

def create_alias(switch_id: str, name: str, wwn: str, description: str = "",
                 is_orphaned: bool = False) -> dict:
    now = _now()
    aid = str(uuid.uuid4())
    with get_db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO fc_aliases(id,switch_id,name,wwn,description,is_orphaned,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (aid, switch_id, name, wwn.lower(), description or None, 1 if is_orphaned else 0, now, now)
        )
        row = conn.execute("SELECT * FROM fc_aliases WHERE id=?", (aid,)).fetchone()
        return row_to_dict(row)

def update_alias(alias_id: str, **kwargs) -> dict | None:
    allowed = {"name", "wwn", "description", "synced_at", "is_orphaned"}
    fields = {k: v for k, v in kwargs.items() if k in allowed}
    if not fields:
        return None
    fields["updated_at"] = _now()
    sets = ", ".join(f"{k}=?" for k in fields)
    vals = list(fields.values()) + [alias_id]
    with get_db() as conn:
        conn.execute(f"UPDATE fc_aliases SET {sets} WHERE id=?", vals)
        row = conn.execute("SELECT * FROM fc_aliases WHERE id=?", (alias_id,)).fetchone()
        return row_to_dict(row) if row else None

def delete_alias(alias_id: str) -> bool:
    with get_db() as conn:
        conn.execute("DELETE FROM fc_aliases WHERE id=?", (alias_id,))
        return True

# -- ZONES ----------------------------------------------------------------------
def get_zones(switch_id: str, vsan_id: int | None = None) -> list[dict]:
    with get_db() as conn:
        if vsan_id is not None:
            rows = conn.execute(
                "SELECT z.*, GROUP_CONCAT(zm.value,'|') AS member_values, "
                " GROUP_CONCAT(zm.member_type,'|') AS member_types "
                " FROM zones z LEFT JOIN zone_members zm ON zm.zone_id=z.id "
                " WHERE z.switch_id=? AND z.vsan_id=? GROUP BY z.id ORDER BY z.name",
                (switch_id, vsan_id)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT z.*, GROUP_CONCAT(zm.value,'|') AS member_values, "
                " GROUP_CONCAT(zm.member_type,'|') AS member_types "
                " FROM zones z LEFT JOIN zone_members zm ON zm.zone_id=z.id "
                " WHERE z.switch_id=? GROUP BY z.id ORDER BY z.name",
                (switch_id,)
            ).fetchall()
        result = []
        for r in rows:
            d = row_to_dict(r)
            vals = d.pop("member_values", "") or ""
            types = d.pop("member_types", "") or ""
            members = []
            if vals:
                for v, t in zip(vals.split("|"), types.split("|")):
                    members.append({"value": v, "member_type": t})
            d["members"] = members
            result.append(d)
        return result

def create_zone(switch_id: str, name: str, vsan_id: int,
                description: str = "", is_draft: bool = True) -> dict:
    now = _now()
    zid = str(uuid.uuid4())
    with get_db() as conn:
        conn.execute(
            "INSERT INTO zones(id,switch_id,name,vsan_id,description,is_draft,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (zid, switch_id, name, vsan_id, description or None, 1 if is_draft else 0, now, now)
        )
        row = conn.execute("SELECT * FROM zones WHERE id=?", (zid,)).fetchone()
        return row_to_dict(row)

def update_zone(zone_id: str, **kwargs) -> dict | None:
    allowed = {"name", "description", "is_draft", "synced_at"}
    fields = {k: v for k, v in kwargs.items() if k in allowed}
    if not fields:
        return None
    fields["updated_at"] = _now()
    sets = ", ".join(f"{k}=?" for k in fields)
    vals = list(fields.values()) + [zone_id]
    with get_db() as conn:
        conn.execute(f"UPDATE zones SET {sets} WHERE id=?", vals)
        row = conn.execute("SELECT * FROM zones WHERE id=?", (zone_id,)).fetchone()
        return row_to_dict(row) if row else None

def delete_zone(zone_id: str) -> bool:
    with get_db() as conn:
        conn.execute("DELETE FROM zones WHERE id=?", (zone_id,))
        return True

def add_zone_member(zone_id: str, value: str, member_type: str = "PWWN") -> dict:
    now = _now()
    mid = str(uuid.uuid4())
    with get_db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO zone_members(id,zone_id,member_type,value,created_at) VALUES(?,?,?,?,?)",
            (mid, zone_id, member_type, value, now)
        )
    return {"zone_id": zone_id, "value": value, "member_type": member_type}

def remove_zone_member(zone_id: str, value: str) -> bool:
    with get_db() as conn:
        conn.execute("DELETE FROM zone_members WHERE zone_id=? AND value=?", (zone_id, value))
        return True

# -- ZONE SETS ------------------------------------------------------------------
def get_zone_sets(switch_id: str, vsan_id: int | None = None) -> list[dict]:
    with get_db() as conn:
        if vsan_id is not None:
            rows = conn.execute(
                "SELECT * FROM zone_sets WHERE switch_id=? AND vsan_id=? ORDER BY name",
                (switch_id, vsan_id)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM zone_sets WHERE switch_id=? ORDER BY name", (switch_id,)
            ).fetchall()
        result = []
        for r in rows:
            d = row_to_dict(r)
            members = conn.execute(
                "SELECT z.id, z.name FROM zone_set_members zsm "
                "JOIN zones z ON z.id=zsm.zone_id WHERE zsm.zone_set_id=?",
                (d["id"],)
            ).fetchall()
            d["zone_members"] = [row_to_dict(m) for m in members]
            result.append(d)
        return result

def create_zone_set(switch_id: str, name: str, vsan_id: int) -> dict:
    now = _now()
    zsid = str(uuid.uuid4())
    with get_db() as conn:
        conn.execute(
            "INSERT INTO zone_sets(id,switch_id,name,vsan_id,is_active,is_draft,created_at,updated_at) "
            "VALUES(?,?,?,?,0,1,?,?)",
            (zsid, switch_id, name, vsan_id, now, now)
        )
        row = conn.execute("SELECT * FROM zone_sets WHERE id=?", (zsid,)).fetchone()
        return row_to_dict(row)

def delete_zone_set(zs_id: str) -> bool:
    with get_db() as conn:
        conn.execute("DELETE FROM zone_sets WHERE id=?", (zs_id,))
        return True

def add_zone_to_set(zone_set_id: str, zone_id: str) -> None:
    now = _now()
    with get_db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO zone_set_members(zone_set_id,zone_id,added_at) VALUES(?,?,?)",
            (zone_set_id, zone_id, now)
        )

def remove_zone_from_set(zone_set_id: str, zone_id: str) -> None:
    with get_db() as conn:
        conn.execute(
            "DELETE FROM zone_set_members WHERE zone_set_id=? AND zone_id=?",
            (zone_set_id, zone_id)
        )

# -- SNAPSHOTS ------------------------------------------------------------------
def get_snapshots(switch_id: str, vsan_id: int | None = None, limit: int = 50) -> list[dict]:
    with get_db() as conn:
        if vsan_id is not None:
            rows = conn.execute(
                "SELECT id,switch_id,vsan_id,trigger,diff_summary,triggered_by,created_at "
                "FROM zoning_snapshots WHERE switch_id=? AND vsan_id=? "
                "ORDER BY created_at DESC LIMIT ?",
                (switch_id, vsan_id, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id,switch_id,vsan_id,trigger,diff_summary,triggered_by,created_at "
                "FROM zoning_snapshots WHERE switch_id=? ORDER BY created_at DESC LIMIT ?",
                (switch_id, limit)
            ).fetchall()
        return [row_to_dict(r) for r in rows]

def get_snapshot(snap_id: str) -> dict | None:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM zoning_snapshots WHERE id=?", (snap_id,)).fetchone()
        return row_to_dict(row) if row else None

def create_snapshot(switch_id: str, vsan_id: int, payload: Any,
                    trigger: str = "MANUAL", diff_summary: Any = None,
                    triggered_by: str = "") -> dict:
    now = _now()
    sid = str(uuid.uuid4())
    with get_db() as conn:
        conn.execute(
            "INSERT INTO zoning_snapshots(id,switch_id,vsan_id,trigger,payload,diff_summary,triggered_by,created_at) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (sid, switch_id, vsan_id, trigger,
             json.dumps(payload),
             json.dumps(diff_summary) if diff_summary else None,
             triggered_by, now)
        )
        row = conn.execute("SELECT * FROM zoning_snapshots WHERE id=?", (sid,)).fetchone()
        return row_to_dict(row)

# -- PORT METRICS ---------------------------------------------------------------
def insert_metric(switch_id: str, interface_name: str, **kwargs) -> None:
    now = _now()
    mid = str(uuid.uuid4())
    fields = {
        "tx_bytes": 0, "rx_bytes": 0, "crc_errors": 0, "link_failures": 0,
        "tx_rate_bps": None, "rx_rate_bps": None,
        "rx_power_dbm": None, "tx_power_dbm": None,
        "temperature": None, "voltage": None, "current_ma": None,
    }
    fields.update({k: v for k, v in kwargs.items() if k in fields})
    with get_db() as conn:
        conn.execute(
            "INSERT INTO port_metrics("
            "id,timestamp,switch_id,interface_name,"
            "tx_bytes,rx_bytes,crc_errors,link_failures,"
            "tx_rate_bps,rx_rate_bps,"
            "rx_power_dbm,tx_power_dbm,temperature,voltage,current_ma"
            ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (mid, now, switch_id, interface_name,
             fields["tx_bytes"], fields["rx_bytes"],
             fields["crc_errors"], fields["link_failures"],
             fields["tx_rate_bps"], fields["rx_rate_bps"],
             fields["rx_power_dbm"], fields["tx_power_dbm"],
             fields["temperature"], fields["voltage"], fields["current_ma"])
        )

def get_latest_metric(switch_id: str, interface_name: str) -> dict | None:
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM port_metrics WHERE switch_id=? AND interface_name=? "
            "ORDER BY timestamp DESC LIMIT 1",
            (switch_id, interface_name)
        ).fetchone()
        return row_to_dict(row) if row else None

def get_metrics_history(switch_id: str, interface_name: str,
                        hours: int = 24, limit: int = 500) -> list[dict]:
    cutoff = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM port_metrics "
            "WHERE switch_id=? AND interface_name=? "
            "ORDER BY timestamp DESC LIMIT ?",
            (switch_id, interface_name, limit)
        ).fetchall()
        return [row_to_dict(r) for r in reversed(rows)]

def get_top_ports(switch_id: str, limit: int = 10) -> list[dict]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT interface_name, "
            " AVG(tx_rate_bps) as avg_tx, AVG(rx_rate_bps) as avg_rx, "
            " MAX(crc_errors) as max_crc "
            "FROM port_metrics WHERE switch_id=? "
            "GROUP BY interface_name ORDER BY avg_tx DESC LIMIT ?",
            (switch_id, limit)
        ).fetchall()
        return [row_to_dict(r) for r in rows]

def get_distinct_interfaces(switch_id: str) -> list[str]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT DISTINCT interface_name FROM port_metrics WHERE switch_id=? ORDER BY interface_name",
            (switch_id,)
        ).fetchall()
        return [r[0] for r in rows]

def get_db_stats() -> dict:
    with get_db() as conn:
        return {
            "switches": conn.execute("SELECT COUNT(*) FROM switches WHERE is_active=1").fetchone()[0],
            "aliases":  conn.execute("SELECT COUNT(*) FROM fc_aliases").fetchone()[0],
            "zones":    conn.execute("SELECT COUNT(*) FROM zones").fetchone()[0],
            "zone_sets": conn.execute("SELECT COUNT(*) FROM zone_sets").fetchone()[0],
            "snapshots": conn.execute("SELECT COUNT(*) FROM zoning_snapshots").fetchone()[0],
            "users":    conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
            "metrics":  conn.execute("SELECT COUNT(*) FROM port_metrics").fetchone()[0],
        }
