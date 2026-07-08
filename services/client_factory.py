"""
import sys as _sys, os as _os
from pathlib import Path as _Path
_here = _Path(__file__).resolve().parent
_root = _here
for _ in range(3):
    if (_root / 'db').is_dir() and (_root / 'services').is_dir():
        break
    _root = _root.parent
if str(_root) not in _sys.path:
    _sys.path.insert(0, str(_root))

client_factory.py -- builds the right MDS client (real vs simulator).
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

from db import database as db
from services.mds_client import MdsClient
from services.mds_simulator import MdsSimulator


def _to_array(v: Any) -> list:
    if not v:
        return []
    return v if isinstance(v, list) else [v]


def is_sim() -> bool:
    return db.get_setting("simulate_mode", "false").lower() == "true"


def build_client(switch_id: str, ip_address: str):
    """Return simulator or real client based on app settings."""
    if is_sim():
        return MdsSimulator(ip_address)
    creds = _get_credentials(switch_id)
    port  = int(db.get_setting(f"switch_{switch_id}_port", "8443"))
    return MdsClient(ip_address, creds["username"], creds["password"], port=port)


def _get_credentials(switch_id: str) -> dict:
    username = db.get_setting(f"switch_{switch_id}_username") or db.get_setting("mds_username", "admin")
    password = db.get_setting(f"switch_{switch_id}_password") or db.get_setting("mds_password", "")
    return {"username": username, "password": password}


def store_credentials(switch_id: str, username: str, password: str, port: int = 8443) -> None:
    db.set_setting(f"switch_{switch_id}_username", username)
    db.set_setting(f"switch_{switch_id}_password", password)
    db.set_setting(f"switch_{switch_id}_port", str(port))


# -- Auth service --------------------------------------------------------------
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(password: str, pw_hash: str) -> bool:
    return hashlib.sha256(password.encode()).hexdigest() == pw_hash


def authenticate(username: str, password: str) -> dict | None:
    user = db.get_user_by_username(username)
    if not user:
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    db.update_user(user["id"], last_login_at=__import__("datetime").datetime.now().isoformat())
    return user


# -- Parsers -------------------------------------------------------------------
WWN_RE = re.compile(r"^([0-9a-f]{2}:){7}[0-9a-f]{2}$", re.I)


def is_valid_wwn(wwn: str) -> bool:
    return bool(WWN_RE.match(wwn.strip()))


def parse_device_aliases(body: dict) -> list[dict]:
    rows = _to_array(body.get("TABLE_device_alias_database", {}).get("ROW_device_alias_database"))
    return [{"name": r["dev_alias_name"].strip(), "wwn": r["pwwn"].strip().lower()} for r in rows
            if r.get("dev_alias_name") and r.get("pwwn")]


# -- VSAN: parse "show vsan" --------------------------------------------------
def parse_vsans(body: dict) -> list[dict]:
    """
    NX-API: show vsan
    Returns TABLE_vsan -> ROW_vsan list with vsan_id, vsan_name, vsan_state.
    """
    rows = _to_array(body.get("TABLE_vsan", {}).get("ROW_vsan"))
    result = []
    for r in rows:
        try:
            vid = int(r.get("vsan_id", 0))
        except (ValueError, TypeError):
            continue
        if not vid:
            continue
        result.append({
            "vsan_id":   vid,
            "name":      (r.get("vsan_name") or f"VSAN{vid}").strip(),
            "state":     (r.get("vsan_state") or "active").strip(),
            "interop":   (r.get("vsan_interoperability_mode") or "default").strip(),
        })
    return result


# -- Zone: parse "show zone vsan X" -------------------------------------------
def parse_zones(body: dict, vsan_id: int) -> list[dict]:
    """
    NX-API: show zone vsan <id>
    Returns TABLE_zone -> ROW_zone with zone_name and TABLE_zone_member.
    """
    zones = []
    for z_row in _to_array(body.get("TABLE_zone", {}).get("ROW_zone")):
        members = []
        for m in _to_array((z_row.get("TABLE_zone_member") or {}).get("ROW_zone_member")):
            # Keys vary: device_alias, wwn, fcid, symbolic_nodename
            if m.get("device_alias"):
                members.append({"type": "device_alias", "value": m["device_alias"].strip()})
            elif m.get("wwn"):
                members.append({"type": "pwwn", "value": m["wwn"].strip().lower()})
            elif m.get("fcid"):
                members.append({"type": "fcid", "value": m["fcid"].strip()})
        zones.append({
            "name":    (z_row.get("zone_name") or "").strip(),
            "vsan_id": vsan_id,
            "members": [m for m in members if m["value"]],
        })
    return zones


def parse_zone_sets(body: dict) -> list[dict]:
    """
    NX-API: show zoneset [vsan X]
    Returns TABLE_zoneset -> ROW_zoneset.
    """
    rows = _to_array(body.get("TABLE_zoneset", {}).get("ROW_zoneset"))
    result = []
    for zs_row in rows:
        zones = []
        for z_row in _to_array(zs_row.get("TABLE_zone", {}).get("ROW_zone")):
            members = []
            for m in _to_array((z_row.get("TABLE_zone_member") or {}).get("ROW_zone_member")):
                if m.get("device_alias"):
                    members.append({"type": "device_alias", "value": m["device_alias"].strip()})
                elif m.get("wwn"):
                    members.append({"type": "pwwn", "value": m["wwn"].strip().lower()})
                elif m.get("fcid"):
                    members.append({"type": "fcid", "value": m["fcid"].strip()})
            zones.append({
                "name":    (z_row.get("zone_name") or "").strip(),
                "members": [m for m in members if m["value"]],
            })
        try:
            vid = int(zs_row.get("zoneset_vsan", 0))
        except (ValueError, TypeError):
            vid = 0
        result.append({
            "name":      (zs_row.get("zoneset_name") or "").strip(),
            "vsan_id":   vid,
            "is_active": str(zs_row.get("zoneset_active", "")).lower() == "true",
            "zones":     zones,
        })
    return result


# -- Interface: parse "show interface brief" -----------------------------------
def parse_interface_brief(body: dict) -> list[dict]:
    """
    NX-API: show interface brief
    Returns TABLE_interface_brief_if -> ROW_interface_brief_if (FC ports only).
    Key fields: interface, vsan, admin_mode, status, oper_mode, oper_speed, fcot_info.
    """
    # NX-API may return either TABLE_interface_brief_if or TABLE_interface_brief
    rows = _to_array(
        body.get("TABLE_interface_brief_if", {}).get("ROW_interface_brief_if") or
        body.get("TABLE_interface_brief", {}).get("ROW_interface_brief")
    )
    result = []
    for r in rows:
        iface = (r.get("interface") or "").strip()
        if not iface.lower().startswith("fc"):
            continue
        try:
            vsan = int(r.get("vsan", 0) or 0)
        except (ValueError, TypeError):
            vsan = 0
        speed_raw = str(r.get("oper_speed") or r.get("speed") or "0").strip()
        # speed may be "8000", "8G", "8 Gbps" etc
        speed_clean = re.sub(r"[^0-9]", "", speed_raw)
        speed_mbps  = int(speed_clean) if speed_clean else 0
        # If speed is in Gbps (e.g. "8") convert to Mbps
        if speed_mbps and speed_mbps <= 256:
            speed_mbps *= 1000
        result.append({
            "name":     iface,
            "state":    (r.get("status") or r.get("oper_status") or "unknown").strip().lower(),
            "mode":     (r.get("oper_mode") or r.get("admin_mode") or "F").strip().upper(),
            "speed":    f"{speed_mbps // 1000}G" if speed_mbps else "--",
            "vsan_id":  vsan,
            "sfp":      (r.get("fcot_info") or "").strip().lower() not in ("absent", "--", ""),
        })
    return result


# -- SFP: parse "show interface transceiver" ----------------------------------
def parse_transceiver(body: dict) -> list[dict]:
    """
    NX-API: show interface transceiver
    TABLE_interface_transceiver -> ROW_interface_transceiver.
    Calibration data is in TABLE_calibration -> ROW_calibration.
    """
    rows = _to_array(
        body.get("TABLE_interface_transceiver", {}).get("ROW_interface_transceiver")
    )
    result = []
    for r in rows:
        iface = (r.get("interface") or "").strip()
        if not iface.lower().startswith("fc"):
            continue
        if (r.get("sfp") or "").strip().lower() == "absent":
            continue

        # Calibration block
        cal = {}
        cal_raw = r.get("TABLE_calibration", {})
        if cal_raw:
            cal = (cal_raw.get("ROW_calibration") or {})
            if isinstance(cal, list):
                cal = cal[0] if cal else {}

        def _f(k):
            v = cal.get(k)
            try:
                return float(v) if v and str(v).strip() not in ("--", "N/A", "") else None
            except (ValueError, TypeError):
                return None

        result.append({
            "interface":    iface,
            "sfp_present":  True,
            "part_number":  (r.get("partnum") or r.get("part_number") or "").strip(),
            "serial_number":(r.get("serialnum") or r.get("serial_number") or "").strip(),
            "vendor":       (r.get("name") or r.get("vendor") or "").strip(),
            "rx_power_dbm": _f("rx_pwr"),
            "tx_power_dbm": _f("tx_pwr"),
            "temperature":  _f("temperature"),
            "voltage":      _f("voltage"),
            "current_ma":   _f("current"),
        })
    return result


def parse_counters(body: dict) -> list[dict]:
    rows = _to_array(
        body.get("TABLE_interface_brief_if", {}).get("ROW_interface_brief_if") or
        body.get("TABLE_interface", {}).get("ROW_interface")
    )
    result = []
    for r in rows:
        iface = r.get("interface", "")
        if not iface.lower().startswith("fc"):
            continue
        result.append({
            "interface":    iface,
            "rx_bytes":     int(r.get("rx_bytes", "0") or "0"),
            "tx_bytes":     int(r.get("tx_bytes", "0") or "0"),
            "rx_crc_err":   int(r.get("rx_crc_err", "0") or "0"),
            "link_failures": int(r.get("link_failures", "0") or "0"),
        })
    return result


def parse_fcns(body: dict) -> list[dict]:
    entries = []
    for vsan_row in _to_array(body.get("TABLE_fcns_vsan", {}).get("ROW_fcns_vsan")):
        vid = int(vsan_row.get("vsan_id", 0))
        for row in _to_array(vsan_row.get("TABLE_fcns_database", {}).get("ROW_fcns_database")):
            entries.append({
                "vsan_id":            vid,
                "pwwn":               (row.get("pwwn") or "").strip(),
                "fcid":               (row.get("fcid") or "").strip(),
                "type":               (row.get("type") or "").strip() or None,
                "vendor":             (row.get("vendor") or "").strip() or None,
                "node_name":          (row.get("node_name") or "").strip() or None,
                "fc4_types":          (row.get("fc4_types") or "").strip() or None,
                "symbolic_port_name": (row.get("symbolic_port_name") or "").strip() or None,
                "connected_interface":(row.get("connected_interface") or "").strip() or None,
                "switch_name":        (row.get("switch_name") or "").strip() or None,
            })
    return entries
