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
def _parse_zone_member(m: dict) -> dict | None:
    """
    Classify a single ROW_zone_member entry per the real NX-API schema.
    The 'type' field is authoritative: pwwn, interface, fcid, ip-address,
    device-alias, fwwn, symbolic-nodename, domain-id, fcalias.
    A pwwn-type member may carry a 'dev_alias' annotation (the resolved
    device-alias name) -- this is metadata about the pwwn, not a separate
    member type.
    """
    mtype = (m.get("type") or "").strip().lower()

    if mtype == "pwwn" and m.get("wwn"):
        return {"type": "pwwn", "value": m["wwn"].strip().lower()}
    if mtype == "device-alias" and m.get("dev_alias"):
        # Rare: some outputs list a device-alias member directly as its own type
        return {"type": "device_alias", "value": m["dev_alias"].strip()}
    if mtype == "interface" and m.get("intf_fc"):
        return {"type": "interface", "value": m["intf_fc"].strip()}
    if mtype == "interface" and m.get("intf_port_ch") is not None:
        return {"type": "interface", "value": f"port-channel{m['intf_port_ch']}"}
    if mtype == "fcid" and m.get("fcid"):
        return {"type": "fcid", "value": m["fcid"].strip()}
    if mtype == "ip-address" and m.get("ipaddr"):
        return {"type": "ip-address", "value": m["ipaddr"].strip()}
    if mtype == "fwwn" and m.get("wwn"):
        return {"type": "fwwn", "value": m["wwn"].strip().lower()}
    if mtype == "symbolic-nodename" and m.get("symnodename"):
        return {"type": "symbolic-nodename", "value": m["symnodename"].strip()}

    # Fallback: no recognized type field, guess from whichever key is present
    if m.get("wwn"):
        return {"type": "pwwn", "value": m["wwn"].strip().lower()}
    if m.get("dev_alias"):
        return {"type": "device_alias", "value": m["dev_alias"].strip()}
    if m.get("fcid"):
        return {"type": "fcid", "value": m["fcid"].strip()}
    return None


def parse_zones(body: dict, vsan_id: int) -> list[dict]:
    """
    NX-API: show zone vsan <id>
    Returns TABLE_zone -> ROW_zone, each with 'name', 'vsan', and an
    optional TABLE_zone_member -> ROW_zone_member (dict or list).

    Some switches return TABLE_zone as null (not an empty dict) when a
    VSAN has no zones configured at all -- guard against that, and skip
    any row that has no usable name (seen on some real switches as a
    rowless default-zone-policy artifact).
    """
    zones = []
    table_zone = body.get("TABLE_zone") or {}
    for z_row in _to_array(table_zone.get("ROW_zone") if isinstance(table_zone, dict) else None):
        name = (z_row.get("name") or "").strip()
        if not name:
            continue  # skip unnamed/placeholder rows -- nothing to persist
        members = []
        member_block = z_row.get("TABLE_zone_member") or {}
        if not isinstance(member_block, dict):
            member_block = {}
        for m in _to_array(member_block.get("ROW_zone_member")):
            parsed = _parse_zone_member(m)
            if parsed and parsed["value"]:
                members.append(parsed)
        zones.append({
            "name":    name,
            "vsan_id": vsan_id,
            "members": members,
        })
    return zones


def parse_zone_sets(body: dict) -> list[dict]:
    """
    NX-API: show zoneset [vsan X]
    Returns TABLE_zoneset -> ROW_zoneset, each with 'name', 'vsan',
    'active' (bool-ish), and nested TABLE_zone -> ROW_zone (each with its
    own 'name' and TABLE_zone_member).

    Guards against TABLE_zoneset being null (some switches return this
    rather than an empty dict when no zone sets exist) and skips any row
    with no usable name.
    """
    table_zoneset = body.get("TABLE_zoneset") or {}
    rows = _to_array(table_zoneset.get("ROW_zoneset") if isinstance(table_zoneset, dict) else None)
    result = []
    for zs_row in rows:
        zs_name = (zs_row.get("name") or "").strip()
        if not zs_name:
            continue  # skip unnamed/placeholder rows

        zones = []
        table_zone = zs_row.get("TABLE_zone") or {}
        if not isinstance(table_zone, dict):
            table_zone = {}
        for z_row in _to_array(table_zone.get("ROW_zone")):
            zname = (z_row.get("name") or "").strip()
            if not zname:
                continue
            members = []
            member_block = z_row.get("TABLE_zone_member") or {}
            if not isinstance(member_block, dict):
                member_block = {}
            for m in _to_array(member_block.get("ROW_zone_member")):
                parsed = _parse_zone_member(m)
                if parsed and parsed["value"]:
                    members.append(parsed)
            zones.append({"name": zname, "members": members})

        try:
            vid = int(zs_row.get("vsan", 0))
        except (ValueError, TypeError):
            vid = 0
        active_raw = zs_row.get("active", zs_row.get("zoneset_active", ""))
        result.append({
            "name":      zs_name,
            "vsan_id":   vid,
            "is_active": str(active_raw).strip().lower() in ("true", "1", "yes"),
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
    Real schema (verified against live switch output):

        TABLE_interface_trans -> ROW_interface_trans (list or single dict)
          interface_sfp: "fc1/2"
          TABLE_calib -> ROW_calib: A LIST of exactly two dicts (when SFP present):
            [0] static identity info: cisco_part_number, cisco_product_id,
                name (vendor), partnum, serialnum, sfp ("sfp is present"),
                supported_speeds, tx_length, tx_medium, txcvr_type, rev, ciscoid
            [1] live readings: optical_rx_pwr, optical_tx_pwr, temperature,
                volt, current, tx_fault_type
          When no SFP is installed, ROW_calib is typically absent or the
          single dict just has {"sfp": "sfp is not present"}.
    """
    rows = _to_array(
        body.get("TABLE_interface_trans", {}).get("ROW_interface_trans")
    )
    result = []
    for r in rows:
        iface = (r.get("interface_sfp") or r.get("interface") or "").strip()
        if not iface.lower().startswith("fc"):
            continue

        calib_rows = _to_array(
            (r.get("TABLE_calib") or {}).get("ROW_calib")
        )

        # Merge the (up to) two calib dicts into one lookup -- static
        # identity info and live readings never share keys, so a simple
        # merge is safe and lets every field be looked up the same way.
        cal = {}
        for c in calib_rows:
            if isinstance(c, dict):
                cal.update(c)

        sfp_status = (cal.get("sfp") or "").strip().lower()
        if not cal or "not present" in sfp_status or "absent" in sfp_status:
            continue  # no SFP installed in this port

        def _f(key):
            v = cal.get(key)
            if v is None:
                return None
            s = str(v).strip()
            if s in ("", "--", "N/A", "n/a"):
                return None
            try:
                return float(s)
            except (ValueError, TypeError):
                return None

        result.append({
            "interface":     iface,
            "sfp_present":   True,
            "part_number":   (cal.get("partnum") or "").strip(),
            "cisco_pid":     (cal.get("cisco_product_id") or "").strip(),
            "serial_number": (cal.get("serialnum") or "").strip(),
            "vendor":        (cal.get("name") or "").strip(),
            "revision":      (cal.get("rev") or "").strip(),
            "transceiver_type": (cal.get("txcvr_type") or "").strip(),
            "supported_speeds": (cal.get("supported_speeds") or "").strip(),
            "rx_power_dbm":  _f("optical_rx_pwr"),
            "tx_power_dbm":  _f("optical_tx_pwr"),
            "temperature":   _f("temperature"),
            "voltage":       _f("volt"),
            "current_ma":    _f("current"),
        })
    return result


def parse_counters(body: dict) -> list[dict]:
    """
    NX-API: show interface counters

    Real schema (verified against live switch output) -- NOTE this is
    structurally different from most other NX-API tables: TABLE_counters
    is itself a top-level LIST, not a dict wrapping ROW_counters:

        {
          "TABLE_counters": [
            { "ROW_counters": [ {interface, rx_bytes, tx_bytes,
                                  rx_rate_bits_ps, tx_rate_bits_ps,
                                  rx_crc_fcs, rx_link_faliures, ...}, ... ] }
          ]
        }

    The switch computes its own live rate in rx_rate_bits_ps /
    tx_rate_bits_ps -- we use that directly rather than manually
    differencing byte counters between polls, which is both less
    accurate (depends on our own poll interval, not the switch's
    internal sampling window) and unnecessary since the switch already
    does this calculation in hardware.

    Note: Cisco's real field name really is "rx_link_faliures" (their
    typo, not ours) -- kept as-is since that's what the switch returns.
    """
    table_counters = body.get("TABLE_counters")
    if not table_counters:
        return []
    # TABLE_counters is a list; each entry has its own ROW_counters
    # (dict or list) -- flatten all of them together.
    all_rows = []
    for block in _to_array(table_counters):
        if not isinstance(block, dict):
            continue
        all_rows.extend(_to_array(block.get("ROW_counters")))

    result = []
    for r in all_rows:
        iface = (r.get("interface") or "").strip()
        if not iface.lower().startswith("fc"):
            continue

        def _int(key, default=0):
            v = r.get(key, default)
            try:
                return int(v)
            except (ValueError, TypeError):
                return default

        def _rate_bps(key):
            v = r.get(key)
            try:
                return float(v)
            except (ValueError, TypeError):
                return None

        result.append({
            "interface":      iface,
            "rx_bytes":       _int("rx_bytes"),
            "tx_bytes":       _int("tx_bytes"),
            "rx_frames":      _int("rx_frames"),
            "tx_frames":      _int("tx_frames"),
            "rx_crc_err":     _int("rx_crc_fcs"),
            "link_failures":  _int("rx_link_faliures"),
            "rx_discards":    _int("rx_discard_frames"),
            "tx_discards":    _int("tx_discard_frames"),
            "rx_rate_bps":    _rate_bps("rx_rate_bits_ps"),
            "tx_rate_bps":    _rate_bps("tx_rate_bits_ps"),
            "txwait_percent_1s": _rate_bps("txwait_percent_1s"),
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
