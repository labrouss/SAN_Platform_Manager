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

    A pwwn-type member frequently carries a 'dev_alias' annotation -- the
    device-alias name the switch has resolved for that pwwn. When present,
    this is the canonical, human-managed identity for the member (it's
    what the operator actually configured and manages), so we store the
    member as a device_alias using that name rather than the raw wwn.
    The wwn is still the underlying identity on the wire, but the alias
    is what should surface in the UI and in any WWN/alias round-trip.
    """
    mtype = (m.get("type") or "").strip().lower()

    if mtype == "pwwn" and m.get("wwn"):
        dev_alias = (m.get("dev_alias") or "").strip()
        if dev_alias:
            return {"type": "device_alias", "value": dev_alias}
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
    if m.get("dev_alias"):
        return {"type": "device_alias", "value": m["dev_alias"].strip()}
    if m.get("wwn"):
        return {"type": "pwwn", "value": m["wwn"].strip().lower()}
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
        seen = set()
        member_block = z_row.get("TABLE_zone_member") or {}
        if not isinstance(member_block, dict):
            member_block = {}
        for m in _to_array(member_block.get("ROW_zone_member")):
            parsed = _parse_zone_member(m)
            if not parsed or not parsed["value"]:
                continue
            key = (parsed["type"], parsed["value"].lower())
            if key in seen:
                continue  # skip duplicate member rows (some switches return these)
            seen.add(key)
            members.append(parsed)
        zones.append({
            "name":    name,
            "vsan_id": vsan_id,
            "members": members,
        })
    return zones


def parse_zone_sets(body: dict, zones_by_name: dict[str, dict] | None = None) -> list[dict]:
    """
    NX-API: show zoneset [vsan X]

    IMPORTANT -- verified against a real switch: "show zoneset" does NOT
    return full zone member details nested inside each zoneset. It only
    returns TABLE_zoneset -> ROW_zoneset, each with:
        name:      zoneset name
        vsan:      vsan id
        isactive:  "yes" | "no"   (NOT "active" -- different key entirely)
        TABLE_zoneset_member -> ROW_zoneset_member: a list of member zones,
            each ONLY {"name": "<zone name>"} -- no pwwn/member data at all.

    To get real zone membership for the zones in a zoneset, you must
    cross-reference against a separately parsed "show zone" result (see
    parse_zones()) and match by zone name. Pass that as zones_by_name
    (a dict of zone name -> parsed zone dict with "members"); if omitted,
    zones are returned with an empty members list, matching exactly what
    the switch itself would tell you from this command alone.
    """
    zones_by_name = zones_by_name or {}

    table_zoneset = body.get("TABLE_zoneset") or {}
    rows = _to_array(table_zoneset.get("ROW_zoneset") if isinstance(table_zoneset, dict) else None)
    result = []
    for zs_row in rows:
        zs_name = (zs_row.get("name") or "").strip()
        if not zs_name:
            continue  # skip unnamed/placeholder rows

        zones = []
        member_block = zs_row.get("TABLE_zoneset_member") or {}
        if not isinstance(member_block, dict):
            member_block = {}
        for z_row in _to_array(member_block.get("ROW_zoneset_member")):
            zname = (z_row.get("name") or "").strip()
            if not zname:
                continue
            # Look up real membership from the separately-fetched "show zone"
            # result -- "show zoneset" itself never provides this.
            known_zone = zones_by_name.get(zname)
            zones.append({
                "name": zname,
                "members": known_zone["members"] if known_zone else [],
            })

        try:
            vid = int(zs_row.get("vsan", 0))
        except (ValueError, TypeError):
            vid = 0

        # isactive is the real field name ("yes"/"no"); keep the old
        # active/zoneset_active names as a fallback for other NX-OS
        # versions that may use them instead.
        active_raw = zs_row.get("isactive",
                     zs_row.get("active", zs_row.get("zoneset_active", "")))
        result.append({
            "name":      zs_name,
            "vsan_id":   vid,
            "is_active": str(active_raw).strip().lower() in ("true", "1", "yes"),
            "zones":     zones,
        })
    return result


# -- Interface: parse "show interface brief" -----------------------------------
def parse_interface_full(body: dict) -> list[dict]:
    """
    NX-API: show interface  (the FULL form -- NOT "show interface brief")

    Confirmed against a real switch (live-tested): "show interface brief"
    does not reliably return per-port VSAN membership on all NX-OS
    versions/platforms, which is why Port Inventory's VSAN column showed
    blank. The full "show interface" form reliably includes it.

    Real field names (verified against live switch output):
        interface:        "fc1/1"
        oper_port_state:  "up" | "down" | ...     (NOT "state")
        port_down_reason: e.g. "Administratively down" (nullable)
        sfp:              e.g. "16G_SW" or null/absent if no SFP
        port_wwn:         the port's OWN wwn
        peer_port_wwn:    the wwn logged into this port (nullable)
        admin_mode / oper_mode: "auto" | "F" | "E" | "TE" | ...
        fcid:             "0xbe1a01" (nullable if down)
        port_vsan:        integer                  (NOT "vsan")
        oper_speed:       "16 Gbps"  -- STRING WITH UNIT SUFFIX, not a
                          bare Mbps number. parseInt-style extraction of
                          the leading digits gives the speed in Gbps
                          directly (no /1000 conversion needed).
    """
    rows = _to_array(body.get("TABLE_interface", {}).get("ROW_interface"))
    result = []
    for r in rows:
        iface = (r.get("interface") or "").strip()
        if not iface.lower().startswith("fc"):
            continue

        try:
            vsan = int(r.get("port_vsan")) if r.get("port_vsan") not in (None, "") else 0
        except (ValueError, TypeError):
            vsan = 0

        # oper_speed is a string like "16 Gbps" -- extract the leading
        # digits directly as Gbps (do NOT treat as Mbps / divide by 1000).
        speed_raw = str(r.get("oper_speed") or "").strip()
        speed_match = re.match(r"(\d+)", speed_raw)
        speed_gbps = int(speed_match.group(1)) if speed_match else 0

        state = (r.get("oper_port_state") or "unknown").strip().lower()
        mode  = (r.get("oper_mode") or r.get("admin_mode") or "F").strip().upper()
        if mode == "AUTO":
            mode = "F"  # "auto" isn't a real port mode -- not yet negotiated/down

        result.append({
            "name":      iface,
            "state":     state,
            "mode":      mode,
            "speed":     f"{speed_gbps}G" if speed_gbps else "--",
            "vsan_id":   vsan,
            "port_wwn":  (r.get("port_wwn") or "").strip().lower(),
            "peer_wwn":  (r.get("peer_port_wwn") or "").strip().lower(),
            "sfp":       bool((r.get("sfp") or "").strip()),
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
