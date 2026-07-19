"""
mds_simulator.py - Cisco MDS 9000 NX-API Simulator
Per-port configurable state: up/down, speed, VSAN, SFP presence,
throughput ranges, and optical power ranges.
Port configs are persisted in the DB via app_settings JSON blob.
"""
import json
import math
import re
from pathlib import Path


def _ip_seed(ip: str) -> int:
    parts = [int(x) for x in re.findall(r'\d+', ip)][:4]
    while len(parts) < 4:
        parts.append(0)
    return ((parts[0] * 31 + parts[1]) * 31 + parts[2]) * 31 + parts[3]


def _make_wwn(prefix: str, ip: str, index: int) -> str:
    seed = _ip_seed(ip)
    b5 = (seed >> 16) & 0xFF
    b6 = (seed >>  8) & 0xFF
    b7 =  seed        & 0xFF
    b8 =  index       & 0xFF
    return f"{prefix}:{b5:02x}:{b6:02x}:{b7:02x}:{b8:02x}"


def _sim_value(mn: float, mx: float, poll: int, phase: float) -> float:
    t = math.sin(poll * 0.3 + phase)
    return mn + (mx - mn) * (0.5 + t * 0.45)


def _auto_ranges(speed_gbps: int, degraded: bool) -> dict:
    cap = speed_gbps * 1000
    return {
        "tx_min_mbps": round(cap * 0.05),
        "tx_max_mbps": round(cap * 0.75),
        "rx_min_mbps": round(cap * 0.05),
        "rx_max_mbps": round(cap * 0.80),
        "rx_pwr_min": -12.5 if degraded else -4.5,
        "rx_pwr_max": -10.0 if degraded else -2.0,
        "tx_pwr_min": -2.5,
        "tx_pwr_max": -0.5,
    }


def default_ports(ip: str) -> list:
    def mk(name, state, mode, speed, vsan, sfp, degraded):
        p = {"name": name, "state": state, "mode": mode,
             "speed_gbps": speed, "vsan_id": vsan,
             "sfp_present": sfp, "degraded": degraded}
        p.update(_auto_ranges(speed, degraded))
        return p
    return [
        mk("fc1/1", "up",   "F",  8,  100, True,  False),
        mk("fc1/2", "up",   "F",  8,  100, True,  False),
        mk("fc1/3", "up",   "F",  8,  100, True,  False),
        mk("fc1/4", "down", "F",  8,  100, False, False),
        mk("fc1/5", "up",   "E",  16, 100, True,  False),
        mk("fc1/6", "up",   "F",  8,  200, True,  False),
        mk("fc1/7", "up",   "F",  8,  200, True,  False),
        mk("fc1/8", "up",   "F",  4,  200, True,  True),
    ]


def _default_aliases(ip: str) -> list:
    return [
        {"name": "DB_Server_01_HBA_A",  "pwwn": _make_wwn("21:00:00:24", ip, 0x01)},
        {"name": "DB_Server_01_HBA_B",  "pwwn": _make_wwn("21:00:00:24", ip, 0x02)},
        {"name": "App_Server_02_HBA_A", "pwwn": _make_wwn("21:00:00:24", ip, 0x03)},
        {"name": "Storage_Array_A_P1",  "pwwn": _make_wwn("50:00:d3:10", ip, 0x04)},
        {"name": "Storage_Array_A_P2",  "pwwn": _make_wwn("50:00:d3:10", ip, 0x05)},
        {"name": "Backup_Host_HBA_A",   "pwwn": _make_wwn("20:00:00:25", ip, 0x06)},
        {"name": "DR_Server_01_HBA_A",  "pwwn": _make_wwn("21:00:00:24", ip, 0x07)},
        {"name": "DR_Server_01_HBA_B",  "pwwn": _make_wwn("21:00:00:24", ip, 0x08)},
    ]


# In-memory state per IP
_states: dict = {}

# Loaded once per process from SAN_SIM_STARTUP_CONFIG, if set -- avoids
# re-parsing the file for every switch IP the simulator is asked about.
_startup_config_cache: dict | None = None
_startup_config_loaded = False


def _load_startup_config_once() -> dict | None:
    global _startup_config_cache, _startup_config_loaded
    if _startup_config_loaded:
        return _startup_config_cache
    _startup_config_loaded = True
    try:
        from services.startup_config import get_configured_path, load_startup_config
        path = get_configured_path()
        if path:
            _startup_config_cache = load_startup_config(path)
            print(f"[SIM] Loaded startup-config from {path}: "
                  f"{len(_startup_config_cache['ports'])} ports, "
                  f"{len(_startup_config_cache['aliases'])} aliases, "
                  f"{len(_startup_config_cache['zones'])} zones, "
                  f"{len(_startup_config_cache['zone_sets'])} zone sets")
    except Exception as e:
        print(f"[SIM] Failed to load startup-config: {e}")
        _startup_config_cache = None
    return _startup_config_cache


def _get_state(ip: str) -> dict:
    if ip not in _states:
        cfg = _load_startup_config_once()
        if cfg and cfg["ports"]:
            # Seed this simulated switch from the startup-config file.
            # Every simulated IP gets an independent copy of the same
            # topology (a fresh deep-ish copy so mutating one switch's
            # state doesn't leak into another's).
            import copy
            _states[ip] = {
                "poll_count": 0,
                "aliases": copy.deepcopy(cfg["aliases"]),
                "zones": copy.deepcopy(cfg["zones"]),
                "zone_sets": copy.deepcopy(cfg["zone_sets"]),
                "ports": copy.deepcopy(cfg["ports"]),
                "vsans": {
                    str(vid): {"name": name, "state": "active"}
                    for vid, name in dict(cfg.get("vsans", {})).items()
                },
            }
        else:
            _states[ip] = {
                "poll_count": 0,
                "aliases": _default_aliases(ip),
                "zones": [
                    {"name": "Zone_DB_to_Storage",   "vsan_id": 100,
                     "members": [{"type": "pwwn", "value": _make_wwn("21:00:00:24", ip, 0x01)},
                                  {"type": "device_alias", "value": "Storage_Array_A_P1"},
                                  {"type": "device_alias", "value": "Storage_Array_A_P2"}]},
                    {"name": "Zone_App_to_Storage",  "vsan_id": 100,
                     "members": [{"type": "pwwn", "value": _make_wwn("21:00:00:24", ip, 0x03)},
                                  {"type": "device_alias", "value": "Storage_Array_A_P1"}]},
                ],
                "zone_sets": [
                    {"name": "Production_ZoneSet", "vsan_id": 100, "is_active": True,
                     "zones": ["Zone_DB_to_Storage", "Zone_App_to_Storage"]},
                ],
                "ports": default_ports(ip),
                "vsans": {},
            }
    return _states[ip]




def get_sim_ports(ip: str) -> list:
    """Return current port configs, merging DB-saved overrides."""
    state = _get_state(ip)
    try:
        from db.database import get_setting
        saved = get_setting("sim_ports_" + ip, "")
        if saved:
            saved_ports = json.loads(saved)
            # Merge: saved config overrides defaults
            state["ports"] = saved_ports
    except Exception:
        pass
    return state["ports"]


def save_sim_ports(ip: str, ports: list) -> None:
    """Persist port configs to DB."""
    _get_state(ip)["ports"] = ports
    try:
        from db.database import set_setting
        set_setting("sim_ports_" + ip, json.dumps(ports))
    except Exception:
        pass


class MdsSimulator:

    def __init__(self, ip: str):
        self.ip = ip
        self._state = _get_state(ip)
        # Load persisted port config
        get_sim_ports(ip)

    def increment_poll(self):
        self._state["poll_count"] += 1

    def test_connectivity(self) -> dict:
        return {
            "hostname": f"MDS-SIM-{self.ip}",
            "model": "MDS 9132T",
            "nxos_version": "9.4(1)",
            "serial_number": f"SIM{_ip_seed(self.ip) & 0xFFFF:04X}",
        }

    def send_command(self, command: str) -> dict:
        self._state["poll_count"] += 1
        c = command.strip().lower()
        if "show interface transceiver"   in c: return self._show_transceiver()
        if "show interface counters brief" in c: return self._show_counters()
        if "show interface counters"      in c: return self._show_counters()
        if "show interface brief"         in c: return self._show_iface_brief()
        if "show interface" in c and "counters" not in c and "transceiver" not in c and "brief" not in c:
            return self._show_interface()
        if "show fcns database"           in c: return self._show_fcns(command)
        if "show flogi database"          in c: return self._show_flogi(command)
        if "show fcs database"            in c: return self._show_fcs(command)
        if "show device-alias database"   in c: return self._show_device_alias()
        if "show zoneset"                 in c: return self._show_zoneset(command)
        if "show zone "                   in c or c.strip() == "show zone": return self._show_zone(command)
        if "show vsan" in c and "membership" in c: return self._show_vsan_membership(command)
        if "show vsan"                    in c: return self._show_vsan(command)
        if "show version"                 in c: return self._show_version()
        if "show inventory"               in c: return self._show_inventory()
        if "show system uptime"           in c: return self._show_uptime()
        if "show startup-config"          in c: return self._show_config()
        if "show running-config"          in c: return self._show_config()
        return {}

    def send_config(self, commands: list) -> None:
        self._apply_config(commands)

    # -- show version ---------------------------------------------------------
    def _show_version(self):
        return {
            "header_str":    f"Cisco Nexus Operating System (NX-OS) Software\nMDS 9132T [SIM {self.ip}]",
            "chassis_id":    "MDS 9132T",
            "sys_ver_str":   "9.4(1)",
            "proc_board_id": f"SIM{_ip_seed(self.ip) & 0xFFFF:04X}",
        }

    def _show_inventory(self):
        return {
            "TABLE_inv": {"ROW_inv": {
                "name": "Chassis", "desc": "MDS 9132T Chassis",
                "productid": "DS-C9132T-MEK9", "vid": "V01",
                "serialnum": f"SIM{_ip_seed(self.ip) & 0xFFFF:04X}",
            }},
        }

    def _show_uptime(self):
        pc = self._state["poll_count"]
        return {"sys_uptime_str": f"{pc // 1440}d {(pc % 1440) // 60}h {pc % 60}m"}

    def _show_config(self) -> dict:
        """
        show startup-config / show running-config.
        Real NX-API returns this as plain text (not a TABLE_/ROW_ structure),
        typically under a "msg" key when output_format is json. We synthesize
        config text reflecting the simulator's CURRENT in-memory state, so
        you can verify what a startup-config seed actually produced.
        """
        st = self._state
        lines = [f"!Command: show running-config",
                 f"!Simulated MDS switch {self.ip}", "!"]

        vsans = st.get("vsans") or {}
        if vsans:
            lines.append("vsan database")
            for vid, meta in sorted(vsans.items(), key=lambda kv: int(kv[0])):
                name = meta.get("name") if isinstance(meta, dict) else meta
                lines.append(f'  vsan {vid} name "{name}"')
                if isinstance(meta, dict) and meta.get("state") == "suspended":
                    lines.append(f'  vsan {vid} suspend')
            lines.append("!")

        for p in st["ports"]:
            lines.append(f"interface {p['name']}")
            lines.append(f"  switchport mode {p['mode']}")
            lines.append(f"  switchport speed {p['speed_gbps'] * 1000}")
            lines.append("  no shutdown" if p["state"] == "up" else "  shutdown")
            lines.append("!")

        if st["aliases"]:
            lines.append("device-alias database")
            for a in st["aliases"]:
                lines.append(f"  device-alias name {a['name']} pwwn {a['pwwn']}")
            lines.append("device-alias commit")
            lines.append("!")

        for z in st["zones"]:
            lines.append(f"zone name {z['name']} vsan {z['vsan_id']}")
            for m in z["members"]:
                if m["type"] == "pwwn":
                    lines.append(f"  member pwwn {m['value']}")
                elif m["type"] == "device_alias":
                    lines.append(f"  member device-alias {m['value']}")
                elif m["type"] == "interface":
                    lines.append(f"  member interface {m['value']}")
            lines.append("!")

        for zs in st["zone_sets"]:
            lines.append(f"zoneset name {zs['name']} vsan {zs['vsan_id']}")
            for zname in zs["zones"]:
                lines.append(f"  member {zname}")
            lines.append("!")
            if zs["is_active"]:
                lines.append(f"zoneset activate name {zs['name']} vsan {zs['vsan_id']}")
                lines.append("!")

        return {"msg": "\n".join(lines)}

    # -- show interface -------------------------------------------------------
    def _show_interface(self):
        """
        show interface (full form)

        Field names confirmed against a real switch: oper_port_state (NOT
        state), port_vsan (NOT vsan), oper_speed as a string WITH unit
        suffix e.g. "16 Gbps" (NOT a bare Mbps number).
        """
        ports = self._state["ports"]
        aliases = self._state["aliases"]
        rows = []
        for i, port in enumerate(ports):
            alias = aliases[i] if i < len(aliases) else None
            rows.append({
                "interface":        port["name"],
                "oper_port_state":  port["state"],
                "port_down_reason": None if port["state"] == "up" else "Administratively down",
                "hardware":         "Fibre Channel",
                "sfp":              f"{port['speed_gbps']}G_SW" if port.get("sfp_present") else None,
                "admin_mode":       port["mode"],
                "oper_mode":        port["mode"] if port["state"] == "up" else "auto",
                "oper_speed":       f"{port['speed_gbps']} Gbps" if port["state"] == "up" else "",
                "port_wwn":         _make_wwn("20:00:de:fb", self.ip, i + 1),
                "peer_port_wwn":    alias["pwwn"] if alias else "",
                "port_vsan":        port["vsan_id"],
                "fcid": f"0x{port['vsan_id'] * 0x10000 + i + 1:06x}" if port["state"] == "up" else "",
                "description":      alias["name"] if alias else "",
            })
        return {"TABLE_interface": {"ROW_interface": rows}}

    def _show_iface_brief(self):
        return {
            "TABLE_interface_brief_if": {
                "ROW_interface_brief_if": [
                    {"interface": p["name"], "vsan": str(p["vsan_id"]),
                     "admin_mode": p["mode"], "status": p["state"],
                     "fcot_info": "swl" if p["sfp_present"] else "--",
                     "oper_mode": p["mode"],
                     "oper_speed": str(p["speed_gbps"])}
                    for p in self._state["ports"]
                ]
            }
        }

    # -- Counters -------------------------------------------------------------
    def _sim_counter(self, port: dict, idx: int) -> dict:
        pc = self._state["poll_count"]
        if port["state"] == "down":
            return {
                "interface": port["name"], "last_cleared_time": "never",
                "rx_frames": 0, "tx_frames": 0,
                "rx_bytes": 0, "tx_bytes": 0,
                "rx_crc_fcs": 0, "rx_link_faliures": 0,
                "rx_discard_frames": 0, "tx_discard_frames": 0,
                "rx_rate_bits_ps": 0, "tx_rate_bits_ps": 0,
                "rx_rate_bytes_ps": 0, "tx_rate_bytes_ps": 0,
                "rx_rate_frames_ps": 0, "tx_rate_frames_ps": 0,
            }
        tx_mbps = _sim_value(port["tx_min_mbps"], port["tx_max_mbps"], pc, idx * 0.7)
        rx_mbps = _sim_value(port["rx_min_mbps"], port["rx_max_mbps"], pc, idx * 0.7 + 0.5)
        base = idx * 10_000_000
        tw = base + round(tx_mbps * 60 * 1e6 / 32) * pc
        rw = base + round(rx_mbps * 60 * 1e6 / 32) * pc
        # The real switch reports its own live rate in bits/sec -- emit
        # that directly (mirroring rx_mbps/tx_mbps, converted to bps)
        # rather than requiring the poller to derive it from byte deltas.
        rx_bps = round(rx_mbps * 1_000_000)
        tx_bps = round(tx_mbps * 1_000_000)
        return {
            "interface":        port["name"],
            "last_cleared_time": "never",
            "rx_frames":        round(rw / 128),
            "tx_frames":        round(tw / 128),
            "rx_bytes":         rw * 4,
            "tx_bytes":         tw * 4,
            "rx_crc_fcs":       0,
            "rx_link_faliures": 0,
            "rx_discard_frames": 0,
            "tx_discard_frames": 0,
            "rx_rate_bits_ps":  rx_bps,
            "tx_rate_bits_ps":  tx_bps,
            "rx_rate_bytes_ps": round(rx_bps / 8),
            "tx_rate_bytes_ps": round(tx_bps / 8),
            "rx_rate_frames_ps": round(rw / 128),
            "tx_rate_frames_ps": round(tw / 128),
        }

    def _show_counters(self):
        # Real schema: TABLE_counters is a top-level LIST, each entry
        # wrapping its own ROW_counters list -- not a single dict like
        # most other NX-API tables.
        return {"TABLE_counters": [
            {"ROW_counters": [
                self._sim_counter(p, i)
                for i, p in enumerate(self._state["ports"])
            ]}
        ]}

    # -- Transceiver ----------------------------------------------------------
    def _sim_xcvr(self, port: dict, idx: int) -> dict:
        if not port["sfp_present"] or port["state"] == "down":
            return {
                "interface_sfp": port["name"],
                "TABLE_calib": {"ROW_calib": {"sfp": "sfp is not present"}},
            }
        pc = self._state["poll_count"]
        rx = _sim_value(port["rx_pwr_min"], port["rx_pwr_max"], pc, idx * 0.6)
        tx = _sim_value(port["tx_pwr_min"], port["tx_pwr_max"], pc, idx * 0.6 + 1)
        temp = _sim_value(32, 42, pc, idx * 0.4)
        volt = _sim_value(3.27, 3.35, pc, idx * 0.2)
        curr = _sim_value(6.0, 7.5, pc, idx * 0.3)
        vendors = ["CISCO-AVAGO", "CISCO-FINISAR", "CISCO-JDSU", "CISCO-AVAGO",
                   "CISCO-FINISAR", "CISCO-JDSU", "CISCO-AVAGO", "CISCO-FINISAR"]
        speed_mbps = port["speed_gbps"] * 1000
        return {
            "interface_sfp": port["name"],
            "TABLE_calib": {"ROW_calib": [
                {
                    # -- Static SFP identity info (real NX-API row 1) --
                    "cisco_part_number": "10-2418-01",
                    "cisco_product_id":  "DS-SFP-FC8G-SW" if port["speed_gbps"] == 8 else f"DS-SFP-FC{port['speed_gbps']}G-SW",
                    "ciscoid":     "unknown (0x0)",
                    "name":        vendors[idx % 8],
                    "partnum":     "SFBR-5799APZ-CS5" if port["degraded"] else "AFBR-57F5PZ-CS1",
                    "rev":         "A",
                    "serialnum":   f"SIM{port['name'].replace('/', '')}{_ip_seed(self.ip) & 0xFFFF:04X}",
                    "sfp":         "sfp is present",
                    "supported_speeds": f"Min speed: {speed_mbps // 4} Mb/s, Max speed: {speed_mbps} Mb/s",
                    "tx_length":   "short distance",
                    "tx_medium":   "multimode laser with 62.5 um aperture (M6)",
                    "txcvr_type":  "short wave laser w/o OFC (SN)",
                },
                {
                    # -- Live readings (real NX-API row 2) --
                    "current":        f"{curr:.2f}",
                    "optical_rx_pwr": f"{rx:.2f}",
                    "optical_tx_pwr": f"{tx:.2f}",
                    "temperature":    f"{temp:.2f}",
                    "tx_fault_type":  0,
                    "volt":           f"{volt:.2f}",
                },
            ]},
        }

    def _show_transceiver(self):
        return {"TABLE_interface_trans": {
            "ROW_interface_trans": [
                self._sim_xcvr(p, i) for i, p in enumerate(self._state["ports"])
            ]
        }}

    # -- FCNS -----------------------------------------------------------------
    def _show_fcns(self, cmd: str):
        st = self._state
        m = re.search(r'vsan\s+(\d+)', cmd, re.I)
        vsan_filter = int(m.group(1)) if m else None
        vsans = [vsan_filter] if vsan_filter else list({p["vsan_id"] for p in st["ports"]})
        vendors = ["Emulex", "QLogic", "Pure Storage", "Cisco"]
        return {"TABLE_fcns_vsan": {"ROW_fcns_vsan": [
            {"vsan_id": str(v), "TABLE_fcns_database": {"ROW_fcns_database": [
                {"pwwn": (st["aliases"][i]["pwwn"] if i < len(st["aliases"]) else _make_wwn("20:00:de:fb", self.ip, i+1)),
                 "fcid": f"0x{v * 0x10000 + i + 1:06x}",
                 "type": "N",
                 "vendor": vendors[j % 4],
                 "fc4_types": "scsi-fcp:init",
                 "symbolic_port_name": st["aliases"][i]["name"] if i < len(st["aliases"]) else "",
                 "connected_interface": p["name"],
                 "switch_name": f"MDS-SIM-{self.ip}"}
                for j, (i, p) in enumerate(
                    (i, p) for i, p in enumerate(st["ports"])
                    if p["vsan_id"] == v and p["state"] == "up"
                )
            ]}} for v in vsans
        ]}}

    def _show_flogi(self, cmd: str):
        st = self._state
        m = re.search(r'vsan\s+(\d+)', cmd, re.I)
        vf = int(m.group(1)) if m else None
        entries = []
        for i, p in enumerate(st["ports"]):
            if p["state"] != "up": continue
            if vf and p["vsan_id"] != vf: continue
            alias = st["aliases"][i] if i < len(st["aliases"]) else None
            if not alias: continue
            entries.append({
                "interface": p["name"], "vsan": p["vsan_id"],
                "fcid": f"0x{p['vsan_id'] * 0x10000 + i + 1:06x}",
                "port_name": alias["pwwn"],
            })
        return {"TABLE_flogi_entry": {"ROW_flogi_entry": entries[0] if len(entries) == 1 else entries}}

    def _show_fcs(self, cmd: str):
        st = self._state
        m = re.search(r'vsan\s+(\d+)', cmd, re.I)
        vf = int(m.group(1)) if m else None
        vsans = [vf] if vf else list({p["vsan_id"] for p in st["ports"]})
        return {"TABLE_fcs_vsan": {"ROW_fcs_vsan": [
            {"vsan_id": str(v), "TABLE_fcs_ie": {"ROW_fcs_ie": [{"ie_name": f"MDS-SIM-{self.ip}",
             "TABLE_fcs_port": {"ROW_fcs_port": [
                 {"port_wwn": st["aliases"][i]["pwwn"] if i < len(st["aliases"]) else "",
                  "port_name": st["aliases"][i]["name"] if i < len(st["aliases"]) else "",
                  "port_type": p["mode"], "interface": p["name"]}
                 for i, p in enumerate(st["ports"]) if p["vsan_id"] == v and p["state"] == "up"
             ]}}]}} for v in vsans
        ]}}

    def _show_device_alias(self):
        return {"TABLE_device_alias_database": {"ROW_device_alias_database": [
            {"dev_alias_name": a["name"], "pwwn": a["pwwn"]}
            for a in self._state["aliases"]
        ]}}

    def _show_vsan(self, cmd: str):
        st = self._state
        vsans = st.get("vsans") or {}
        # Auto-register any VSAN referenced by a port but not yet in the
        # vsans dict (e.g. seed data assigns ports to VSANs 100/200 without
        # an explicit "vsan database" block) -- mirrors real switch
        # behavior where a port's VSAN always implicitly exists.
        port_vsans = {p["vsan_id"] for p in st["ports"]}
        changed = False
        for v in port_vsans:
            if v and str(v) not in vsans:
                vsans[str(v)] = {"name": f"VSAN{v}", "state": "active"}
                changed = True
        if changed:
            st["vsans"] = vsans

        all_ids = sorted(set(int(v) for v in vsans.keys()) | port_vsans)
        rows = []
        for v in all_ids:
            if not v:
                continue
            meta = vsans.get(str(v), {})
            rows.append({
                "vsan_id":   str(v),
                "vsan_name": meta.get("name") or f"VSAN{v}",
                "vsan_state": meta.get("state", "active"),
            })
        return {"TABLE_vsan": {"ROW_vsan": rows}}

    def _show_vsan_membership(self, cmd: str):
        m = re.search(r'vsan\s+(\d+)', cmd, re.I)
        vsan = int(m.group(1)) if m else 100
        ifaces = [p["name"] for p in self._state["ports"] if p["vsan_id"] == vsan]
        return {"TABLE_vsan_membership": {"ROW_vsan_membership": {"vsan": str(vsan), "interfaces": ifaces}}}

    def _member_to_row(self, mm: dict) -> dict:
        """Build a ROW_zone_member dict matching real NX-API shape for one member."""
        aliases = self._state["aliases"]
        if mm["type"] == "pwwn":
            row = {"type": "pwwn", "wwn": mm["value"]}
            # Annotate with the resolved device-alias name if one maps to this pwwn,
            # exactly as a real switch does ("pwwn ... [alias_name]").
            alias = next((a["name"] for a in aliases if a["pwwn"] == mm["value"]), None)
            if alias:
                row["dev_alias"] = alias
            return row
        if mm["type"] == "device_alias":
            # Resolve the alias to its pwwn -- real switches always store/show
            # device-alias zone members as a pwwn with a dev_alias annotation,
            # never as a bare alias-only member.
            alias_pwwn = next((a["pwwn"] for a in aliases if a["name"] == mm["value"]), None)
            if alias_pwwn:
                return {"type": "pwwn", "wwn": alias_pwwn, "dev_alias": mm["value"]}
            return {"type": "pwwn", "wwn": "", "dev_alias": mm["value"]}
        if mm["type"] == "interface":
            return {"type": "interface", "intf_fc": mm["value"], "wwn": ""}
        if mm["type"] == "fcid":
            return {"type": "fcid", "fcid": mm["value"]}
        if mm["type"] == "ip-address":
            return {"type": "ip-address", "ipaddr": mm["value"]}
        return {"type": mm["type"], "wwn": mm["value"]}

    def _show_zone(self, cmd: str):
        """show zone vsan <id> -- returns individual zones (not wrapped in a zoneset)."""
        st = self._state
        m = re.search(r'vsan\s+(\d+)', cmd, re.I)
        vf = int(m.group(1)) if m else None
        zones = [z for z in st["zones"] if not vf or z["vsan_id"] == vf]
        return {"TABLE_zone": {"ROW_zone": [
            {"name": z["name"], "vsan": z["vsan_id"],
             "TABLE_zone_member": {"ROW_zone_member": [
                 self._member_to_row(mm) for mm in z["members"]
             ]}} if z["members"] else {"name": z["name"], "vsan": z["vsan_id"]}
            for z in zones
        ]}}

    def _show_zoneset(self, cmd: str):
        """
        show zoneset vsan <id>

        Matches the REAL switch schema (verified against live NX-API output):
        TABLE_zoneset -> ROW_zoneset, each with 'name', 'vsan', 'isactive'
        ("yes"/"no"), and TABLE_zoneset_member -> ROW_zoneset_member listing
        ONLY the zone names that belong to the set -- no member/pwwn detail
        at all. Full zone membership must come from a separate "show zone"
        call, exactly as it does on a real switch.
        """
        st = self._state
        m = re.search(r'vsan\s+(\d+)', cmd, re.I)
        vf = int(m.group(1)) if m else None
        sets = [zs for zs in st["zone_sets"] if not vf or zs["vsan_id"] == vf]
        return {"TABLE_zoneset": {"ROW_zoneset": [
            {"name": zs["name"], "vsan": zs["vsan_id"],
             "isactive": "yes" if zs["is_active"] else "no",
             "TABLE_zoneset_member": {"ROW_zoneset_member": [
                 {"name": zname} for zname in zs["zones"]
             ]}}
            for zs in sets
        ]}}

    def _apply_config(self, commands: list):
        st = self._state
        cur_zone = cur_zs = None
        cur_vsan = 100
        in_alias = False
        in_vsan_db = False
        for raw in commands:
            c = raw.strip().lower()
            if not c or c in ("conf t", "end"): continue
            if c == "device-alias database": in_alias = True; continue
            if c == "device-alias commit":   in_alias = False; continue
            if in_alias:
                mm = re.match(r'device-alias name (\S+)\s+pwwn\s+(\S+)', raw.strip(), re.I)
                if mm:
                    name, pwwn = mm.group(1), mm.group(2).lower()
                    ei = next((i for i, a in enumerate(st["aliases"]) if a["name"].lower() == name.lower()), -1)
                    if ei >= 0: st["aliases"][ei] = {"name": name, "pwwn": pwwn}
                    else: st["aliases"].append({"name": name, "pwwn": pwwn})
                continue

            if c == "vsan database":
                in_vsan_db = True
                continue
            if in_vsan_db:
                vsans = st.setdefault("vsans", {})

                # "no vsan <id>" -- delete the VSAN entirely. Ports that
                # were in it fall back to VSAN 1 (the real switch moves
                # them to the isolated VSAN 4094, but for simulation
                # purposes reverting to VSAN 1 is close enough and keeps
                # test data legible).
                no_del_m = re.match(r'^no\s+vsan\s+(\d+)$', raw.strip(), re.I)
                if no_del_m:
                    del_vsan = int(no_del_m.group(1))
                    vsans.pop(str(del_vsan), None)
                    for p in st["ports"]:
                        if p["vsan_id"] == del_vsan:
                            p["vsan_id"] = 1
                    continue

                # "no vsan <id> suspend" -- resume/activate a suspended VSAN
                no_susp_m = re.match(r'^no\s+vsan\s+(\d+)\s+suspend$', raw.strip(), re.I)
                if no_susp_m:
                    vid = str(int(no_susp_m.group(1)))
                    vsans.setdefault(vid, {"name": f"VSAN{vid}", "state": "active"})["state"] = "active"
                    continue

                # "vsan <id> suspend" -- suspend a VSAN (takes down all its ports)
                susp_m = re.match(r'^vsan\s+(\d+)\s+suspend$', raw.strip(), re.I)
                if susp_m:
                    vid = str(int(susp_m.group(1)))
                    vsans.setdefault(vid, {"name": f"VSAN{vid}", "state": "active"})["state"] = "suspended"
                    continue

                # "vsan <id> name <name>" -- rename (or implicitly create) a VSAN
                name_m = re.match(r'^vsan\s+(\d+)\s+name\s+(\S+)$', raw.strip(), re.I)
                if name_m:
                    vid, new_name = str(int(name_m.group(1))), name_m.group(2)
                    vsans.setdefault(vid, {"name": new_name, "state": "active"})["name"] = new_name
                    continue

                # "vsan <id> interface <iface> [force]" -- moves a port to
                # a different VSAN. A port belongs to exactly one VSAN, so
                # this implicitly removes it from whatever VSAN it was in.
                vm = re.match(r'^vsan\s+(\d+)\s+interface\s+(\S+)(?:\s+force)?$', raw.strip(), re.I)
                if vm:
                    new_vsan, iface_name = int(vm.group(1)), vm.group(2)
                    port = next((p for p in st["ports"] if p["name"].lower() == iface_name.lower()), None)
                    if port:
                        port["vsan_id"] = new_vsan
                    continue

                # "vsan <id>" (bare) -- create a new VSAN
                create_m = re.match(r'^vsan\s+(\d+)$', raw.strip(), re.I)
                if create_m:
                    vid = str(int(create_m.group(1)))
                    vsans.setdefault(vid, {"name": f"VSAN{vid}", "state": "active"})
                    continue

                # Any other line ends the vsan-db submode
                in_vsan_db = False
                # fall through to allow this line to be matched normally

            no_zm = re.match(r'^no\s+zone\s+name\s+(\S+)\s+vsan\s+(\d+)$', raw.strip(), re.I)
            if no_zm:
                dz_name, dz_vsan = no_zm.group(1), int(no_zm.group(2))
                st["zones"] = [z for z in st["zones"]
                               if not (z["name"] == dz_name and z["vsan_id"] == dz_vsan)]
                # Also remove it from any zone set that referenced it
                for zs in st["zone_sets"]:
                    if zs["vsan_id"] == dz_vsan and dz_name in zs["zones"]:
                        zs["zones"].remove(dz_name)
                cur_zone = cur_zs = None
                continue

            no_zsm = re.match(r'^no\s+zoneset\s+name\s+(\S+)\s+vsan\s+(\d+)$', raw.strip(), re.I)
            if no_zsm:
                dzs_name, dzs_vsan = no_zsm.group(1), int(no_zsm.group(2))
                st["zone_sets"] = [zs for zs in st["zone_sets"]
                                    if not (zs["name"] == dzs_name and zs["vsan_id"] == dzs_vsan)]
                cur_zone = cur_zs = None
                continue

            act_m = re.match(r'^zoneset\s+activate\s+name\s+(\S+)\s+vsan\s+(\d+)$', raw.strip(), re.I)
            if act_m:
                act_name, act_vsan = act_m.group(1), int(act_m.group(2))
                # Cisco NX-OS allows only one active zoneset per VSAN --
                # activating one implicitly deactivates any other in the
                # same VSAN.
                for zs in st["zone_sets"]:
                    if zs["vsan_id"] == act_vsan:
                        zs["is_active"] = (zs["name"] == act_name)
                cur_zone = cur_zs = None
                continue

            zm = re.match(r'^zone name (\S+)\s+vsan\s+(\d+)$', raw.strip(), re.I)
            if zm:
                cur_zone = zm.group(1); cur_vsan = int(zm.group(2)); cur_zs = None
                if not any(z["name"] == cur_zone and z["vsan_id"] == cur_vsan for z in st["zones"]):
                    st["zones"].append({"name": cur_zone, "vsan_id": cur_vsan, "members": []})
                continue

            # Check for a new zoneset block BEFORE falling into zone-member
            # parsing -- otherwise "zoneset name X vsan Y" is swallowed as a
            # non-matching member line while cur_zone is still set.
            zsm = re.match(r'^zoneset name (\S+)\s+vsan\s+(\d+)$', raw.strip(), re.I)
            if zsm:
                cur_zs = zsm.group(1); cur_vsan = int(zsm.group(2)); cur_zone = None
                if not any(zs["name"] == cur_zs and zs["vsan_id"] == cur_vsan for zs in st["zone_sets"]):
                    st["zone_sets"].append({"name": cur_zs, "vsan_id": cur_vsan, "is_active": False, "zones": []})
                continue

            if cur_zone:
                zone = next((z for z in st["zones"] if z["name"] == cur_zone and z["vsan_id"] == cur_vsan), None)
                if zone:
                    pm = re.match(r'member\s+pwwn\s+(\S+)', raw.strip(), re.I)
                    am = re.match(r'member\s+device-alias\s+(\S+)', raw.strip(), re.I)
                    if pm and not any(mm["value"] == pm.group(1).lower() for mm in zone["members"]):
                        zone["members"].append({"type": "pwwn", "value": pm.group(1).lower()})
                    if am and not any(mm["value"] == am.group(1) for mm in zone["members"]):
                        zone["members"].append({"type": "device_alias", "value": am.group(1)})
                continue

            if cur_zs:
                mm = re.match(r'^\s*member\s+(\S+)', raw.strip(), re.I)
                if mm:
                    zs = next((z for z in st["zone_sets"] if z["name"] == cur_zs and z["vsan_id"] == cur_vsan), None)
                    if zs and mm.group(1) not in zs["zones"]:
                        zs["zones"].append(mm.group(1))
