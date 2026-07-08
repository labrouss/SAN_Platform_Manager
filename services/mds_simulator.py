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


def _get_state(ip: str) -> dict:
    if ip not in _states:
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

    # -- show interface -------------------------------------------------------
    def _show_interface(self):
        ports = self._state["ports"]
        aliases = self._state["aliases"]
        rows = []
        for i, port in enumerate(ports):
            alias = aliases[i] if i < len(aliases) else None
            rows.append({
                "interface":     port["name"],
                "state":         port["state"],
                "admin_state":   "up",
                "admin_mode":    port["mode"],
                "oper_mode":     port["mode"],
                "oper_speed":    str(port["speed_gbps"] * 1000),
                "port_wwn":      _make_wwn("20:00:de:fb", self.ip, i + 1),
                "peer_port_wwn": alias["pwwn"] if alias else "",
                "vsan":          str(port["vsan_id"]),
                "fcid": f"0x{port['vsan_id'] * 0x10000 + i + 1:06x}" if port["state"] == "up" else "",
                "description":   alias["name"] if alias else "",
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
            return {"interface": port["name"], "rx_frames": "0", "tx_frames": "0",
                    "rx_words": "0", "tx_words": "0", "rx_bytes": "0", "tx_bytes": "0",
                    "rx_crc_err": "0", "link_failures": "0"}
        tx_mbps = _sim_value(port["tx_min_mbps"], port["tx_max_mbps"], pc, idx * 0.7)
        rx_mbps = _sim_value(port["rx_min_mbps"], port["rx_max_mbps"], pc, idx * 0.7 + 0.5)
        base = idx * 10_000_000
        tw = base + round(tx_mbps * 60 * 1e6 / 32) * pc
        rw = base + round(rx_mbps * 60 * 1e6 / 32) * pc
        return {
            "interface":  port["name"],
            "rx_frames":  str(round(rw / 128)),
            "tx_frames":  str(round(tw / 128)),
            "rx_words":   str(rw), "tx_words": str(tw),
            "rx_bytes":   str(rw * 4), "tx_bytes": str(tw * 4),
            "rx_crc_err": "0", "link_failures": "0",
        }

    def _show_counters(self):
        return {"TABLE_interface": {
            "ROW_interface": [self._sim_counter(p, i)
                              for i, p in enumerate(self._state["ports"])]
        }}

    # -- Transceiver ----------------------------------------------------------
    def _sim_xcvr(self, port: dict, idx: int) -> dict:
        if not port["sfp_present"] or port["state"] == "down":
            return {"interface": port["name"], "sfp": "absent"}
        pc = self._state["poll_count"]
        rx = _sim_value(port["rx_pwr_min"], port["rx_pwr_max"], pc, idx * 0.6)
        tx = _sim_value(port["tx_pwr_min"], port["tx_pwr_max"], pc, idx * 0.6 + 1)
        temp = _sim_value(32, 42, pc, idx * 0.4)
        volt = _sim_value(3.27, 3.35, pc, idx * 0.2)
        curr = _sim_value(6.0, 7.5, pc, idx * 0.3)
        vendors = ["CISCO-AVAGO", "CISCO-FINISAR", "CISCO-JDSU", "CISCO-AVAGO",
                   "CISCO-FINISAR", "CISCO-JDSU", "CISCO-AVAGO", "CISCO-FINISAR"]
        return {
            "interface": port["name"], "sfp": "present",
            "name": vendors[idx % 8],
            "partnum": "SFBR-5799APZ-CS5" if port["degraded"] else "AFBR-57F5PZ-CS1",
            "serialnum": f"SIM{port['name'].replace('/', '')}{_ip_seed(self.ip) & 0xFFFF:04X}",
            "TABLE_calibration": {"ROW_calibration": {
                "temperature": f"{temp:.1f}",
                "voltage":     f"{volt:.3f}",
                "current":     f"{curr:.2f}",
                "rx_pwr":      f"{rx:.2f}",
                "tx_pwr":      f"{tx:.2f}",
            }},
        }

    def _show_transceiver(self):
        return {"TABLE_interface_transceiver": {
            "ROW_interface_transceiver": [
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
        vsans = list({p["vsan_id"] for p in self._state["ports"]})
        return {"TABLE_vsan": {"ROW_vsan": [
            {"vsan_id": str(v), "vsan_name": f"VSAN{v}", "vsan_state": "active"}
            for v in vsans
        ]}}

    def _show_vsan_membership(self, cmd: str):
        m = re.search(r'vsan\s+(\d+)', cmd, re.I)
        vsan = int(m.group(1)) if m else 100
        ifaces = [p["name"] for p in self._state["ports"] if p["vsan_id"] == vsan]
        return {"TABLE_vsan_membership": {"ROW_vsan_membership": {"vsan": str(vsan), "interfaces": ifaces}}}

    def _show_zone(self, cmd: str):
        """show zone vsan <id> -- returns individual zones (not wrapped in a zoneset)."""
        st = self._state
        m = re.search(r'vsan\s+(\d+)', cmd, re.I)
        vf = int(m.group(1)) if m else None
        zones = [z for z in st["zones"] if not vf or z["vsan_id"] == vf]
        return {"TABLE_zone": {"ROW_zone": [
            {"zone_name": z["name"],
             "TABLE_zone_member": {"ROW_zone_member": [
                 {"wwn": mm["value"]} if mm["type"] == "pwwn" else {"device_alias": mm["value"]}
                 for mm in z["members"]
             ]}}
            for z in zones
        ]}}

    def _show_zoneset(self, cmd: str):
        st = self._state
        m = re.search(r'vsan\s+(\d+)', cmd, re.I)
        vf = int(m.group(1)) if m else None
        sets = [zs for zs in st["zone_sets"] if not vf or zs["vsan_id"] == vf]
        return {"TABLE_zoneset": {"ROW_zoneset": [
            {"zoneset_name": zs["name"], "zoneset_vsan": str(zs["vsan_id"]),
             "zoneset_active": str(zs["is_active"]),
             "TABLE_zone": {"ROW_zone": [
                 {"zone_name": zname,
                  "TABLE_zone_member": {"ROW_zone_member": [
                      {"wwn": mm["value"]} if mm["type"] == "pwwn" else {"device_alias": mm["value"]}
                      for mm in z["members"]
                  ]}}
                 for zname in zs["zones"]
                 for z in st["zones"] if z["name"] == zname and z["vsan_id"] == zs["vsan_id"]
             ]}}
            for zs in sets
        ]}}

    def _apply_config(self, commands: list):
        st = self._state
        cur_zone = cur_zs = None
        cur_vsan = 100
        in_alias = False
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
            zm = re.match(r'^zone name (\S+)\s+vsan\s+(\d+)$', raw.strip(), re.I)
            if zm:
                cur_zone = zm.group(1); cur_vsan = int(zm.group(2)); cur_zs = None
                if not any(z["name"] == cur_zone and z["vsan_id"] == cur_vsan for z in st["zones"]):
                    st["zones"].append({"name": cur_zone, "vsan_id": cur_vsan, "members": []})
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
            zsm = re.match(r'^zoneset name (\S+)\s+vsan\s+(\d+)$', raw.strip(), re.I)
            if zsm:
                cur_zs = zsm.group(1); cur_vsan = int(zsm.group(2)); cur_zone = None
                if not any(zs["name"] == cur_zs and zs["vsan_id"] == cur_vsan for zs in st["zone_sets"]):
                    st["zone_sets"].append({"name": cur_zs, "vsan_id": cur_vsan, "is_active": False, "zones": []})
                continue
            if cur_zs:
                mm = re.match(r'^\s*member\s+(\S+)', raw.strip(), re.I)
                if mm:
                    zs = next((z for z in st["zone_sets"] if z["name"] == cur_zs and z["vsan_id"] == cur_vsan), None)
                    if zs and mm.group(1) not in zs["zones"]:
                        zs["zones"].append(mm.group(1))
