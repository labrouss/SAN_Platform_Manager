"""
startup_config.py -- Load a Cisco NX-OS-style startup-config file and convert
it into the MdsSimulator's internal state shape.

This lets the Docker image for the simulator be seeded with a specific
topology (VSANs, interfaces, device-aliases, zones, zone sets, active
zoneset) by mounting a config file and pointing an environment variable
at it, rather than always starting from the hardcoded 8-port default.

Supported directives (a practical subset of real NX-OS config syntax):

    vsan database
      vsan 100 name "Fabric-A"
      vsan 200 name "Fabric-B"

    interface fc1/1
      switchport mode F
      switchport speed 8000
      no shutdown
    interface fc1/4
      shutdown

    device-alias database
      device-alias name DB_Server_01_HBA_A pwwn 21:00:00:24:ff:8a:1b:01
      device-alias name Storage_Array_A_P1 pwwn 50:00:d3:10:59:be:8a:04

    zone name Zone_DB_to_Storage vsan 100
      member device-alias DB_Server_01_HBA_A
      member device-alias Storage_Array_A_P1

    zoneset name Production_ZoneSet vsan 100
      member Zone_DB_to_Storage
    zoneset activate name Production_ZoneSet vsan 100

Any line not matching a known directive is ignored (comments, banners,
unrelated config sections like ntp/aaa/interface mgmt0, etc.) so a real
switch's full running-config/startup-config can usually be pointed at
this loader directly without needing to strip it down first.
"""
from __future__ import annotations

import os
import re
from pathlib import Path


def _auto_ranges(speed_gbps: int, degraded: bool) -> dict:
    """Mirrors MdsSimulator's own range defaults for a given link speed."""
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


def parse_startup_config(text: str) -> dict:
    """
    Parse startup-config text into a dict with keys: vsans, ports, aliases,
    zones, zone_sets -- matching MdsSimulator's internal _state shape
    (minus poll_count, which the caller fills in).
    """
    vsans: dict[int, str] = {}
    ports: dict[str, dict] = {}
    aliases: list[dict] = []
    zones: list[dict] = []
    zone_sets: list[dict] = []

    lines = [l.rstrip() for l in text.splitlines()]

    i = 0
    n = len(lines)

    def indented(s: str) -> bool:
        return s.startswith(" ") or s.startswith("\t")

    while i < n:
        raw = lines[i]
        line = raw.strip()
        i += 1
        if not line or line.startswith("!") or line.startswith("#"):
            continue

        # -- vsan database block --------------------------------------------
        if line == "vsan database":
            while i < n and (indented(lines[i]) or not lines[i].strip()):
                sub = lines[i].strip()
                i += 1
                if not sub:
                    continue
                m = re.match(r'vsan\s+(\d+)\s+interface\s+(fc\d+/\d+)', sub, re.I)
                if m:
                    vid, iface = int(m.group(1)), m.group(2).lower()
                    port = ports.setdefault(iface, {
                        "name": iface, "state": "up", "mode": "F", "speed_gbps": 8,
                        "vsan_id": vid, "sfp_present": True, "degraded": False,
                    })
                    port["vsan_id"] = vid
                    continue
                m = re.match(r'vsan\s+(\d+)(?:\s+name\s+"?([^"\n]+)"?)?', sub, re.I)
                if m:
                    vid = int(m.group(1))
                    name = (m.group(2) or f"VSAN{vid}").strip()
                    vsans[vid] = name
            continue

        # -- interface fcX/Y block --------------------------------------------
        m = re.match(r'interface\s+(fc\d+/\d+)', line, re.I)
        if m:
            iface = m.group(1).lower()
            port = ports.setdefault(iface, {
                "name": iface, "state": "up", "mode": "F", "speed_gbps": 8,
                "vsan_id": 100, "sfp_present": True, "degraded": False,
            })
            while i < n and (indented(lines[i]) or not lines[i].strip()):
                sub = lines[i].strip()
                i += 1
                if not sub:
                    continue
                if re.match(r'no\s+shutdown', sub, re.I):
                    port["state"] = "up"
                elif re.match(r'^shutdown$', sub, re.I):
                    port["state"] = "down"
                mm = re.match(r'switchport\s+mode\s+(\S+)', sub, re.I)
                if mm:
                    port["mode"] = mm.group(1).upper()
                sm = re.match(r'switchport\s+speed\s+(\d+)', sub, re.I)
                if sm:
                    mbps = int(sm.group(1))
                    port["speed_gbps"] = max(1, round(mbps / 1000))
                vm = re.match(r'switchport\s+description\s+(.+)', sub, re.I)
                if vm:
                    port["description"] = vm.group(1).strip()
                degm = re.match(r'#\s*degraded', sub, re.I)
                if degm:
                    port["degraded"] = True
                sfpm = re.match(r'#\s*no[- ]sfp', sub, re.I)
                if sfpm:
                    port["sfp_present"] = False
            continue

        # A bare "vsan X interface fcY/Z" line (alternate NX-OS style used
        # inside "vsan database" on some platforms, or standalone) --
        # associates an interface with a VSAN.
        m = re.match(r'vsan\s+(\d+)\s+interface\s+(fc\d+/\d+)', line, re.I)
        if m:
            vid, iface = int(m.group(1)), m.group(2).lower()
            port = ports.setdefault(iface, {
                "name": iface, "state": "up", "mode": "F", "speed_gbps": 8,
                "vsan_id": vid, "sfp_present": True, "degraded": False,
            })
            port["vsan_id"] = vid
            continue

        # -- device-alias database block --------------------------------------
        if line.lower() == "device-alias database":
            while i < n and (indented(lines[i]) or not lines[i].strip()):
                sub = lines[i].strip()
                i += 1
                if not sub:
                    continue
                mm = re.match(r'device-alias\s+name\s+(\S+)\s+pwwn\s+(\S+)', sub, re.I)
                if mm:
                    aliases.append({"name": mm.group(1), "pwwn": mm.group(2).lower()})
            continue

        # -- zone name X vsan Y block ------------------------------------------
        m = re.match(r'zone\s+name\s+(\S+)\s+vsan\s+(\d+)', line, re.I)
        if m:
            zname, zvsan = m.group(1), int(m.group(2))
            members = []
            while i < n and (indented(lines[i]) or not lines[i].strip()):
                sub = lines[i].strip()
                i += 1
                if not sub:
                    continue
                pm = re.match(r'member\s+pwwn\s+(\S+)', sub, re.I)
                am = re.match(r'member\s+device-alias\s+(\S+)', sub, re.I)
                im = re.match(r'member\s+interface\s+(\S+)', sub, re.I)
                if pm:
                    members.append({"type": "pwwn", "value": pm.group(1).lower()})
                elif am:
                    members.append({"type": "device_alias", "value": am.group(1)})
                elif im:
                    members.append({"type": "interface", "value": im.group(1)})
            zones.append({"name": zname, "vsan_id": zvsan, "members": members})
            continue

        # -- zoneset activate name X vsan Y (standalone, no block) -----------
        m = re.match(r'zoneset\s+activate\s+name\s+(\S+)\s+vsan\s+(\d+)', line, re.I)
        if m:
            zsname, zsvsan = m.group(1), int(m.group(2))
            for zs in zone_sets:
                if zs["vsan_id"] == zsvsan:
                    zs["is_active"] = (zs["name"] == zsname)
            continue

        # -- zoneset name X vsan Y block ---------------------------------------
        m = re.match(r'zoneset\s+name\s+(\S+)\s+vsan\s+(\d+)', line, re.I)
        if m:
            zsname, zsvsan = m.group(1), int(m.group(2))
            member_zones = []
            while i < n and (indented(lines[i]) or not lines[i].strip()):
                sub = lines[i].strip()
                i += 1
                if not sub:
                    continue
                mm = re.match(r'member\s+(\S+)', sub, re.I)
                if mm:
                    member_zones.append(mm.group(1))
            zone_sets.append({
                "name": zsname, "vsan_id": zsvsan,
                "is_active": False, "zones": member_zones,
            })
            continue

        # Anything else (ntp, aaa, hostname, interface mgmt0, banners, etc.)
        # is intentionally ignored -- a full running-config can be pointed
        # at this loader without pre-stripping unrelated sections. If a
        # section has an indented body we didn't recognize, skip past it
        # so it doesn't get misread as top-level directives.
        while i < n and indented(lines[i]):
            i += 1

    # Fill in computed throughput/optical ranges for every port discovered
    for port in ports.values():
        port.update(_auto_ranges(port["speed_gbps"], port["degraded"]))

    return {
        "vsans": vsans,
        "ports": list(ports.values()),
        "aliases": aliases,
        "zones": zones,
        "zone_sets": zone_sets,
    }


def load_startup_config(path: str | Path) -> dict:
    """Read and parse a startup-config file from disk."""
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return parse_startup_config(text)


def get_configured_path() -> str | None:
    """
    Resolve the startup-config file path from the environment, if set.
    Convention for the Docker image: mount the config file and set
    SAN_SIM_STARTUP_CONFIG to its in-container path, e.g.:

        docker run -v ./my-startup-config.txt:/config/startup-config.txt \\
                   -e SAN_SIM_STARTUP_CONFIG=/config/startup-config.txt \\
                   san-platform
    """
    path = os.environ.get("SAN_SIM_STARTUP_CONFIG", "").strip()
    if path and Path(path).is_file():
        return path
    return None
