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

bridge.py -- QWebChannel bridge between the HTML/JS frontend and Python backend.
All methods are called from JavaScript via: window.bridge.methodName(args, callback)
"""
from __future__ import annotations

import json
import hashlib
from datetime import datetime, timezone

from PyQt5.QtCore import QObject, pyqtSlot, pyqtSignal

from db import database as db
from services.client_factory import (
    authenticate, hash_password, build_client, store_credentials,
    parse_device_aliases, parse_zone_sets, parse_zones, parse_vsans,
    parse_fcns, parse_transceiver, parse_interface_brief, parse_counters,
    is_sim
)


def _j(obj) -> str:
    """Serialize to JSON string, handling non-serializable types."""
    return json.dumps(obj, default=str)


class Bridge(QObject):
    """Exposed to JS as window.bridge via QWebChannel."""

    # Signals the frontend can connect to
    poll_updated = pyqtSignal()
    notify = pyqtSignal(str, str)   # (type: "success"|"error"|"info", message)

    # -- Auth -------------------------------------------------------------------

    @pyqtSlot(str, str, result=str)
    def login(self, username: str, password: str) -> str:
        try:
            user = authenticate(username, password)
            if user:
                return _j({"ok": True, "user": user})
            # Show debug info so we can diagnose
            import hashlib
            from db.database import get_all_users, DB_PATH
            users = get_all_users()
            stored = users[0]["password_hash"] if users else "NO_USERS"
            given  = hashlib.sha256(password.encode()).hexdigest()
            debug  = "DB:{} users:{} stored:{}... given:{}...".format(
                str(DB_PATH), len(users), stored[:12], given[:12]
            )
            return _j({"ok": False, "error": "Invalid username or password", "debug": debug})
        except Exception as e:
            import traceback
            return _j({"ok": False, "error": "Exception: " + str(e), "trace": traceback.format_exc()})

    # -- Settings ---------------------------------------------------------------

    @pyqtSlot(result=str)
    def get_settings(self) -> str:
        return _j(db.get_all_settings())

    @pyqtSlot(str, str)
    def set_setting(self, key: str, value: str) -> None:
        db.set_setting(key, value)

    @pyqtSlot(str, result=str)
    def get_setting(self, key: str) -> str:
        return db.get_setting(key, "")

    @pyqtSlot(result=str)
    def is_sim_mode(self) -> str:
        return _j(is_sim())

    # -- DB stats ---------------------------------------------------------------

    @pyqtSlot(result=str)
    def get_db_stats(self) -> str:
        return _j(db.get_db_stats())

    # -- Switches ---------------------------------------------------------------

    @pyqtSlot(result=str)
    def get_switches(self) -> str:
        return _j(db.get_all_switches())

    @pyqtSlot(str, result=str)
    def get_switch(self, switch_id: str) -> str:
        return _j(db.get_switch(switch_id))

    @pyqtSlot(str, str, str, str, str, str, result=str)
    def create_switch(self, ip: str, hostname: str, display_name: str,
                      model: str, serial: str, notes: str) -> str:
        try:
            sw = db.create_switch(ip, hostname, display_name, model, serial, notes)
            return _j({"ok": True, "switch": sw})
        except Exception as e:
            return _j({"ok": False, "error": str(e)})

    @pyqtSlot(str, str, str, result=str)
    def update_switch(self, switch_id: str, display_name: str, notes: str) -> str:
        try:
            sw = db.update_switch(switch_id, display_name=display_name, notes=notes)
            return _j({"ok": True, "switch": sw})
        except Exception as e:
            return _j({"ok": False, "error": str(e)})

    @pyqtSlot(str, result=str)
    def delete_switch(self, switch_id: str) -> str:
        try:
            db.delete_switch(switch_id)
            return _j({"ok": True})
        except Exception as e:
            return _j({"ok": False, "error": str(e)})

    @pyqtSlot(str, str, result=str)
    def test_switch_connection(self, switch_id: str, ip: str) -> str:
        try:
            client = build_client(switch_id, ip)
            info = client.test_connectivity()
            return _j({"ok": True, "info": info})
        except Exception as e:
            return _j({"ok": False, "error": str(e)})

    @pyqtSlot(str, str, str, str, str, result=str)
    def store_switch_credentials(self, switch_id: str, ip: str,
                                  username: str, password: str, port: str = "8443") -> str:
        try:
            store_credentials(switch_id, username, password, int(port or 8443))
            return _j({"ok": True})
        except Exception as e:
            return _j({"ok": False, "error": str(e)})

    # -- VSANs --------------------------------------------------------------------

    @pyqtSlot(str, result=str)
    def get_switch_vsans(self, switch_id: str) -> str:
        """Return VSANs already stored in the DB for this switch."""
        return _j(db.get_vsans(switch_id))

    @pyqtSlot(str, str, result=str)
    def sync_vsans(self, switch_id: str, ip: str) -> str:
        """Run 'show vsan' on the switch and persist the discovered VSANs."""
        try:
            client = build_client(switch_id, ip)
            body = client.send_command("show vsan")
            vsans = parse_vsans(body)
            if not vsans:
                return _j({"ok": False, "error": "No VSANs returned by switch"})
            saved = db.replace_vsans(switch_id, vsans)
            return _j({"ok": True, "vsans": saved, "count": len(saved)})
        except Exception as e:
            import traceback
            return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()})

    # -- Aliases ----------------------------------------------------------------

    @pyqtSlot(str, result=str)
    def get_aliases(self, switch_id: str) -> str:
        return _j(db.get_aliases(switch_id))

    @pyqtSlot(str, str, str, str, result=str)
    def create_alias(self, switch_id: str, name: str, wwn: str, description: str) -> str:
        try:
            a = db.create_alias(switch_id, name, wwn, description)
            return _j({"ok": True, "alias": a})
        except Exception as e:
            return _j({"ok": False, "error": str(e)})

    @pyqtSlot(str, str, str, str, result=str)
    def update_alias(self, alias_id: str, name: str, wwn: str, description: str) -> str:
        try:
            a = db.update_alias(alias_id, name=name, wwn=wwn, description=description)
            return _j({"ok": True, "alias": a})
        except Exception as e:
            return _j({"ok": False, "error": str(e)})

    @pyqtSlot(str, result=str)
    def delete_alias(self, alias_id: str) -> str:
        try:
            db.delete_alias(alias_id)
            return _j({"ok": True})
        except Exception as e:
            return _j({"ok": False, "error": str(e)})

    @pyqtSlot(str, str, result=str)
    def sync_aliases(self, switch_id: str, ip: str) -> str:
        try:
            client = build_client(switch_id, ip)
            body = client.send_command("show device-alias database")
            aliases = parse_device_aliases(body)
            existing = {a["wwn"]: a for a in db.get_aliases(switch_id)}
            new_count = 0
            for a in aliases:
                if a["wwn"] not in existing:
                    db.create_alias(switch_id, a["name"], a["wwn"])
                    new_count += 1
                else:
                    db.update_alias(existing[a["wwn"]]["id"], synced_at=db._now())
            return _j({"ok": True, "total": len(aliases), "new": new_count})
        except Exception as e:
            return _j({"ok": False, "error": str(e)})

    # -- Zones ------------------------------------------------------------------

    @pyqtSlot(str, result=str)
    def get_zones(self, switch_id: str) -> str:
        return _j(db.get_zones(switch_id))

    @pyqtSlot(str, int, result=str)
    def get_zones_by_vsan(self, switch_id: str, vsan_id: int) -> str:
        return _j(db.get_zones(switch_id, vsan_id))

    @pyqtSlot(str, str, int, result=str)
    def create_zone(self, switch_id: str, name: str, vsan_id: int) -> str:
        try:
            z = db.create_zone(switch_id, name, vsan_id)
            return _j({"ok": True, "zone": z})
        except Exception as e:
            return _j({"ok": False, "error": str(e)})

    @pyqtSlot(str, str, result=str)
    def update_zone_name(self, zone_id: str, name: str) -> str:
        try:
            db.update_zone(zone_id, name=name)
            return _j({"ok": True})
        except Exception as e:
            return _j({"ok": False, "error": str(e)})

    @pyqtSlot(str, result=str)
    def delete_zone(self, zone_id: str) -> str:
        try:
            db.delete_zone(zone_id)
            return _j({"ok": True})
        except Exception as e:
            return _j({"ok": False, "error": str(e)})

    @pyqtSlot(str, str, str, result=str)
    def add_zone_member(self, zone_id: str, value: str, member_type: str) -> str:
        try:
            db.add_zone_member(zone_id, value, member_type)
            return _j({"ok": True})
        except Exception as e:
            return _j({"ok": False, "error": str(e)})

    @pyqtSlot(str, str, result=str)
    def remove_zone_member(self, zone_id: str, value: str) -> str:
        try:
            db.remove_zone_member(zone_id, value)
            return _j({"ok": True})
        except Exception as e:
            return _j({"ok": False, "error": str(e)})

    @pyqtSlot(str, str, result=str)
    def replace_zone_members(self, zone_id: str, members_json: str) -> str:
        """Replace all members of a zone atomically."""
        try:
            members = json.loads(members_json)
            from db.database import get_db
            with get_db() as conn:
                conn.execute("DELETE FROM zone_members WHERE zone_id=?", (zone_id,))
            for m in members:
                db.add_zone_member(zone_id, m["value"], m.get("type", "PWWN"))
            return _j({"ok": True})
        except Exception as e:
            return _j({"ok": False, "error": str(e)})

    # -- Zone Sets --------------------------------------------------------------

    @pyqtSlot(str, result=str)
    def get_zone_sets(self, switch_id: str) -> str:
        return _j(db.get_zone_sets(switch_id))

    @pyqtSlot(str, int, result=str)
    def get_zone_sets_by_vsan(self, switch_id: str, vsan_id: int) -> str:
        return _j(db.get_zone_sets(switch_id, vsan_id))

    @pyqtSlot(str, str, int, result=str)
    def create_zone_set(self, switch_id: str, name: str, vsan_id: int) -> str:
        try:
            zs = db.create_zone_set(switch_id, name, vsan_id)
            return _j({"ok": True, "zone_set": zs})
        except Exception as e:
            return _j({"ok": False, "error": str(e)})

    @pyqtSlot(str, result=str)
    def delete_zone_set(self, zs_id: str) -> str:
        try:
            db.delete_zone_set(zs_id)
            return _j({"ok": True})
        except Exception as e:
            return _j({"ok": False, "error": str(e)})

    @pyqtSlot(str, str, str, result=str)
    def update_zone_set_members(self, zs_id: str, name: str, zone_ids_json: str) -> str:
        """Update zone set name and replace all its zone members."""
        try:
            zone_ids = json.loads(zone_ids_json)
            from db.database import get_db
            with get_db() as conn:
                conn.execute("UPDATE zone_sets SET name=?, updated_at=? WHERE id=?",
                             (name, db._now(), zs_id))
                conn.execute("DELETE FROM zone_set_members WHERE zone_set_id=?", (zs_id,))
            for zid in zone_ids:
                db.add_zone_to_set(zs_id, zid)
            return _j({"ok": True})
        except Exception as e:
            return _j({"ok": False, "error": str(e)})

    @pyqtSlot(str, str, int, result=str)
    def activate_zone_set(self, zs_id: str, switch_id: str, vsan_id: int) -> str:
        try:
            from db.database import get_db
            with get_db() as conn:
                conn.execute("UPDATE zone_sets SET is_active=0 WHERE switch_id=? AND vsan_id=?",
                             (switch_id, vsan_id))
                conn.execute("UPDATE zone_sets SET is_active=1 WHERE id=?", (zs_id,))
            return _j({"ok": True})
        except Exception as e:
            return _j({"ok": False, "error": str(e)})

    # -- Commit to switch -------------------------------------------------------

    @pyqtSlot(str, str, int, str, result=str)
    def commit_zones(self, switch_id: str, ip: str, vsan_id: int, username: str) -> str:
        try:
            zones = db.get_zones(switch_id, vsan_id)
            zone_sets = db.get_zone_sets(switch_id, vsan_id)
            # Pre-commit snapshot
            db.create_snapshot(switch_id, vsan_id, {"zones": zones, "zone_sets": zone_sets},
                               trigger="PRE_COMMIT", triggered_by=username)
            client = build_client(switch_id, ip)
            cmds = ["conf t"]
            for z in zones:
                cmds.append(f"zone name {z['name']} vsan {vsan_id}")
                for m in z.get("members", []):
                    t = m.get("member_type", "PWWN")
                    if t == "DEVICE_ALIAS":
                        cmds.append(f"  member device-alias {m['value']}")
                    else:
                        cmds.append(f"  member pwwn {m['value']}")
            for zs in zone_sets:
                cmds.append(f"zoneset name {zs['name']} vsan {vsan_id}")
                for zm in zs.get("zone_members", []):
                    cmds.append(f"  member {zm['name']}")
                if zs.get("is_active"):
                    cmds.append(f"zoneset activate name {zs['name']} vsan {vsan_id}")
            cmds.append("end")
            client.send_config(cmds)
            now = db._now()
            for z in zones:
                db.update_zone(z["id"], is_draft=False, synced_at=now)
            return _j({"ok": True})
        except Exception as e:
            return _j({"ok": False, "error": str(e)})

    @pyqtSlot(str, str, int, result=str)
    def pull_zones(self, switch_id: str, ip: str, vsan_id: int) -> str:
        try:
            client  = build_client(switch_id, ip)
            imported = 0

            # Pull individual zones via "show zone vsan X"
            zone_body = client.send_command(f"show zone vsan {vsan_id}")
            zones_data = parse_zones(zone_body, vsan_id)
            zone_name_to_id = {}
            for z_data in zones_data:
                existing = next((z for z in db.get_zones(switch_id, vsan_id)
                                 if z["name"] == z_data["name"]), None)
                if existing:
                    zone_name_to_id[z_data["name"]] = existing["id"]
                else:
                    zone = db.create_zone(switch_id, z_data["name"], vsan_id, is_draft=False)
                    zone_name_to_id[z_data["name"]] = zone["id"]
                    for mem in z_data["members"]:
                        t = "DEVICE_ALIAS" if mem["type"] == "device_alias" else "PWWN"
                        db.add_zone_member(zone["id"], mem["value"], t)
                    imported += 1

            # Pull zone sets via "show zoneset vsan X"
            zs_body = client.send_command(f"show zoneset vsan {vsan_id}")
            for zs_data in parse_zone_sets(zs_body):
                if not any(zs["name"] == zs_data["name"]
                           for zs in db.get_zone_sets(switch_id, vsan_id)):
                    zs = db.create_zone_set(switch_id, zs_data["name"], vsan_id)
                    if zs_data.get("is_active"):
                        from db.database import get_db
                        with get_db() as conn:
                            conn.execute("UPDATE zone_sets SET is_active=1 WHERE id=?", (zs["id"],))
                    for z_info in zs_data.get("zones", []):
                        zname = z_info["name"] if isinstance(z_info, dict) else z_info
                        if zname in zone_name_to_id:
                            db.add_zone_to_set(zs["id"], zone_name_to_id[zname])

            return _j({"ok": True, "imported": imported})
        except Exception as e:
            import traceback
            return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()})

    # -- Snapshots --------------------------------------------------------------

    @pyqtSlot(str, result=str)
    def get_snapshots(self, switch_id: str) -> str:
        return _j(db.get_snapshots(switch_id, limit=100))

    @pyqtSlot(str, result=str)
    def get_snapshot_payload(self, snap_id: str) -> str:
        snap = db.get_snapshot(snap_id)
        if snap:
            return snap["payload"]
        return "null"

    @pyqtSlot(str, str, result=str)
    def take_snapshot(self, switch_id: str, username: str) -> str:
        try:
            zones = db.get_zones(switch_id)
            zone_sets = db.get_zone_sets(switch_id)
            db.create_snapshot(switch_id, 0, {"zones": zones, "zone_sets": zone_sets},
                               trigger="MANUAL", triggered_by=username)
            return _j({"ok": True})
        except Exception as e:
            return _j({"ok": False, "error": str(e)})

    @pyqtSlot(str, str, result=str)
    def restore_snapshot(self, snap_id: str, switch_id: str) -> str:
        try:
            import json as _json
            snap = db.get_snapshot(snap_id)
            if not snap:
                return _j({"ok": False, "error": "Snapshot not found"})
            payload = _json.loads(snap["payload"])
            vsan_id = snap["vsan_id"]
            for z in db.get_zones(switch_id, vsan_id):
                if z.get("is_draft"):
                    db.delete_zone(z["id"])
            for z in payload.get("zones", []):
                new_z = db.create_zone(switch_id, z["name"], z.get("vsan_id", vsan_id))
                for m in z.get("members", []):
                    db.add_zone_member(new_z["id"], m["value"], m.get("member_type", "PWWN"))
            return _j({"ok": True})
        except Exception as e:
            return _j({"ok": False, "error": str(e)})

    # -- Live switch data -------------------------------------------------------

    @pyqtSlot(str, str, result=str)
    def get_inventory(self, switch_id: str, ip: str) -> str:
        try:
            client = build_client(switch_id, ip)
            # Use show interface brief -- lighter, returns state+speed+vsan per port
            body  = client.send_command("show interface brief")
            ports = parse_interface_brief(body)
            # Enrich with peer WWN from show flogi database
            try:
                flogi_body = client.send_command("show flogi database")
                flogi_rows = flogi_body.get("TABLE_flogi_entry", {}).get("ROW_flogi_entry", [])
                if isinstance(flogi_rows, dict): flogi_rows = [flogi_rows]
                # Map interface -> peer wwn
                flogi_map = {r.get("interface","").strip(): r.get("port_name","").strip().lower()
                             for r in flogi_rows if r.get("interface") and r.get("port_name")}
            except Exception:
                flogi_map = {}
            aliases = {a["wwn"]: a["name"] for a in db.get_aliases(switch_id)}
            result = []
            for p in ports:
                peer_wwn = flogi_map.get(p["name"], "")
                result.append({
                    "name":     p["name"],
                    "state":    p["state"],
                    "mode":     p["mode"],
                    "speed":    p["speed"],
                    "vsan":     str(p["vsan_id"]) if p["vsan_id"] else "--",
                    "peer_wwn": peer_wwn,
                    "alias":    aliases.get(peer_wwn, ""),
                })
            return _j({"ok": True, "ports": result})
        except Exception as e:
            import traceback
            return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()})

    @pyqtSlot(str, str, int, result=str)
    def get_fcns(self, switch_id: str, ip: str, vsan_id: int) -> str:
        try:
            client = build_client(switch_id, ip)
            fcns = parse_fcns(client.send_command(f"show fcns database detail vsan {vsan_id}"))
            return _j({"ok": True, "entries": fcns})
        except Exception as e:
            return _j({"ok": False, "error": str(e)})

    @pyqtSlot(str, str, result=str)
    def get_sfp(self, switch_id: str, ip: str) -> str:
        try:
            client = build_client(switch_id, ip)
            if hasattr(client, "increment_poll"):
                client.increment_poll()
            # show interface transceiver -- returns per-port SFP diagnostic values
            body  = client.send_command("show interface transceiver")
            xcvrs = parse_transceiver(body)
            return _j({"ok": True, "xcvrs": xcvrs})
        except Exception as e:
            import traceback
            return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()})

    # -- Metrics ----------------------------------------------------------------

    @pyqtSlot(str, result=str)
    def get_top_ports(self, switch_id: str) -> str:
        return _j(db.get_top_ports(switch_id, limit=10))

    @pyqtSlot(str, result=str)
    def get_interfaces(self, switch_id: str) -> str:
        return _j(db.get_distinct_interfaces(switch_id))

    @pyqtSlot(str, str, int, result=str)
    def get_port_history(self, switch_id: str, interface: str, limit: int) -> str:
        return _j(db.get_metrics_history(switch_id, interface, limit=limit))

    # -- Users ------------------------------------------------------------------

    @pyqtSlot(result=str)
    def get_users(self) -> str:
        return _j(db.get_all_users())

    @pyqtSlot(str, str, str, str, result=str)
    def create_user(self, email: str, username: str, password: str, role: str) -> str:
        try:
            u = db.create_user(email, username, hash_password(password), role)
            return _j({"ok": True, "user": u})
        except Exception as e:
            return _j({"ok": False, "error": str(e)})

    @pyqtSlot(str, str, str, str, result=str)
    def update_user(self, uid: str, email: str, role: str, password: str) -> str:
        try:
            kwargs = {"email": email, "role": role}
            if password:
                kwargs["password_hash"] = hash_password(password)
            u = db.update_user(uid, **kwargs)
            return _j({"ok": True, "user": u})
        except Exception as e:
            return _j({"ok": False, "error": str(e)})

    @pyqtSlot(str, result=str)
    def delete_user(self, uid: str) -> str:
        try:
            db.delete_user(uid)
            return _j({"ok": True})
        except Exception as e:
            return _j({"ok": False, "error": str(e)})

    @pyqtSlot(str, result=str)
    def get_sim_ports(self, ip: str) -> str:
        try:
            from services.mds_simulator import get_sim_ports
            return _j(get_sim_ports(ip))
        except Exception as e:
            return _j([])

    @pyqtSlot(str, str, result=str)
    def save_sim_ports(self, ip: str, ports_json: str) -> str:
        try:
            import json as _json
            from services.mds_simulator import save_sim_ports
            ports = _json.loads(ports_json)
            save_sim_ports(ip, ports)
            return _j({"ok": True})
        except Exception as e:
            return _j({"ok": False, "error": str(e)})

    @pyqtSlot(str, result=str)
    def reset_sim_ports(self, ip: str) -> str:
        try:
            from services.mds_simulator import default_ports, save_sim_ports
            ports = default_ports(ip)
            save_sim_ports(ip, ports)
            return _j({"ok": True, "ports": ports})
        except Exception as e:
            return _j({"ok": False, "error": str(e)})


    @pyqtSlot(str, result=str)
    def save_backup_file(self, json_str: str) -> str:
        """Open a native Save dialog and write the backup JSON to the chosen path."""
        try:
            from PyQt5.QtWidgets import QFileDialog
            import datetime
            default_name = 'san_backup_' + datetime.datetime.now().strftime('%Y-%m-%d') + '.json'
            path, _ = QFileDialog.getSaveFileName(
                None,
                'Save Backup',
                default_name,
                'JSON Files (*.json);;All Files (*)'
            )
            if not path:
                return _j({'ok': False, 'cancelled': True})
            with open(path, 'w', encoding='utf-8') as f:
                f.write(json_str)
            return _j({'ok': True, 'path': path})
        except Exception as e:
            return _j({'ok': False, 'error': str(e)})


    @pyqtSlot(result=str)
    def get_db_path(self) -> str:
        from db.database import DB_PATH
        return str(DB_PATH)

    @pyqtSlot(result=str)
    def export_backup(self) -> str:
        import json
        switches = db.get_all_switches()
        for sw in switches:
            sid = sw['id']
            sw['aliases']   = db.get_aliases(sid)
            sw['zones']     = db.get_zones(sid)
            sw['zone_sets'] = db.get_zone_sets(sid)
            sw['snapshots'] = db.get_snapshots(sid, limit=500)
        payload = {
            'version': '5.0',
            'exported_at': __import__('datetime').datetime.now().isoformat(),
            'switches': switches,
            'settings': db.get_all_settings(),
        }
        return json.dumps(payload, default=str, indent=2)

    @pyqtSlot(str, result=str)
    def import_backup(self, json_str: str) -> str:
        try:
            import json
            backup = json.loads(json_str)
            for sw_data in backup.get('switches', []):
                existing = next((s for s in db.get_all_switches()
                                 if s['ip_address'] == sw_data['ip_address']), None)
                if not existing:
                    existing = db.create_switch(sw_data['ip_address'],
                                               sw_data.get('hostname',''),
                                               sw_data.get('display_name',''))
                sid = existing['id']
                for a in sw_data.get('aliases', []):
                    try: db.create_alias(sid, a['name'], a['wwn'], a.get('description',''))
                    except Exception: pass
            return _j({'ok': True})
        except Exception as e:
            return _j({'ok': False, 'error': str(e)})

    @pyqtSlot(result=str)
    def purge_metrics(self) -> str:
        try:
            from db.database import get_db
            with get_db() as conn:
                deleted = conn.execute('DELETE FROM port_metrics').rowcount
            return _j({'ok': True, 'deleted': deleted})
        except Exception as e:
            return _j({'ok': False, 'error': str(e)})


