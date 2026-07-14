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

    @pyqtSlot(str, str, str, result=str)
    def commit_aliases(self, switch_id: str, ip: str, username: str) -> str:
        """Push all local (un-synced) device aliases to the switch via NX-API."""
        try:
            aliases = db.get_aliases(switch_id)
            if not aliases:
                return _j({"ok": False, "error": "No aliases to commit"})

            client = build_client(switch_id, ip)
            cmds = ["conf t", "device-alias database"]
            for a in aliases:
                # device-alias name <name> pwwn <wwn>
                cmds.append(f"  device-alias name {a['name']} pwwn {a['wwn']}")
            cmds.append("device-alias commit")
            cmds.append("end")
            client.send_config(cmds)

            now = db._now()
            for a in aliases:
                db.update_alias(a["id"], synced_at=now)

            return _j({"ok": True, "count": len(aliases)})
        except Exception as e:
            import traceback
            return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()})


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
            # Renaming a zone invalidates any prior commit -- the switch
            # still has the OLD name. Reset to draft so delete/commit logic
            # doesn't assume the switch matches the new name.
            db.update_zone(zone_id, name=name, is_draft=True, synced_at=None)
            return _j({"ok": True})
        except Exception as e:
            return _j({"ok": False, "error": str(e)})

    @pyqtSlot(str, str, result=str)
    def delete_zone(self, zone_id: str, ip: str = "") -> str:
        try:
            zone = db.get_zone_by_id(zone_id)
            if zone is None:
                return _j({"ok": False, "error": "Zone not found"})

            # Only push a removal command to the switch if it was ever
            # committed there (synced_at set) -- a pure local draft has
            # nothing on the switch to remove. Use last_synced_name (the
            # name actually pushed) in case it was renamed after commit.
            if zone.get("synced_at") and ip:
                switch_name = zone.get("last_synced_name") or zone["name"]
                try:
                    client = build_client(zone["switch_id"], ip)
                    cmds = [
                        "conf t",
                        f"no zone name {switch_name} vsan {zone['vsan_id']}",
                        "end",
                    ]
                    client.send_config(cmds)
                except Exception as e:
                    return _j({"ok": False,
                               "error": f"Failed to remove zone from switch: {e}"})

            db.delete_zone(zone_id)
            return _j({"ok": True})
        except Exception as e:
            import traceback
            return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()})

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
            # Member list changed -- the switch's copy (if any) is now stale.
            db.update_zone(zone_id, is_draft=True, synced_at=None)
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

    @pyqtSlot(str, str, result=str)
    def delete_zone_set(self, zs_id: str, ip: str = "") -> str:
        try:
            zs = db.get_zone_set_by_id(zs_id)
            if zs is None:
                return _j({"ok": False, "error": "Zone set not found"})

            if zs.get("synced_at") and ip:
                switch_name = zs.get("last_synced_name") or zs["name"]
                try:
                    client = build_client(zs["switch_id"], ip)
                    cmds = [
                        "conf t",
                        f"no zoneset name {switch_name} vsan {zs['vsan_id']}",
                        "end",
                    ]
                    client.send_config(cmds)
                except Exception as e:
                    return _j({"ok": False,
                               "error": f"Failed to remove zone set from switch: {e}"})

            db.delete_zone_set(zs_id)
            return _j({"ok": True})
        except Exception as e:
            import traceback
            return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()})

    @pyqtSlot(str, str, str, result=str)
    def update_zone_set_members(self, zs_id: str, name: str, zone_ids_json: str) -> str:
        """Update zone set name and replace all its zone members."""
        try:
            zone_ids = json.loads(zone_ids_json)
            from db.database import get_db
            with get_db() as conn:
                # Renaming or changing membership invalidates any prior
                # commit -- the switch still has the OLD name/members.
                # Reset to draft/unsynced so delete/commit logic doesn't
                # assume the switch matches this new state.
                conn.execute(
                    "UPDATE zone_sets SET name=?, is_draft=1, synced_at=NULL, updated_at=? WHERE id=?",
                    (name, db._now(), zs_id)
                )
                conn.execute("DELETE FROM zone_set_members WHERE zone_set_id=?", (zs_id,))
            for zid in zone_ids:
                db.add_zone_to_set(zs_id, zid)
            return _j({"ok": True})
        except Exception as e:
            return _j({"ok": False, "error": str(e)})

    @pyqtSlot(str, str, int, str, result=str)
    def activate_zone_set(self, zs_id: str, switch_id: str, vsan_id: int, ip: str = "") -> str:
        try:
            from db.database import get_db
            with get_db() as conn:
                conn.execute("UPDATE zone_sets SET is_active=0 WHERE switch_id=? AND vsan_id=?",
                             (switch_id, vsan_id))
                conn.execute("UPDATE zone_sets SET is_active=1 WHERE id=?", (zs_id,))

            zs = db.get_zone_set_by_id(zs_id)
            if zs is None:
                return _j({"ok": False, "error": "Zone set not found"})

            if not ip:
                # No switch context (e.g. simulator disabled, no IP known) --
                # local-only activation, will be pushed on the next full commit.
                return _j({"ok": True})

            # If this zone set has pending local edits (synced_at cleared by
            # a rename or membership change, or it was never committed at
            # all), a bare "zoneset activate name X" is not enough -- the
            # switch may not even have this zone set/membership yet, or may
            # have it under stale content. Push the FULL current zone set
            # (and its member zones) to the switch first via the same logic
            # commit_zones uses, THEN activate. This guarantees Activate
            # always reflects what's actually on the switch afterward,
            # instead of silently no-op'ing when synced_at happens to be
            # None (e.g. right after re-saving membership).
            if not zs.get("synced_at"):
                commit_result = json.loads(self.commit_zones(switch_id, ip, vsan_id, "system"))
                if not commit_result.get("ok"):
                    return _j({"ok": False,
                               "error": f"Failed to commit zone set before activating: {commit_result.get('error')}"})
                # Re-fetch -- commit_zones just updated synced_at/last_synced_name
                zs = db.get_zone_set_by_id(zs_id)

            switch_name = zs.get("last_synced_name") or zs["name"]
            try:
                client = build_client(switch_id, ip)
                cmds = [
                    "conf t",
                    f"zoneset activate name {switch_name} vsan {vsan_id}",
                    "end",
                ]
                client.send_config(cmds)
            except Exception as e:
                return _j({"ok": False,
                           "error": f"Activated locally but failed to push to switch: {e}"})

            return _j({"ok": True})
        except Exception as e:
            import traceback
            return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()})

    # -- Commit to switch -------------------------------------------------------

    @pyqtSlot(str, str, int, str, result=str)
    def commit_zones(self, switch_id: str, ip: str, vsan_id: int, username: str) -> str:
        try:
            # Always sync first: reconcile any zone/zone-set that has no
            # pending local edit against the switch's current state, so we
            # never blindly overwrite changes made outside this app. Zones
            # the user is actively editing (is_draft=1) are left untouched
            # here -- they get pushed as-is below.
            try:
                self._pull_zones_impl(switch_id, ip, vsan_id, only_clean=True)
            except Exception:
                pass  # if pre-sync fails (e.g. switch briefly unreachable), still attempt commit

            zones = db.get_zones(switch_id, vsan_id)
            zone_sets = db.get_zone_sets(switch_id, vsan_id)
            # Pre-commit snapshot
            db.create_snapshot(switch_id, vsan_id, {"zones": zones, "zone_sets": zone_sets},
                               trigger="PRE_COMMIT", triggered_by=username)
            client = build_client(switch_id, ip)
            cmds = ["conf t"]

            # If a zone/zone-set was renamed since its last successful commit,
            # remove the OLD name from the switch first so we don't leave an
            # orphaned duplicate behind under the previous name.
            for z in zones:
                old_name = z.get("last_synced_name")
                if old_name and old_name != z["name"]:
                    cmds.append(f"no zone name {old_name} vsan {vsan_id}")
            for zs in zone_sets:
                old_name = zs.get("last_synced_name")
                if old_name and old_name != zs["name"]:
                    cmds.append(f"no zoneset name {old_name} vsan {vsan_id}")

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
                db.update_zone(z["id"], is_draft=False, synced_at=now, last_synced_name=z["name"])
            if zone_sets:
                from db.database import get_db
                with get_db() as conn:
                    for zs in zone_sets:
                        conn.execute(
                            "UPDATE zone_sets SET is_draft=0, synced_at=?, last_synced_name=? WHERE id=?",
                            (now, zs["name"], zs["id"])
                        )
            return _j({"ok": True})
        except Exception as e:
            import traceback
            return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()})

    @pyqtSlot(str, str, int, result=str)
    def _pull_zones_impl(self, switch_id: str, ip: str, vsan_id: int,
                          only_clean: bool = False) -> dict:
        """Core pull logic, reusable by both the pull_zones slot and
        commit_zones (which must sync first to avoid clobbering
        switch-side changes made outside the app).

        only_clean: if True, skip reconciling any local zone/zone-set that
        currently has unsaved local edits (is_draft=1, i.e. the user changed
        it since the last commit) so an automatic pre-commit sync never
        discards work the user is about to push. Explicit user-triggered
        pulls (the Pull button) pass only_clean=False and always overwrite.
        """
        client  = build_client(switch_id, ip)
        now = db._now()
        imported = 0
        updated = 0

        # -- Zones: "show zone vsan X" --------------------------------------
        zone_body = client.send_command(f"show zone vsan {vsan_id}")
        zones_data = parse_zones(zone_body, vsan_id)
        zone_name_to_id = {}
        existing_zones = {z["name"]: z for z in db.get_zones(switch_id, vsan_id)}

        for z_data in zones_data:
            existing = existing_zones.get(z_data["name"])
            if existing:
                zone_id = existing["id"]
                zone_name_to_id[z_data["name"]] = zone_id
                if only_clean and existing.get("is_draft"):
                    # User has a pending local edit -- don't overwrite it,
                    # this zone will be pushed as-is by the commit that follows.
                    continue
                from db.database import get_db
                with get_db() as conn:
                    conn.execute("DELETE FROM zone_members WHERE zone_id=?", (zone_id,))
                for mem in z_data["members"]:
                    t = "DEVICE_ALIAS" if mem["type"] == "device_alias" else "PWWN"
                    db.add_zone_member(zone_id, mem["value"], t)
                db.update_zone(zone_id, is_draft=False, synced_at=now,
                               last_synced_name=z_data["name"])
                updated += 1
            else:
                zone = db.create_zone(switch_id, z_data["name"], vsan_id, is_draft=False)
                zone_name_to_id[z_data["name"]] = zone["id"]
                # Track it immediately so a duplicate name later in this same
                # switch response updates instead of re-creating (which would
                # otherwise violate the (switch_id, name, vsan_id) UNIQUE
                # constraint if a switch ever returns the same name twice).
                existing_zones[z_data["name"]] = zone
                for mem in z_data["members"]:
                    t = "DEVICE_ALIAS" if mem["type"] == "device_alias" else "PWWN"
                    db.add_zone_member(zone["id"], mem["value"], t)
                db.update_zone(zone["id"], synced_at=now, last_synced_name=z_data["name"])
                imported += 1

        # -- Zone sets: "show zoneset vsan X" -------------------------------
        zs_body = client.send_command(f"show zoneset vsan {vsan_id}")
        existing_zs = {zs["name"]: zs for zs in db.get_zone_sets(switch_id, vsan_id)}
        from db.database import get_db

        for zs_data in parse_zone_sets(zs_body):
            existing = existing_zs.get(zs_data["name"])
            zone_ids = []
            for z_info in zs_data.get("zones", []):
                zname = z_info["name"] if isinstance(z_info, dict) else z_info
                if zname in zone_name_to_id:
                    zone_ids.append(zone_name_to_id[zname])

            if existing:
                zs_id = existing["id"]
                if only_clean and existing.get("is_draft"):
                    continue
                with get_db() as conn:
                    conn.execute(
                        "UPDATE zone_sets SET is_active=?, is_draft=0, synced_at=?, "
                        "last_synced_name=?, updated_at=? WHERE id=?",
                        (1 if zs_data.get("is_active") else 0, now,
                         zs_data["name"], now, zs_id)
                    )
                    conn.execute("DELETE FROM zone_set_members WHERE zone_set_id=?", (zs_id,))
                for zid in zone_ids:
                    db.add_zone_to_set(zs_id, zid)
                updated += 1
            else:
                zs = db.create_zone_set(switch_id, zs_data["name"], vsan_id)
                # Track it immediately so a duplicate zoneset name later in
                # this same switch response updates instead of re-creating.
                existing_zs[zs_data["name"]] = zs
                with get_db() as conn:
                    conn.execute(
                        "UPDATE zone_sets SET is_active=?, is_draft=0, synced_at=?, "
                        "last_synced_name=? WHERE id=?",
                        (1 if zs_data.get("is_active") else 0, now, zs_data["name"], zs["id"])
                    )
                for zid in zone_ids:
                    db.add_zone_to_set(zs["id"], zid)
                imported += 1

        return {"ok": True, "imported": imported, "updated": updated}

    @pyqtSlot(str, str, int, result=str)
    def pull_zones(self, switch_id: str, ip: str, vsan_id: int) -> str:
        try:
            return _j(self._pull_zones_impl(switch_id, ip, vsan_id, only_clean=False))
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
    def get_all_pwwns(self, switch_id: str, ip: str) -> str:
        """
        Return every pWWN currently known to the switch across all VSANs,
        pulled from the FCNS name server database. Used to populate the
        PWWN dropdown when creating/editing an FC alias, so the user picks
        from what is actually attached rather than typing a WWN by hand.
        """
        try:
            client = build_client(switch_id, ip)
            fcns = parse_fcns(client.send_command("show fcns database detail"))
            seen = set()
            result = []
            for e in fcns:
                pwwn = e.get("pwwn")
                if not pwwn or pwwn in seen:
                    continue
                seen.add(pwwn)
                result.append({
                    "pwwn": pwwn,
                    "vsan_id": e.get("vsan_id"),
                    "vendor": e.get("vendor"),
                    "interface": e.get("connected_interface"),
                    "symbolic_port_name": e.get("symbolic_port_name"),
                })
            return _j({"ok": True, "pwwns": result})
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

    @pyqtSlot(str, str, result=str)
    def poll_now(self, switch_id: str, ip: str) -> str:
        """
        Trigger an immediate, synchronous poll of a single switch (counters
        + transceiver), writing fresh metrics to the DB right away.

        The background MdsPoller thread only polls on its own fixed
        schedule (poll_interval_sec, default 60s) -- it has no awareness
        of the Performance tab's real-time refresh button. Without this,
        clicking "Start Real-Time" at a 5s interval just re-reads the same
        stale DB row until the background poller's own next cycle happens
        to land, so the charts never actually move on the requested
        cadence. This method lets the UI force a poll on-demand, at
        whatever interval the user picked.
        """
        try:
            sw = db.get_switch(switch_id)
            if sw is None:
                return _j({"ok": False, "error": "Switch not found"})
            from workers.poller import MdsPoller
            MdsPoller()._poll_switch(sw)
            return _j({"ok": True})
        except Exception as e:
            import traceback
            return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()})

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

    @pyqtSlot(str, int, int, result=str)
    def attach_random_devices(self, ip: str, vsan_id: int, count: int) -> str:
        """
        Instructor/training helper: attach `count` random simulated devices
        to random currently-available ports in the given VSAN. Creates a
        random pWWN + matching device-alias for each, and sets the chosen
        ports to VSAN `vsan_id`, state up, with an SFP present. Intended
        for quickly populating a classroom/demo fabric without manually
        configuring each port and alias by hand.
        """
        try:
            import random
            from services.mds_simulator import get_sim_ports, save_sim_ports, _make_wwn

            ports = get_sim_ports(ip)
            if not ports:
                return _j({"ok": False, "error": "No simulated ports found for this switch"})

            # Prefer ports not already assigned to this VSAN and not already
            # "up" with a device attached, so we don't clobber an existing
            # demo device -- but fall back to any port if there aren't
            # enough free ones, since this is an instructor convenience
            # tool, not a strict allocator.
            candidates = [p for p in ports if p["vsan_id"] != vsan_id or p["state"] == "down"]
            if len(candidates) < count:
                candidates = list(ports)
            if not candidates:
                return _j({"ok": False, "error": "No ports available on this switch"})

            random.shuffle(candidates)
            chosen = candidates[:min(count, len(candidates))]

            device_prefixes = ["Host", "Server", "Storage", "Backup", "DR", "Tape", "Array"]
            created_aliases = []

            for i, port in enumerate(chosen):
                port["vsan_id"] = vsan_id
                port["state"] = "up"
                port["sfp_present"] = True

                seed = random.randint(0, 0xFFFFFF)
                pwwn = _make_wwn("21:00:00:24", ip, (seed + i) & 0xFF)
                prefix = random.choice(device_prefixes)
                alias_name = f"{prefix}_{random.randint(1,99):02d}_HBA_{chr(65 + i % 4)}"

                try:
                    alias = db.create_alias(_switch_id_for_ip(ip), alias_name, pwwn,
                                             f"Auto-attached to {port['name']} (instructor tool)")
                    created_aliases.append({"name": alias_name, "pwwn": pwwn, "port": port["name"]})
                except Exception:
                    # Name collision or similar -- skip this one, still attach the port
                    created_aliases.append({"name": None, "pwwn": pwwn, "port": port["name"]})

            save_sim_ports(ip, ports)

            return _j({"ok": True, "attached": created_aliases, "vsan_id": vsan_id})
        except Exception as e:
            import traceback
            return _j({"ok": False, "error": str(e), "trace": traceback.format_exc()})


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


