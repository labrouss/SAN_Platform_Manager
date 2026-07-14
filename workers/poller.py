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

poller.py -- Background polling worker.
Polls all active switches every N seconds (default 60).
Collects counters + transceiver data and writes to SQLite.
"""
from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Callable

from db import database as db
from services.client_factory import (
    build_client, parse_counters, parse_transceiver, is_sim
)

# In-memory counter state for delta calculations
_prev_counters: dict[str, dict] = {}  # key: "switch_id::iface"


class MdsPoller:
    def __init__(self, on_update: Callable | None = None):
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self.on_update = on_update  # optional callback after each poll

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="MdsPoller")
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def poll_interval(self) -> int:
        try:
            return int(db.get_setting("poll_interval_sec", "60"))
        except ValueError:
            return 60

    def _run(self) -> None:
        while not self._stop_event.is_set():
            self._poll_all()
            self._stop_event.wait(self.poll_interval())

    def _poll_all(self) -> None:
        switches = db.get_all_switches()
        for sw in switches:
            try:
                self._poll_switch(sw)
            except Exception as e:
                print(f"[Poller] Error polling {sw['ip_address']}: {e}")
        if self.on_update:
            try:
                self.on_update()
            except Exception:
                pass

    def _poll_switch(self, sw: dict) -> None:
        switch_id  = sw["id"]
        ip         = sw["ip_address"]
        client     = build_client(switch_id, ip)

        # Increment simulator poll count
        if is_sim() and hasattr(client, "increment_poll"):
            client.increment_poll()

        now = datetime.now(timezone.utc)

        # -- counters -----------------------------------------------------------
        try:
            body = client.send_command("show interface counters")
            counters = parse_counters(body)
        except Exception as e:
            print(f"[Poller] counters failed for {ip}: {e}")
            counters = []

        # -- transceiver --------------------------------------------------------
        try:
            tbody = client.send_command("show interface transceiver")
            xcvrs = {x["interface"]: x for x in parse_transceiver(tbody)}
        except Exception:
            xcvrs = {}

        # -- write metrics ------------------------------------------------------
        for ctr in counters:
            iface = ctr["interface"]
            prev_key = f"{switch_id}::{iface}"
            prev = _prev_counters.get(prev_key)

            # Prefer the switch's own hardware-computed rate (rx_rate_bits_ps /
            # tx_rate_bits_ps from "show interface counters") -- it reflects
            # the switch's internal sampling window, not ours, and is
            # available even on the very first poll (no history needed).
            # Only fall back to our own byte-delta calculation if the switch
            # didn't report a rate at all (e.g. very old NX-OS).
            tx_rate = ctr.get("tx_rate_bps")
            rx_rate = ctr.get("rx_rate_bps")

            if tx_rate is None or rx_rate is None:
                if prev:
                    dt = (now - prev["ts"]).total_seconds()
                    if dt > 0:
                        if tx_rate is None:
                            tx_rate = max(0.0, (ctr["tx_bytes"] - prev["tx_bytes"]) / dt * 8)
                        if rx_rate is None:
                            rx_rate = max(0.0, (ctr["rx_bytes"] - prev["rx_bytes"]) / dt * 8)

            _prev_counters[prev_key] = {
                "tx_bytes": ctr["tx_bytes"],
                "rx_bytes": ctr["rx_bytes"],
                "ts": now,
            }

            xcvr = xcvrs.get(iface, {})
            db.insert_metric(
                switch_id=switch_id,
                interface_name=iface,
                tx_bytes=ctr["tx_bytes"],
                rx_bytes=ctr["rx_bytes"],
                crc_errors=ctr["rx_crc_err"],
                link_failures=ctr["link_failures"],
                tx_rate_bps=tx_rate,
                rx_rate_bps=rx_rate,
                rx_power_dbm=xcvr.get("rx_power_dbm"),
                tx_power_dbm=xcvr.get("tx_power_dbm"),
                temperature=xcvr.get("temperature"),
                voltage=xcvr.get("voltage"),
                current_ma=xcvr.get("current_ma"),
            )

        # Update switch last_seen_at
        db.update_switch(switch_id, last_seen_at=now.isoformat())
