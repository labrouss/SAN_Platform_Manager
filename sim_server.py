#!/usr/bin/env python3
"""
sim_server.py -- Standalone NX-API-compatible HTTP server wrapping
MdsSimulator, for running the simulator in its own Docker container.

Exposes POST /ins-api accepting the same {"ins_api": {...}} JSON body
real Cisco MDS switches accept, so any NX-API client (including this
app's own MdsClient, or third-party tools) can point at it as if it
were a real switch.

Environment variables:
    SAN_SIM_STARTUP_CONFIG  Path to a startup-config file to seed the
                            simulated switch from (see startup_config.py
                            for supported syntax). If unset, the simulator
                            falls back to its built-in 8-port default.
    SAN_SIM_HOST            Bind address (default 0.0.0.0)
    SAN_SIM_PORT            Bind port (default 8443)
    SAN_SIM_IP              The "switch IP" identity to simulate
                            (default 127.0.0.1). Only matters for
                            generating deterministic WWNs/serials.

Usage (bare):
    SAN_SIM_STARTUP_CONFIG=/config/startup-config.txt python sim_server.py

Usage (Docker): see Dockerfile.sim in this directory.
"""
from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from services.mds_simulator import MdsSimulator, get_sim_ports  # noqa: E402

SIM_IP = os.environ.get("SAN_SIM_IP", "127.0.0.1")
HOST = os.environ.get("SAN_SIM_HOST", "0.0.0.0")
PORT = int(os.environ.get("SAN_SIM_PORT", "8443"))

_sim = MdsSimulator(SIM_IP)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"[sim_server] {self.address_string()} - {fmt % args}")

    def _send_json(self, status: int, body: dict):
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path in ("/", "/health", "/healthz"):
            self._send_json(200, {"status": "ok", "sim_ip": SIM_IP})
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):
        if self.path not in ("/ins-api", "/ins"):
            self._send_json(404, {"error": "not found"})
            return

        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            self._send_json(400, {"error": "invalid JSON"})
            return

        ins_api = payload.get("ins_api", {})
        cmd_type = ins_api.get("type", "cli_show")
        command = ins_api.get("input", "")

        try:
            if cmd_type == "cli_conf":
                # A single config command per request (matches how the
                # real MdsClient sends config now -- one command per call).
                _sim.send_config([command])
                body = {}
            else:
                body = _sim.send_command(command)
        except Exception as e:
            self._send_json(500, {
                "ins_api": {"outputs": {"output": {
                    "body": {}, "code": "500", "msg": str(e)
                }}}
            })
            return

        self._send_json(200, {
            "ins_api": {"outputs": {"output": {
                "body": body, "code": "200", "msg": "Success"
            }}}
        })


def main():
    startup_path = os.environ.get("SAN_SIM_STARTUP_CONFIG", "")
    if startup_path:
        if Path(startup_path).is_file():
            print(f"[sim_server] Will seed from startup-config: {startup_path}")
        else:
            print(f"[sim_server] WARNING: SAN_SIM_STARTUP_CONFIG={startup_path} "
                  f"does not exist -- falling back to built-in defaults")
    else:
        print("[sim_server] No SAN_SIM_STARTUP_CONFIG set -- using built-in "
              "8-port default topology")

    # Touch the simulator once now so startup-config loading (and any
    # load errors) happen at boot, not on the first incoming request.
    info = _sim.test_connectivity()
    print(f"[sim_server] Simulated switch identity: {info}")

    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"[sim_server] Listening on http://{HOST}:{PORT}/ins-api  (sim_ip={SIM_IP})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
