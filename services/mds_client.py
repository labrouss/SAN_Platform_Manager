"""
mds_client.py -- Cisco MDS 9000 NX-API JSON-RPC transport.
Translated from the original TypeScript MdsClient.ts.

Supports both /ins-api (MDS 9000) and /ins (NX-OS with FCoE) endpoints.
"""
from __future__ import annotations

import re
import urllib3
from typing import Any

import requests
from requests.auth import HTTPBasicAuth

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Endpoint cache: ip:port -> "/ins-api" | "/ins"
_endpoint_cache: dict[str, str] = {}


class MdsClientError(Exception):
    pass


class MdsClient:
    """HTTP client for Cisco NX-API on MDS/NX-OS switches."""

    def __init__(self, ip_address: str, username: str, password: str, port: int = 8443):
        self.ip_address = ip_address
        self.username = username
        self.password = password
        self.port = port
        self._cache_key = f"{ip_address}:{port}"
        proto = "http" if port in (80, 8080) else "https"
        self._base_url = f"{proto}://{ip_address}:{port}"
        self._session = requests.Session()
        self._session.auth = HTTPBasicAuth(username, password)
        self._session.verify = False
        self._session.headers.update({"Content-Type": "application/json"})
        self._session.timeout = 20

    def _get_endpoint(self) -> str:
        if self._cache_key in _endpoint_cache:
            return _endpoint_cache[self._cache_key]
        # Probe /ins-api first
        try:
            r = self._session.post(
                f"{self._base_url}/ins-api",
                json=self._build_payload("cli_show", "show version"),
                timeout=10,
            )
            if r.status_code != 404:
                _endpoint_cache[self._cache_key] = "/ins-api"
                return "/ins-api"
        except Exception:
            pass
        _endpoint_cache[self._cache_key] = "/ins"
        return "/ins"

    def _build_payload(self, cmd_type: str, command: str) -> dict:
        return {
            "ins_api": {
                "version": "1.0",
                "type": cmd_type,
                "chunk": "0",
                "sid": "sid",
                "input": command,
                "output_format": "json",
            }
        }

    def send_command(self, command: str, cmd_type: str = "cli_show") -> Any:
        """Send a single NX-API command; return the parsed output body."""
        endpoint = self._get_endpoint()
        payload = self._build_payload(cmd_type, command)
        try:
            r = self._session.post(
                f"{self._base_url}{endpoint}",
                json=payload,
                timeout=20,
                verify=False,
            )
        except requests.exceptions.ConnectionError as e:
            raise MdsClientError(f"Connection error to {self.ip_address}: {e}") from e
        except requests.exceptions.Timeout:
            raise MdsClientError(f"Timeout connecting to {self.ip_address}")

        if r.status_code == 401:
            raise MdsClientError("Authentication failed -- check username/password")
        if r.status_code not in (200, 201):
            raise MdsClientError(f"HTTP {r.status_code} from {self.ip_address}")

        data = r.json()
        output = data.get("ins_api", {}).get("outputs", {}).get("output", {})
        if isinstance(output, list):
            output = output[0]
        code = output.get("code", "")
        if code not in ("200", ""):
            msg = output.get("msg", "Unknown error")
            raise MdsClientError(f"NX-API error {code}: {msg}")
        return output.get("body", {})

    def send_config(self, commands: list[str]) -> None:
        """
        Send configuration commands via cli_conf.

        NX-API's cli_conf input historically accepts semicolon-joined
        commands, but this is NOT reliable when the sequence enters and
        stays inside a config submode -- e.g. `zone name X` / `member pwwn Y`
        / `zoneset name X` / `member Y`. In practice, semicolons inside
        these submode blocks get treated as literal characters rather than
        command separators, silently dropping or corrupting member lines.

        The reliable approach -- matching how a human would type each line
        one at a time into a CLI session -- is to POST every command as its
        own separate cli_conf request, in order, reusing the same session
        so the switch's config-mode state (conf t / zone name X / etc.)
        carries over correctly between requests.
        """
        endpoint = self._get_endpoint()
        for cmd in commands:
            cmd = cmd.strip()
            if not cmd:
                continue
            payload = self._build_payload("cli_conf", cmd)
            r = self._session.post(
                f"{self._base_url}{endpoint}",
                json=payload,
                timeout=30,
                verify=False,
            )
            if r.status_code == 401:
                raise MdsClientError("Authentication failed")
            if r.status_code not in (200, 201):
                raise MdsClientError(f"Config failed on '{cmd}': HTTP {r.status_code}")

    def test_connectivity(self) -> dict:
        """Verify connectivity by fetching show version. Returns version info."""
        body = self.send_command("show version")
        return {
            "hostname": body.get("host_name", ""),
            "nxos_version": body.get("kickstart_ver_str", body.get("nxos_ver_str", "")),
            "model": body.get("chassis_id", ""),
            "serial_number": body.get("proc_board_id", ""),
        }
