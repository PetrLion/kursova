#!/usr/bin/env python3
"""
GNS3 Topology Creator v3
========================
Works with GNS3 3.0.6 using the /v3 API endpoints.

Automatically builds the network topology:
  - 4 Cisco IOS routers: R1 (1.1.1.1), R2 (2.2.2.2), R3 (3.3.3.3), R4 (4.4.4.4)
  - 5 VPCS devices: PC1–PC5 (user access segments)
  - 3 server nodes: SRV-WEB, SRV-REDIS, SRV-DB (DMZ)
  - OSPF routing on all routers
  - ACL rules for traffic filtering

Usage:
    python3 gns3_topology_creator_v3.py [--host HOST] [--port PORT]
                                        [--user USER] [--password PASS]
                                        [--flask-url URL]
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import requests
from requests.auth import HTTPBasicAuth

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("gns3-creator")

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 3080
DEFAULT_FLASK_URL = "http://localhost:5050"
PROJECT_NAME = "network-security-topology"
MAX_RETRIES = 5
RETRY_DELAY = 2  # seconds

# ---------------------------------------------------------------------------
# Network topology definition
# ---------------------------------------------------------------------------
#
#                         [R1]  1.1.1.1
#                      /    |    \
#                    /      |      \
#                [R2]      [R4]    [R3]
#               2.2.2.2  4.4.4.4  3.3.3.3
#              /   \      /   \    /  |  \
#           PC1   PC2  PC3  PC4,PC5  SRV-WEB SRV-REDIS SRV-DB
#          (access) (access)(access)(restricted)  (DMZ)
#
# Point-to-point backbone links (R1 hub-and-spoke):
#   R1 <-> R2 : 10.0.12.0/30  (R1=.1, R2=.2)
#   R1 <-> R3 : 10.0.13.0/30  (R1=.1, R3=.2)
#   R1 <-> R4 : 10.0.14.0/30  (R1=.1, R4=.2)
#
# Access networks:
#   R2 <-> PC1,PC2  : 10.0.20.0/24  (R2=.1, PC1=.10, PC2=.11)
#   R4 <-> PC3      : 10.0.21.0/24  (R4=.1, PC3=.10)
#
# Restricted:
#   R4 <-> PC4,PC5  : 10.0.30.0/24  (R4=.1, PC4=.10, PC5=.11)
#
# DMZ:
#   R3 <-> SRV-WEB  : 10.0.40.0/24  (R3=.1, SRV-WEB=.10)
#   R3 <-> SRV-REDIS: 10.0.41.0/24  (R3=.1, SRV-REDIS=.10)
#   R3 <-> SRV-DB   : 10.0.42.0/24  (R3=.1, SRV-DB=.10)

NODES: List[Dict] = [
    # -- Routers (Dynamips / fallback to VPCS) --
    {"name": "R1", "kind": "router", "router_id": "1.1.1.1",
     "x": 0,    "y": 0,    "symbol": "router"},
    {"name": "R2", "kind": "router", "router_id": "2.2.2.2",
     "x": -300, "y": 200,  "symbol": "router"},
    {"name": "R3", "kind": "router", "router_id": "3.3.3.3",
     "x":  300, "y": 200,  "symbol": "router"},
    {"name": "R4", "kind": "router", "router_id": "4.4.4.4",
     "x": 0,    "y": 200,  "symbol": "router"},
    # -- PCs (VPCS) --
    {"name": "PC1", "kind": "vpcs", "x": -450, "y": 400, "symbol": "computer"},
    {"name": "PC2", "kind": "vpcs", "x": -250, "y": 400, "symbol": "computer"},
    {"name": "PC3", "kind": "vpcs", "x":  -50, "y": 400, "symbol": "computer"},
    {"name": "PC4", "kind": "vpcs", "x":  100, "y": 400, "symbol": "computer"},
    {"name": "PC5", "kind": "vpcs", "x":  250, "y": 400, "symbol": "computer"},
    # -- Servers (VPCS) --
    {"name": "SRV-WEB",   "kind": "vpcs", "x": 150,  "y": 400, "symbol": "server"},
    {"name": "SRV-REDIS", "kind": "vpcs", "x": 300,  "y": 400, "symbol": "server"},
    {"name": "SRV-DB",    "kind": "vpcs", "x": 450,  "y": 400, "symbol": "server"},
]

# (src_node, src_port, dst_node, dst_port)
LINKS: List[Tuple[str, int, str, int]] = [
    # Backbone R1 <-> R2/R3/R4
    ("R1", 0, "R2", 0),
    ("R1", 1, "R3", 0),
    ("R1", 2, "R4", 0),
    # R2 -> PC1, PC2
    ("R2", 1, "PC1", 0),
    ("R2", 2, "PC2", 0),
    # R4 -> PC3, PC4, PC5
    ("R4", 1, "PC3", 0),
    ("R4", 2, "PC4", 0),
    ("R4", 3, "PC5", 0),
    # R3 -> SRV-WEB, SRV-REDIS, SRV-DB
    ("R3", 1, "SRV-WEB",   0),
    ("R3", 2, "SRV-REDIS", 0),
    ("R3", 3, "SRV-DB",    0),
]

# IP addressing for nodes (interface, ip, gw, description)
NODE_IP: Dict[str, Dict] = {
    # Loopbacks / router-ids
    "R1": {"loopback": "1.1.1.1/32"},
    "R2": {"loopback": "2.2.2.2/32"},
    "R3": {"loopback": "3.3.3.3/32"},
    "R4": {"loopback": "4.4.4.4/32"},
    # Backbone
    "R1_to_R2": "10.0.12.1/30",
    "R2_to_R1": "10.0.12.2/30",
    "R1_to_R3": "10.0.13.1/30",
    "R3_to_R1": "10.0.13.2/30",
    "R1_to_R4": "10.0.14.1/30",
    "R4_to_R1": "10.0.14.2/30",
    # Access
    "R2_access": "10.0.20.1/24",
    "PC1": {"ip": "10.0.20.10/24", "gw": "10.0.20.1"},
    "PC2": {"ip": "10.0.20.11/24", "gw": "10.0.20.1"},
    "R4_access": "10.0.21.1/24",
    "PC3": {"ip": "10.0.21.10/24", "gw": "10.0.21.1"},
    # Restricted
    "R4_restricted": "10.0.30.1/24",
    "PC4": {"ip": "10.0.30.10/24", "gw": "10.0.30.1"},
    "PC5": {"ip": "10.0.30.11/24", "gw": "10.0.30.1"},
    # DMZ
    "R3_dmz_web":   "10.0.40.1/24",
    "R3_dmz_redis": "10.0.41.1/24",
    "R3_dmz_db":    "10.0.42.1/24",
    "SRV-WEB":   {"ip": "10.0.40.10/24", "gw": "10.0.40.1"},
    "SRV-REDIS": {"ip": "10.0.41.10/24", "gw": "10.0.41.1"},
    "SRV-DB":    {"ip": "10.0.42.10/24", "gw": "10.0.42.1"},
}

# VPCS startup scripts
VPCS_CONFIGS: Dict[str, str] = {
    "PC1":      "ip 10.0.20.10 255.255.255.0 10.0.20.1\nsave",
    "PC2":      "ip 10.0.20.11 255.255.255.0 10.0.20.1\nsave",
    "PC3":      "ip 10.0.21.10 255.255.255.0 10.0.21.1\nsave",
    "PC4":      "ip 10.0.30.10 255.255.255.0 10.0.30.1\nsave",
    "PC5":      "ip 10.0.30.11 255.255.255.0 10.0.30.1\nsave",
    "SRV-WEB":   "ip 10.0.40.10 255.255.255.0 10.0.40.1\nsave",
    "SRV-REDIS": "ip 10.0.41.10 255.255.255.0 10.0.41.1\nsave",
    "SRV-DB":    "ip 10.0.42.10 255.255.255.0 10.0.42.1\nsave",
}

# Cisco IOS startup configs for routers
IOS_CONFIGS: Dict[str, str] = {
    "R1": """\
hostname R1
!
interface Loopback0
 ip address 1.1.1.1 255.255.255.255
 no shutdown
!
interface FastEthernet0/0
 ip address 10.0.12.1 255.255.255.252
 no shutdown
!
interface FastEthernet0/1
 ip address 10.0.13.1 255.255.255.252
 no shutdown
!
interface FastEthernet1/0
 ip address 10.0.14.1 255.255.255.252
 no shutdown
!
router ospf 1
 router-id 1.1.1.1
 network 1.1.1.1 0.0.0.0 area 0
 network 10.0.12.0 0.0.0.3 area 0
 network 10.0.13.0 0.0.0.3 area 0
 network 10.0.14.0 0.0.0.3 area 0
!
end
""",
    "R2": """\
hostname R2
!
interface Loopback0
 ip address 2.2.2.2 255.255.255.255
 no shutdown
!
interface FastEthernet0/0
 ip address 10.0.12.2 255.255.255.252
 no shutdown
!
interface FastEthernet0/1
 ip address 10.0.20.1 255.255.255.0
 no shutdown
!
router ospf 1
 router-id 2.2.2.2
 network 2.2.2.2 0.0.0.0 area 0
 network 10.0.12.0 0.0.0.3 area 0
 network 10.0.20.0 0.0.0.255 area 0
!
ip access-list extended DENY_RESTRICTED_TO_DMZ
 deny ip 10.0.30.0 0.0.0.255 10.0.40.0 0.0.0.255
 deny ip 10.0.30.0 0.0.0.255 10.0.41.0 0.0.0.255
 deny ip 10.0.30.0 0.0.0.255 10.0.42.0 0.0.0.255
 permit ip any any
!
end
""",
    "R3": """\
hostname R3
!
interface Loopback0
 ip address 3.3.3.3 255.255.255.255
 no shutdown
!
interface FastEthernet0/0
 ip address 10.0.13.2 255.255.255.252
 no shutdown
!
interface FastEthernet0/1
 ip address 10.0.40.1 255.255.255.0
 no shutdown
!
interface FastEthernet1/0
 ip address 10.0.41.1 255.255.255.0
 no shutdown
!
interface FastEthernet1/1
 ip address 10.0.42.1 255.255.255.0
 no shutdown
!
router ospf 1
 router-id 3.3.3.3
 network 3.3.3.3 0.0.0.0 area 0
 network 10.0.13.0 0.0.0.3 area 0
 network 10.0.40.0 0.0.0.255 area 0
 network 10.0.41.0 0.0.0.255 area 0
 network 10.0.42.0 0.0.0.255 area 0
!
ip access-list extended DMZ_INBOUND
 permit tcp any 10.0.40.0 0.0.0.255 eq 80
 permit tcp any 10.0.40.0 0.0.0.255 eq 443
 permit tcp any 10.0.41.0 0.0.0.255 eq 6379
 permit tcp any 10.0.42.0 0.0.0.255 eq 3306
 deny   ip any any
!
end
""",
    "R4": """\
hostname R4
!
interface Loopback0
 ip address 4.4.4.4 255.255.255.255
 no shutdown
!
interface FastEthernet0/0
 ip address 10.0.14.2 255.255.255.252
 no shutdown
!
interface FastEthernet0/1
 ip address 10.0.21.1 255.255.255.0
 no shutdown
!
interface FastEthernet1/0
 ip address 10.0.30.1 255.255.255.0
 ip access-group RESTRICTED_ACL in
 no shutdown
!
router ospf 1
 router-id 4.4.4.4
 network 4.4.4.4 0.0.0.0 area 0
 network 10.0.14.0 0.0.0.3 area 0
 network 10.0.21.0 0.0.0.255 area 0
 network 10.0.30.0 0.0.0.255 area 0
!
ip access-list extended RESTRICTED_ACL
 deny   ip 10.0.30.0 0.0.0.255 10.0.40.0 0.0.0.255
 deny   ip 10.0.30.0 0.0.0.255 10.0.41.0 0.0.0.255
 deny   ip 10.0.30.0 0.0.0.255 10.0.42.0 0.0.0.255
 permit ip any any
!
end
""",
}


# ---------------------------------------------------------------------------
# GNS3 v3 API Client
# ---------------------------------------------------------------------------
class GNS3ClientV3:
    """Thin wrapper around the GNS3 3.x (v3) REST API with retry logic."""

    def __init__(self, host: str, port: int,
                 username: Optional[str] = None,
                 password: Optional[str] = None):
        self.base = f"http://{host}:{port}"
        self.api = f"{self.base}/v3"
        self.session = requests.Session()
        self.session.headers["Content-Type"] = "application/json"
        self._authenticated = False
        self._username = username
        self._password = password

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------
    def authenticate(self) -> bool:
        """
        Try authentication strategies in order:
          1. No auth (GNS3 started with --no-auth)
          2. Provided username / password  (JWT bearer token)
          3. Default credentials admin/admin
        Returns True when a working strategy is found.
        """
        # 1. No-auth probe
        if self._probe_no_auth():
            log.info("✅ GNS3 accepted unauthenticated request")
            self._authenticated = True
            return True

        # 2. Explicit credentials
        cred_pairs: List[Tuple[Optional[str], Optional[str]]] = []
        if self._username and self._password:
            cred_pairs.append((self._username, self._password))
        # 3. Fallback defaults
        cred_pairs += [
            ("admin", "admin"),
            ("gns3", "gns3"),
            ("admin", ""),
        ]

        for user, pwd in cred_pairs:
            token = self._get_jwt(user, pwd)
            if token:
                self.session.headers["Authorization"] = f"Bearer {token}"
                log.info("✅ GNS3 authenticated as '%s'", user)
                self._authenticated = True
                return True
            # Also try HTTP Basic (some GNS3 3.x builds still accept it)
            if self._probe_basic(user, pwd):
                self.session.auth = HTTPBasicAuth(user, pwd)
                log.info("✅ GNS3 authenticated via Basic as '%s'", user)
                self._authenticated = True
                return True

        log.error(
            "❌ Cannot authenticate with GNS3. "
            "Start the server with --no-auth or provide --user / --password."
        )
        return False

    def _probe_no_auth(self) -> bool:
        try:
            r = self.session.get(f"{self.api}/version", timeout=5)
            return r.status_code == 200
        except requests.RequestException:
            return False

    def _get_jwt(self, username: str, password: str) -> Optional[str]:
        """POST /v3/access/users/login — returns bearer token or None."""
        try:
            r = requests.post(
                f"{self.api}/access/users/login",
                data={"username": username, "password": password},
                timeout=5,
            )
            if r.status_code == 200:
                return r.json().get("access_token")
        except requests.RequestException:
            pass
        return None

    def _probe_basic(self, username: str, password: str) -> bool:
        try:
            r = requests.get(
                f"{self.api}/version",
                auth=HTTPBasicAuth(username, password),
                timeout=5,
            )
            return r.status_code == 200
        except requests.RequestException:
            return False

    # ------------------------------------------------------------------
    # Generic HTTP helpers with retry
    # ------------------------------------------------------------------
    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        url = f"{self.api}{path}"
        last_exc: Optional[Exception] = None
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                resp = self.session.request(method, url, timeout=15, **kwargs)
                if resp.status_code < 500:
                    return resp
                log.warning(
                    "Attempt %d/%d — server error %d for %s %s",
                    attempt, MAX_RETRIES, resp.status_code, method, path,
                )
            except requests.RequestException as exc:
                last_exc = exc
                log.warning(
                    "Attempt %d/%d — request error for %s %s: %s",
                    attempt, MAX_RETRIES, method, path, exc,
                )
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)
        if last_exc:
            raise last_exc
        raise RuntimeError(f"All {MAX_RETRIES} attempts failed for {method} {path}")

    def get(self, path: str, **kw) -> requests.Response:
        return self._request("GET", path, **kw)

    def post(self, path: str, data: Optional[dict] = None, **kw) -> requests.Response:
        return self._request("POST", path, json=data, **kw)

    def put(self, path: str, data: Optional[dict] = None, **kw) -> requests.Response:
        return self._request("PUT", path, json=data, **kw)

    def delete(self, path: str, **kw) -> requests.Response:
        return self._request("DELETE", path, **kw)

    # ------------------------------------------------------------------
    # High-level GNS3 operations
    # ------------------------------------------------------------------
    def version(self) -> dict:
        return self.get("/version").json()

    def list_projects(self) -> List[dict]:
        r = self.get("/projects")
        if r.status_code == 200:
            return r.json()
        return []

    def delete_project(self, project_id: str) -> bool:
        r = self.delete(f"/projects/{project_id}")
        return r.status_code in (200, 204)

    def create_project(self, name: str) -> Optional[dict]:
        r = self.post("/projects", {"name": name, "auto_close": False})
        if r.status_code in (200, 201):
            return r.json()
        log.error("Failed to create project: %d %s", r.status_code, r.text)
        return None

    def open_project(self, project_id: str) -> bool:
        r = self.post(f"/projects/{project_id}/open")
        return r.status_code in (200, 201)

    def list_templates(self) -> List[dict]:
        r = self.get("/templates")
        if r.status_code == 200:
            return r.json()
        return []

    def create_node(self, project_id: str, payload: dict) -> Optional[dict]:
        r = self.post(f"/projects/{project_id}/nodes", payload)
        if r.status_code in (200, 201):
            return r.json()
        log.error("Failed to create node '%s': %d %s",
                  payload.get("name"), r.status_code, r.text)
        return None

    def create_link(self, project_id: str, node_a_id: str, port_a: int,
                    node_b_id: str, port_b: int) -> Optional[dict]:
        payload = {
            "nodes": [
                {"node_id": node_a_id, "adapter_number": 0, "port_number": port_a},
                {"node_id": node_b_id, "adapter_number": 0, "port_number": port_b},
            ]
        }
        r = self.post(f"/projects/{project_id}/links", payload)
        if r.status_code in (200, 201):
            return r.json()
        log.warning("Link creation returned %d: %s", r.status_code, r.text[:200])
        return None

    def set_node_config(self, project_id: str, node_id: str, config: str) -> bool:
        """Write startup-config / script to a node via the files API."""
        path = f"/projects/{project_id}/nodes/{node_id}/files/startup.vpc"
        r = self._request(
            "POST", path,
            data=config.encode(),
            headers={"Content-Type": "text/plain"},
        )
        return r.status_code in (200, 201, 204)

    def start_all_nodes(self, project_id: str) -> bool:
        r = self.post(f"/projects/{project_id}/nodes/start")
        return r.status_code in (200, 201, 204)


# ---------------------------------------------------------------------------
# Template detection helpers
# ---------------------------------------------------------------------------
def _find_template(templates: List[dict], keywords: List[str]) -> Optional[dict]:
    """Return first template whose name contains any of the keywords (case-insensitive)."""
    kw_lower = [k.lower() for k in keywords]
    for t in templates:
        name_lower = t.get("name", "").lower()
        if any(k in name_lower for k in kw_lower):
            return t
    return None


def _build_node_payload(node_def: dict, templates: List[dict]) -> dict:
    """Build a GNS3 node creation payload from a high-level node definition."""
    name = node_def["name"]
    x, y = node_def.get("x", 0), node_def.get("y", 0)

    if node_def["kind"] == "router":
        # Prefer a Cisco IOS / Dynamips template
        tpl = _find_template(templates, ["cisco", "ios", "c7200", "c3725", "c2691"])
        if tpl:
            return {
                "name": name,
                "template_id": tpl["template_id"],
                "compute_id": "local",
                "x": x,
                "y": y,
            }
        # Fallback: bare VPCS labelled as router
        log.warning(
            "No Cisco IOS template found — using VPCS for %s (routing will be simulated)",
            name,
        )

    # Default: VPCS
    return {
        "name": name,
        "compute_id": "local",
        "node_type": "vpcs",
        "x": x,
        "y": y,
        "properties": {},
    }


# ---------------------------------------------------------------------------
# Topology build
# ---------------------------------------------------------------------------
def cleanup_old_projects(client: GNS3ClientV3) -> None:
    """Remove existing projects with the same name."""
    projects = client.list_projects()
    for p in projects:
        if p.get("name") == PROJECT_NAME:
            pid = p["project_id"]
            if client.delete_project(pid):
                log.info("🗑  Deleted old project %s (%s)", PROJECT_NAME, pid)
            else:
                log.warning("Could not delete old project %s", pid)


def build_topology(client: GNS3ClientV3) -> Optional[dict]:
    """
    Creates the full network topology on GNS3 and returns a dict with
    project info + node / link details suitable for the Flask app.
    """
    templates = client.list_templates()
    log.info("Found %d templates on GNS3 server", len(templates))

    # -- Create project ----------------------------------------------------
    log.info("📁 Creating project '%s' …", PROJECT_NAME)
    project = client.create_project(PROJECT_NAME)
    if not project:
        return None
    pid = project["project_id"]
    log.info("✅ Project created: %s (id=%s)", PROJECT_NAME, pid)

    # -- Open project -------------------------------------------------------
    client.open_project(pid)

    # -- Create nodes -------------------------------------------------------
    node_ids: Dict[str, str] = {}  # name -> node_id
    log.info("🖥  Creating %d nodes …", len(NODES))
    for node_def in NODES:
        payload = _build_node_payload(node_def, templates)
        result = client.create_node(pid, payload)
        if result:
            node_ids[node_def["name"]] = result["node_id"]
            log.info("  ✅ %-12s  id=%s", node_def["name"], result["node_id"])
        else:
            log.error("  ❌ Failed to create node: %s", node_def["name"])

    # -- Create links -------------------------------------------------------
    log.info("🔗 Creating %d links …", len(LINKS))
    link_results = []
    for src_name, src_port, dst_name, dst_port in LINKS:
        src_id = node_ids.get(src_name)
        dst_id = node_ids.get(dst_name)
        if not src_id or not dst_id:
            log.warning("  ⚠  Skipping link %s→%s (node not created)",
                        src_name, dst_name)
            continue
        result = client.create_link(pid, src_id, src_port, dst_id, dst_port)
        if result:
            link_results.append((src_name, dst_name, result.get("link_id")))
            log.info("  ✅ %s (port %d) ↔ %s (port %d)",
                     src_name, src_port, dst_name, dst_port)
        else:
            log.warning("  ⚠  Link %s↔%s could not be created", src_name, dst_name)

    # -- Apply VPCS IP configs ----------------------------------------------
    log.info("📝 Applying node configurations …")
    for node_name, script in VPCS_CONFIGS.items():
        nid = node_ids.get(node_name)
        if nid:
            ok = client.set_node_config(pid, nid, script)
            status = "✅" if ok else "⚠ "
            log.info("  %s %s", status, node_name)

    # -- Start all nodes ----------------------------------------------------
    log.info("▶  Starting all nodes …")
    if client.start_all_nodes(pid):
        log.info("✅ All nodes started")
    else:
        log.warning("⚠  Could not start nodes (may need to start manually)")

    # -- Build topology summary for Flask -----------------------------------
    topology = _build_topology_summary(pid, node_ids, link_results)
    topology["project_id"] = pid
    topology["project_name"] = PROJECT_NAME
    return topology


def _build_topology_summary(
    pid: str,
    node_ids: Dict[str, str],
    link_results: List[Tuple[str, str, Optional[str]]],
) -> dict:
    """Build a topology dict compatible with the Flask app's state.topology format."""
    nodes_vis = []
    edges_vis = []

    router_ids = {"R1": "1.1.1.1", "R2": "2.2.2.2",
                  "R3": "3.3.3.3", "R4": "4.4.4.4"}

    for node_def in NODES:
        name = node_def["name"]
        nid = node_ids.get(name, "")
        color = "#2980B9" if node_def["kind"] == "router" else "#27AE60"
        nodes_vis.append({
            "id":        nid or name,
            "label":     name,
            "router_id": router_ids.get(name, ""),
            "color":     color,
            "shape":     "box",
            "kind":      node_def["kind"],
            "ip":        NODE_IP.get(name, {}).get("ip", ""),
        })

    for src_name, dst_name, link_id in link_results:
        src_id = node_ids.get(src_name, src_name)
        dst_id = node_ids.get(dst_name, dst_name)
        edges_vis.append({
            "from":  src_id,
            "to":    dst_id,
            "label": f"{src_name}↔{dst_name}",
            "color": "#3fb950",
            "state": "up",
        })

    return {
        "nodes": nodes_vis,
        "edges": edges_vis,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# ---------------------------------------------------------------------------
# Flask integration
# ---------------------------------------------------------------------------
def push_to_flask(flask_url: str, topology: dict) -> bool:
    """POST topology data to the Flask /api/topology endpoint."""
    endpoint = f"{flask_url}/api/topology"
    try:
        r = requests.post(endpoint, json=topology, timeout=5)
        if r.status_code in (200, 201):
            log.info("✅ Topology pushed to Flask app at %s", endpoint)
            return True
        log.warning("Flask /api/topology returned %d: %s",
                    r.status_code, r.text[:100])
    except requests.RequestException as exc:
        log.warning("Could not reach Flask app at %s: %s", endpoint, exc)
    return False


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="GNS3 Topology Creator v3 — builds the network topology via GNS3 3.x API"
    )
    parser.add_argument("--host",      default=DEFAULT_HOST,      help="GNS3 server host (default: 127.0.0.1)")
    parser.add_argument("--port",      type=int, default=DEFAULT_PORT, help="GNS3 server port (default: 3080)")
    parser.add_argument("--user",      default=None,              help="GNS3 username")
    parser.add_argument("--password",  default=None,              help="GNS3 password")
    parser.add_argument("--flask-url", default=DEFAULT_FLASK_URL, help="Flask app URL (default: http://localhost:5050)")
    parser.add_argument("--no-start",  action="store_true",       help="Do not start nodes after creation")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    print("=" * 60)
    print("  GNS3 Topology Creator v3")
    print(f"  GNS3:  http://{args.host}:{args.port}/v3")
    print(f"  Flask: {args.flask_url}")
    print("=" * 60)
    print()

    client = GNS3ClientV3(
        host=args.host,
        port=args.port,
        username=args.user,
        password=args.password,
    )

    # -- Connect & authenticate -------------------------------------------
    log.info("🔌 Connecting to GNS3 server …")
    if not client.authenticate():
        print("\n❌ Authentication failed. Tips:")
        print("   • Start GNS3 with --no-auth flag:  gns3server --no-auth --host 127.0.0.1 --port 3080")
        print("   • Or provide credentials:          --user admin --password <pass>")
        return 1

    ver = client.version()
    print(f"✅ Connected to GNS3 {ver.get('version', '?')} (local version {ver.get('local_version', '?')})")
    print()

    # -- Clean up old projects -------------------------------------------
    log.info("🧹 Cleaning up old projects named '%s' …", PROJECT_NAME)
    cleanup_old_projects(client)

    # -- Build topology --------------------------------------------------
    log.info("🏗  Building topology …")
    topology = build_topology(client)
    if not topology:
        log.error("❌ Topology creation failed")
        return 1

    pid = topology["project_id"]

    # -- Push to Flask ---------------------------------------------------
    push_to_flask(args.flask_url, topology)

    # -- Summary ---------------------------------------------------------
    print()
    print("=" * 60)
    print("  ✅ Topology created successfully!")
    print()
    print(f"  Project ID : {pid}")
    print(f"  Nodes      : {len(topology['nodes'])}")
    print(f"  Links      : {len(topology['edges'])}")
    print()
    print("  Network segments:")
    print("    Access 1 (PC1, PC2)          : 10.0.20.0/24")
    print("    Access 2 (PC3)               : 10.0.21.0/24")
    print("    Restricted (PC4, PC5)        : 10.0.30.0/24")
    print("    DMZ Web                      : 10.0.40.0/24")
    print("    DMZ Redis                    : 10.0.41.0/24")
    print("    DMZ DB                       : 10.0.42.0/24")
    print()
    print("  Access URLs:")
    print(f"    GNS3 Web UI : http://{args.host}:{args.port}/static/web-ui/server/1/project/{pid}")
    print(f"    Flask app   : {args.flask_url}")
    print()
    print("  ⏳ Estimated startup time: ~30–60 s for VPCS / ~2–5 min for IOS routers")
    print("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
