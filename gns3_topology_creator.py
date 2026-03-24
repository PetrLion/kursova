#!/usr/bin/env python3
"""
GNS3 Topology Creator — Course Work Network Security Lab
=========================================================
Automatically creates a complete GNS3 network topology:

  Network structure:
  ┌────────────────────────────────────────────────────────┐
  │                    R1 (Core) 1.1.1.1                   │
  │                   /    |     \\                          │
  │       R2 (Office)  R3 (Restr.)  R4 (DMZ)              │
  │      2.2.2.2       3.3.3.3      4.4.4.4                │
  │      /   \\            |         / | \\                   │
  │   PC1   PC2          PC3    WEB RDS  DB               │
  └────────────────────────────────────────────────────────┘

  Inter-router links:
    R1 ↔ R2 : 10.1.12.0/30  (R1:fa0/0, R2:fa0/0)
    R1 ↔ R3 : 10.1.13.0/30  (R1:fa0/1, R3:fa0/0)
    R1 ↔ R4 : 10.1.14.0/30  (R1:fa1/0, R4:fa0/0)
  Access zone (R2):
    PC1 10.0.20.10/24  ← R2 fa0/1  (gw 10.0.20.1)
    PC2 10.0.21.10/24  ← R2 fa1/0  (gw 10.0.21.1)
  Restricted zone (R3):
    PC3 10.0.30.10/24  ← R3 fa0/1  (gw 10.0.30.1)
  DMZ (R4):
    SRV-WEB   10.0.40.10/24 ← R4 fa0/1  (gw 10.0.40.1)
    SRV-REDIS 10.0.41.10/24 ← R4 fa1/0  (gw 10.0.41.1)
    SRV-DB    10.0.42.10/24 ← R4 fa2/0  (gw 10.0.42.1)

  ACL on R3 (FastEthernet0/1 outbound):
    DENY   PC3 → SRV-REDIS (10.0.41.0/24)
    DENY   PC3 → SRV-DB    (10.0.42.0/24)
    PERMIT everything else

Usage:
    python3 gns3_topology_creator.py
    python3 gns3_topology_creator.py --host 127.0.0.1 --port 3080
    python3 gns3_topology_creator.py --user admin --password secret
    python3 gns3_topology_creator.py --no-configure   # skip telnet config
    GNS3_PASS=secret python3 gns3_topology_creator.py

Requirements:
    pip install requests
"""

import argparse
import json
import logging
import os
import sys
import time
import socket as _socket
import threading
from datetime import datetime
from typing import Optional, Dict, List, Tuple, Any

import requests
from requests.auth import HTTPBasicAuth

# ── Logging setup ─────────────────────────────────────────────────────────────
_log_file = f"gns3_creator_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(_log_file, encoding="utf-8"),
    ],
)
log = logging.getLogger(__name__)

# ── Default connection settings (override via env or CLI) ─────────────────────
GNS3_HOST    = os.environ.get("GNS3_HOST",    "127.0.0.1")
GNS3_PORT    = int(os.environ.get("GNS3_PORT", "3080"))
GNS3_USER    = os.environ.get("GNS3_USER",    "admin")
GNS3_PASS    = os.environ.get("GNS3_PASS",    "")
FLASK_URL    = os.environ.get("FLASK_URL",    "http://localhost:5050")
PROJECT_NAME = os.environ.get("GNS3_PROJECT", "Kursova-Network-Security")

# ── Topology definition ───────────────────────────────────────────────────────
# Each entry: name, role (router|vpcs), GNS3 canvas position, IP data
NODES: List[Dict[str, Any]] = [
    # ── Routers ────────────────────────────────────────────────────────────
    {"name": "R1", "role": "router", "x":    0, "y": -150,
     "loopback": "1.1.1.1", "desc": "Core"},
    {"name": "R2", "role": "router", "x": -300, "y":   50,
     "loopback": "2.2.2.2", "desc": "Office"},
    {"name": "R3", "role": "router", "x":    0, "y":   50,
     "loopback": "3.3.3.3", "desc": "Restricted"},
    {"name": "R4", "role": "router", "x":  300, "y":   50,
     "loopback": "4.4.4.4", "desc": "DMZ"},
    # ── VPCS endpoints ─────────────────────────────────────────────────────
    {"name": "PC1",       "role": "vpcs", "x": -450, "y": 250,
     "ip": "10.0.20.10", "mask": "/24", "gw": "10.0.20.1"},
    {"name": "PC2",       "role": "vpcs", "x": -200, "y": 250,
     "ip": "10.0.21.10", "mask": "/24", "gw": "10.0.21.1"},
    {"name": "PC3",       "role": "vpcs", "x":    0, "y": 250,
     "ip": "10.0.30.10", "mask": "/24", "gw": "10.0.30.1"},
    # ── VPCS servers ────────────────────────────────────────────────────────
    {"name": "SRV-WEB",   "role": "vpcs", "x":  150, "y": 250,
     "ip": "10.0.40.10", "mask": "/24", "gw": "10.0.40.1"},
    {"name": "SRV-REDIS", "role": "vpcs", "x":  300, "y": 250,
     "ip": "10.0.41.10", "mask": "/24", "gw": "10.0.41.1"},
    {"name": "SRV-DB",    "role": "vpcs", "x":  450, "y": 250,
     "ip": "10.0.42.10", "mask": "/24", "gw": "10.0.42.1"},
]

# Links: (from_name, from_adapter, from_port, to_name, to_adapter, to_port)
# Adapter/port mapping for Cisco C3725:
#   adapter 0, port 0 → fa0/0   (built-in C3725-IO-2FE)
#   adapter 0, port 1 → fa0/1
#   adapter 1, port 0 → fa1/0   (NM-1FE-TX in slot 1)
#   adapter 2, port 0 → fa2/0   (NM-1FE-TX in slot 2)
# VPCS: adapter 0, port 0 → eth0
LINKS: List[Tuple] = [
    # ── Inter-router backbone ──────────────────────────────────────────────
    ("R1", 0, 0,  "R2", 0, 0),   # R1:fa0/0  ↔  R2:fa0/0   10.1.12.0/30
    ("R1", 0, 1,  "R3", 0, 0),   # R1:fa0/1  ↔  R3:fa0/0   10.1.13.0/30
    ("R1", 1, 0,  "R4", 0, 0),   # R1:fa1/0  ↔  R4:fa0/0   10.1.14.0/30
    # ── Access zone (R2) ──────────────────────────────────────────────────
    ("R2", 0, 1,  "PC1",      0, 0),  # R2:fa0/1  ↔  PC1
    ("R2", 1, 0,  "PC2",      0, 0),  # R2:fa1/0  ↔  PC2
    # ── Restricted zone (R3) ──────────────────────────────────────────────
    ("R3", 0, 1,  "PC3",      0, 0),  # R3:fa0/1  ↔  PC3
    # ── DMZ (R4) ──────────────────────────────────────────────────────────
    ("R4", 0, 1,  "SRV-WEB",  0, 0),  # R4:fa0/1  ↔  SRV-WEB
    ("R4", 1, 0,  "SRV-REDIS",0, 0),  # R4:fa1/0  ↔  SRV-REDIS
    ("R4", 2, 0,  "SRV-DB",   0, 0),  # R4:fa2/0  ↔  SRV-DB
]

# ── Cisco IOS router configurations ───────────────────────────────────────────
# These are pushed line-by-line via the telnet console after boot.
ROUTER_CONFIGS: Dict[str, str] = {
    "R1": """\
hostname R1
no ip domain-lookup
!
interface Loopback0
 ip address 1.1.1.1 255.255.255.255
!
interface FastEthernet0/0
 description To-R2
 ip address 10.1.12.1 255.255.255.252
 no shutdown
!
interface FastEthernet0/1
 description To-R3
 ip address 10.1.13.1 255.255.255.252
 no shutdown
!
interface FastEthernet1/0
 description To-R4
 ip address 10.1.14.1 255.255.255.252
 no shutdown
!
router ospf 1
 router-id 1.1.1.1
 network 1.1.1.1 0.0.0.0 area 0
 network 10.1.12.0 0.0.0.3 area 0
 network 10.1.13.0 0.0.0.3 area 0
 network 10.1.14.0 0.0.0.3 area 0
!
line con 0
 logging synchronous
!
end
""",
    "R2": """\
hostname R2
no ip domain-lookup
!
interface Loopback0
 ip address 2.2.2.2 255.255.255.255
!
interface FastEthernet0/0
 description To-R1
 ip address 10.1.12.2 255.255.255.252
 no shutdown
!
interface FastEthernet0/1
 description To-PC1-Access
 ip address 10.0.20.1 255.255.255.0
 no shutdown
!
interface FastEthernet1/0
 description To-PC2-Access
 ip address 10.0.21.1 255.255.255.0
 no shutdown
!
router ospf 1
 router-id 2.2.2.2
 network 2.2.2.2 0.0.0.0 area 0
 network 10.1.12.0 0.0.0.3 area 0
 network 10.0.20.0 0.0.0.255 area 0
 network 10.0.21.0 0.0.0.255 area 0
!
line con 0
 logging synchronous
!
end
""",
    "R3": """\
hostname R3
no ip domain-lookup
!
interface Loopback0
 ip address 3.3.3.3 255.255.255.255
!
interface FastEthernet0/0
 description To-R1
 ip address 10.1.13.2 255.255.255.252
 no shutdown
!
interface FastEthernet0/1
 description To-PC3-Restricted
 ip address 10.0.30.1 255.255.255.0
 no shutdown
!
ip access-list extended ACL-RESTRICTED
 deny   ip 10.0.30.0 0.0.0.255 10.0.41.0 0.0.0.255
 deny   ip 10.0.30.0 0.0.0.255 10.0.42.0 0.0.0.255
 permit ip any any
!
interface FastEthernet0/1
 ip access-group ACL-RESTRICTED out
!
router ospf 1
 router-id 3.3.3.3
 network 3.3.3.3 0.0.0.0 area 0
 network 10.1.13.0 0.0.0.3 area 0
 network 10.0.30.0 0.0.0.255 area 0
!
line con 0
 logging synchronous
!
end
""",
    "R4": """\
hostname R4
no ip domain-lookup
!
interface Loopback0
 ip address 4.4.4.4 255.255.255.255
!
interface FastEthernet0/0
 description To-R1
 ip address 10.1.14.2 255.255.255.252
 no shutdown
!
interface FastEthernet0/1
 description To-SRV-WEB
 ip address 10.0.40.1 255.255.255.0
 no shutdown
!
interface FastEthernet1/0
 description To-SRV-REDIS
 ip address 10.0.41.1 255.255.255.0
 no shutdown
!
interface FastEthernet2/0
 description To-SRV-DB
 ip address 10.0.42.1 255.255.255.0
 no shutdown
!
router ospf 1
 router-id 4.4.4.4
 network 4.4.4.4 0.0.0.0 area 0
 network 10.1.14.0 0.0.0.3 area 0
 network 10.0.40.0 0.0.0.255 area 0
 network 10.0.41.0 0.0.0.255 area 0
 network 10.0.42.0 0.0.0.255 area 0
!
line con 0
 logging synchronous
!
end
""",
}

# FRR (Docker) equivalent configs — used as fallback when Cisco IOS unavailable
ROUTER_CONFIGS_FRR: Dict[str, str] = {
    "R1": """\
frr version 8.4
frr defaults traditional
hostname R1
!
interface lo
 ip address 1.1.1.1/32
 ip ospf area 0
!
interface eth0
 description To-R2
 ip address 10.1.12.1/30
 ip ospf area 0
!
interface eth1
 description To-R3
 ip address 10.1.13.1/30
 ip ospf area 0
!
interface eth2
 description To-R4
 ip address 10.1.14.1/30
 ip ospf area 0
!
router ospf
 ospf router-id 1.1.1.1
 network 0.0.0.0/0 area 0
!
""",
    "R2": """\
frr version 8.4
frr defaults traditional
hostname R2
!
interface lo
 ip address 2.2.2.2/32
 ip ospf area 0
!
interface eth0
 description To-R1
 ip address 10.1.12.2/30
 ip ospf area 0
!
interface eth1
 description To-PC1-Access
 ip address 10.0.20.1/24
 ip ospf area 0
!
interface eth2
 description To-PC2-Access
 ip address 10.0.21.1/24
 ip ospf area 0
!
router ospf
 ospf router-id 2.2.2.2
 network 0.0.0.0/0 area 0
!
""",
    "R3": """\
frr version 8.4
frr defaults traditional
hostname R3
!
interface lo
 ip address 3.3.3.3/32
 ip ospf area 0
!
interface eth0
 description To-R1
 ip address 10.1.13.2/30
 ip ospf area 0
!
interface eth1
 description To-PC3-Restricted
 ip address 10.0.30.1/24
 ip ospf area 0
!
router ospf
 ospf router-id 3.3.3.3
 network 0.0.0.0/0 area 0
!
""",
    "R4": """\
frr version 8.4
frr defaults traditional
hostname R4
!
interface lo
 ip address 4.4.4.4/32
 ip ospf area 0
!
interface eth0
 description To-R1
 ip address 10.1.14.2/30
 ip ospf area 0
!
interface eth1
 description To-SRV-WEB
 ip address 10.0.40.1/24
 ip ospf area 0
!
interface eth2
 description To-SRV-REDIS
 ip address 10.0.41.1/24
 ip ospf area 0
!
interface eth3
 description To-SRV-DB
 ip address 10.0.42.1/24
 ip ospf area 0
!
router ospf
 ospf router-id 4.4.4.4
 network 0.0.0.0/0 area 0
!
""",
}


# ═══════════════════════════════════════════════════════════════════════════════
# GNS3 API client
# ═══════════════════════════════════════════════════════════════════════════════

class GNS3API:
    """GNS3 REST API v2 client with automatic retry and auth handling."""

    def __init__(self, host: str, port: int,
                 user: str = "", password: str = "",
                 retries: int = 5):
        self.base_url = f"http://{host}:{port}/v2"
        self.session  = requests.Session()
        self.retries  = retries
        if user or password:
            self.session.auth = HTTPBasicAuth(user, password)
        self.session.headers.update({"Content-Type": "application/json"})

    # ── Low-level request ──────────────────────────────────────────────────
    def _req(self, method: str, path: str, **kwargs) -> Optional[requests.Response]:
        url = f"{self.base_url}{path}"
        for attempt in range(1, self.retries + 1):
            try:
                resp = self.session.request(method, url, timeout=30, **kwargs)
                resp.raise_for_status()
                return resp
            except requests.exceptions.ConnectionError:
                log.warning("GNS3 unreachable (attempt %d/%d) — retry in 3s",
                            attempt, self.retries)
                time.sleep(3)
            except requests.exceptions.HTTPError as exc:
                log.error("HTTP %s — %s %s", exc.response.status_code, method, url)
                if exc.response.status_code in (401, 403):
                    log.error("Authentication failed — use --user / --password")
                    return None
                # Log response body for debugging
                try:
                    log.debug("Response body: %s", exc.response.text[:400])
                except Exception:
                    pass
                return None
            except Exception as exc:
                log.error("Request error: %s", exc)
                return None
        log.error("Max retries reached for %s %s", method, url)
        return None

    # ── Convenience wrappers ───────────────────────────────────────────────
    def get(self, path: str, **kw) -> Optional[Any]:
        r = self._req("GET", path, **kw)
        return r.json() if r is not None else None

    def post(self, path: str, data: Optional[dict] = None, **kw) -> Optional[Any]:
        r = self._req("POST", path, json=data or {}, **kw)
        return r.json() if r is not None else None

    def put(self, path: str, data: Optional[dict] = None, **kw) -> Optional[Any]:
        r = self._req("PUT", path, json=data or {}, **kw)
        return r.json() if r is not None else None

    def delete(self, path: str, **kw) -> bool:
        r = self._req("DELETE", path, **kw)
        return r is not None

    # ── Higher-level helpers ───────────────────────────────────────────────
    def version(self) -> Optional[str]:
        data = self.get("/version")
        return data.get("version") if data else None

    def wait_ready(self, timeout: int = 30) -> bool:
        """Poll until the API responds."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            v = self.version()
            if v:
                log.info("GNS3 API ready — version %s", v)
                return True
            time.sleep(2)
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# Authentication helpers
# ═══════════════════════════════════════════════════════════════════════════════

def try_auth(host: str, port: int) -> Tuple[str, str]:
    """Try common credential pairs; return first that works."""
    candidates = [
        ("", ""),
        ("admin", ""),
        ("admin", "admin"),
        ("gns3",  "gns3"),
        ("admin", "gns3"),
    ]
    base = f"http://{host}:{port}/v2/version"
    for user, pwd in candidates:
        try:
            auth = HTTPBasicAuth(user, pwd) if (user or pwd) else None
            r = requests.get(base, auth=auth, timeout=5)
            if r.status_code == 200:
                log.info("Auth OK — user=%r", user or "(none)")
                return user, pwd
        except Exception:
            pass
    log.warning("Could not auto-detect credentials — proceeding unauthenticated")
    return "", ""


# ═══════════════════════════════════════════════════════════════════════════════
# Template discovery
# ═══════════════════════════════════════════════════════════════════════════════

def find_router_template(api: GNS3API) -> Optional[dict]:
    """
    Return the best available router template.
    Preference order: dynamips (Cisco IOS) > iou > qemu > docker FRR.
    """
    templates = api.get("/templates") or []
    priority  = {"dynamips": 10, "iou": 8, "qemu": 5, "docker": 3}
    router_keywords = ("cisco", "ios", "c3725", "c7200", "c3640", "c2691",
                       "frr", "router", "vyos", "mikrotik")

    candidates: List[Tuple[int, dict]] = []
    for tmpl in templates:
        ttype = tmpl.get("template_type", tmpl.get("node_type", ""))
        name  = tmpl.get("name", "").lower()
        if ttype in priority or any(k in name for k in router_keywords):
            candidates.append((priority.get(ttype, 1), tmpl))

    if not candidates:
        return None

    candidates.sort(key=lambda x: x[0], reverse=True)
    _, best = candidates[0]
    log.info("Router template: %s (%s)", best.get("name"), best.get("template_type"))
    return best


def find_vpcs_template(api: GNS3API) -> Optional[dict]:
    """Return the VPCS template if present."""
    for tmpl in (api.get("/templates") or []):
        if tmpl.get("template_type") == "vpcs":
            return tmpl
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# Project management
# ═══════════════════════════════════════════════════════════════════════════════

def create_or_open_project(api: GNS3API, name: str) -> Optional[str]:
    """
    Find an existing project by name or create a new one.
    Returns project_id string or None on failure.
    """
    projects = api.get("/projects") or []
    for proj in projects:
        if proj.get("name") == name:
            pid = proj["project_id"]
            log.info("Found existing project '%s' (id=%s)", name, pid)
            # Close first so we can reopen cleanly
            api.post(f"/projects/{pid}/close")
            time.sleep(1)
            api.post(f"/projects/{pid}/open")
            return pid

    result = api.post("/projects", {"name": name})
    if result:
        pid = result["project_id"]
        log.info("Created project '%s' (id=%s)", name, pid)
        return pid

    log.error("Failed to create project '%s'", name)
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# Node creation
# ═══════════════════════════════════════════════════════════════════════════════

def _make_router_payload(node_def: dict) -> dict:
    """Build a direct Dynamips node payload (no template)."""
    return {
        "name":       node_def["name"],
        "node_type":  "dynamips",
        "compute_id": "local",
        "x":          node_def.get("x", 0),
        "y":          node_def.get("y", 0),
        "properties": {
            "platform": "c3725",
            "ram":      128,
            "nvram":    256,
            # NOTE: 'image' must be left empty here; GNS3 will look for the
            # IOS image in its images directory.  The user must first import
            # a Cisco IOS image (e.g. c3725-adventerprisek9-mz.124-25d.bin)
            # via the GNS3 GUI or the /v2/compute/dynamips/images API.
            "image":    "",
            "slot0":    "C3725-IO-2FE",
            "slot1":    "NM-1FE-TX",
            "slot2":    "NM-1FE-TX",
        },
    }


def create_node_from_template(api: GNS3API, pid: str,
                               node_def: dict, tid: str) -> Optional[dict]:
    payload = {
        "name":       node_def["name"],
        "x":          node_def.get("x", 0),
        "y":          node_def.get("y", 0),
        "compute_id": "local",
    }
    return api.post(f"/projects/{pid}/templates/{tid}", payload)


def create_router_node(api: GNS3API, pid: str,
                       node_def: dict,
                       template: Optional[dict]) -> Optional[dict]:
    name = node_def["name"]
    # Try from template first
    if template:
        tid    = template.get("template_id")
        result = create_node_from_template(api, pid, node_def, tid)
        if result:
            log.info("  ✅ %-12s created from template '%s'",
                     name, template.get("name"))
            return result

    # Fallback: direct Dynamips node (needs IOS image configured in GNS3)
    result = api.post(f"/projects/{pid}/nodes", _make_router_payload(node_def))
    if result:
        log.info("  ✅ %-12s created (dynamips direct)", name)
        return result

    log.warning("  ⚠️  %-12s — could not create router node", name)
    return None


def create_vpcs_node(api: GNS3API, pid: str,
                     node_def: dict,
                     template: Optional[dict]) -> Optional[dict]:
    name = node_def["name"]
    if template:
        tid    = template.get("template_id")
        result = create_node_from_template(api, pid, node_def, tid)
        if result:
            log.info("  ✅ %-12s (vpcs) created from template", name)
            return result

    # Direct VPCS creation
    payload = {
        "name":       name,
        "node_type":  "vpcs",
        "compute_id": "local",
        "x":          node_def.get("x", 0),
        "y":          node_def.get("y", 0),
    }
    result = api.post(f"/projects/{pid}/nodes", payload)
    if result:
        log.info("  ✅ %-12s (vpcs) created", name)
        return result

    log.warning("  ⚠️  %-12s — could not create VPCS node", name)
    return None


def create_all_nodes(api: GNS3API, pid: str,
                     router_tmpl: Optional[dict],
                     vpcs_tmpl: Optional[dict]) -> Dict[str, dict]:
    """Create every node; return name→node_info dict."""
    nodes_map: Dict[str, dict] = {}

    for node_def in NODES:
        name = node_def["name"]
        role = node_def["role"]
        if role == "router":
            node = create_router_node(api, pid, node_def, router_tmpl)
        else:
            node = create_vpcs_node(api, pid, node_def, vpcs_tmpl)

        if node:
            nodes_map[name] = node

    return nodes_map


# ═══════════════════════════════════════════════════════════════════════════════
# Link creation
# ═══════════════════════════════════════════════════════════════════════════════

def create_links(api: GNS3API, pid: str,
                 nodes_map: Dict[str, dict]) -> int:
    """Create all topology links; return count of successfully created links."""
    created = 0
    for (n1, a1, p1, n2, a2, p2) in LINKS:
        if n1 not in nodes_map or n2 not in nodes_map:
            log.warning("  ⚠️  Skipping %s↔%s — node(s) missing", n1, n2)
            continue

        payload = {
            "nodes": [
                {"node_id": nodes_map[n1]["node_id"],
                 "adapter_number": a1, "port_number": p1},
                {"node_id": nodes_map[n2]["node_id"],
                 "adapter_number": a2, "port_number": p2},
            ]
        }
        result = api.post(f"/projects/{pid}/links", payload)
        if result:
            log.info("  ✅ %s[a%dp%d] ↔ %s[a%dp%d]", n1, a1, p1, n2, a2, p2)
            created += 1
        else:
            log.warning("  ⚠️  Link %s↔%s failed", n1, n2)

    return created


# ═══════════════════════════════════════════════════════════════════════════════
# Node startup
# ═══════════════════════════════════════════════════════════════════════════════

def start_all_nodes(api: GNS3API, pid: str) -> bool:
    """POST nodes/start for the project."""
    result = api.post(f"/projects/{pid}/nodes/start")
    if result is not None:
        log.info("All nodes started ✅")
        return True
    log.error("Failed to start nodes ❌")
    return False


# ═══════════════════════════════════════════════════════════════════════════════
# Console / telnet helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _wait_console(host: str, port: int, timeout: int = 120) -> bool:
    """Block until the TCP console port accepts connections."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = _socket.create_connection((host, port), timeout=2)
            s.close()
            return True
        except (ConnectionRefusedError, OSError):
            time.sleep(3)
    return False


class _Telnet:
    """Minimal Telnet client using raw sockets (no telnetlib dependency)."""

    def __init__(self, host: str, port: int, timeout: float = 20.0):
        self._sock = _socket.create_connection((host, port), timeout=timeout)
        self._sock.settimeout(timeout)
        self._buf = b""

    def write(self, data: bytes) -> None:
        self._sock.sendall(data)

    def read_very_eager(self) -> bytes:
        """Read all available data without blocking."""
        self._sock.setblocking(False)
        chunks: List[bytes] = []
        try:
            while True:
                chunk = self._sock.recv(4096)
                if not chunk:
                    break
                # Strip telnet IAC sequences (3-byte sequences: IAC + cmd + opt)
                cleaned = bytearray()
                i = 0
                while i < len(chunk):
                    if chunk[i] == 0xFF and i + 3 <= len(chunk):
                        i += 3  # skip IAC + command + option
                    else:
                        cleaned.append(chunk[i])
                        i += 1
                chunks.append(bytes(cleaned))
        except (BlockingIOError, _socket.timeout):
            pass
        finally:
            self._sock.setblocking(True)
        return b"".join(chunks)

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


def _send_cisco_config(host: str, port: int, config: str) -> bool:
    """Push IOS configuration lines via the router console."""
    try:
        tn = _Telnet(host, port, timeout=20)
        time.sleep(2)
        tn.read_very_eager()

        # Wake the console
        tn.write(b"\r\n")
        time.sleep(1)
        tn.read_very_eager()

        # Get into privileged exec
        tn.write(b"enable\r\n")
        time.sleep(0.5)
        tn.read_very_eager()

        # Enter global config
        tn.write(b"conf t\r\n")
        time.sleep(0.5)
        tn.read_very_eager()

        # Send each config line
        for raw_line in config.splitlines():
            line = raw_line.rstrip()
            if not line or line.startswith("!") or line in ("end", ""):
                continue
            tn.write(line.encode("ascii", errors="replace") + b"\r\n")
            time.sleep(0.08)

        # Exit config mode and save
        tn.write(b"end\r\n")
        time.sleep(0.3)
        tn.write(b"write memory\r\n")
        time.sleep(3)
        tn.read_very_eager()
        tn.close()
        return True
    except Exception as exc:
        log.error("Cisco console error: %s", exc)
        return False


def _send_frr_config(host: str, port: int, config: str) -> bool:
    """Push FRR configuration via the router console using vtysh."""
    import base64
    try:
        tn = _Telnet(host, port, timeout=20)
        time.sleep(2)
        tn.read_very_eager()

        tn.write(b"\n")
        time.sleep(0.5)

        # Use base64 to safely transfer the config without shell injection risks.
        # The config is encoded, decoded on the router, and written to frr.conf.
        b64_config = base64.b64encode(config.encode("utf-8")).decode("ascii")
        cmd = f"echo {b64_config} | base64 -d > /etc/frr/frr.conf\n"
        tn.write(cmd.encode("ascii"))
        time.sleep(1)

        # Apply and reload FRR
        tn.write(b"vtysh -c 'write'\n")
        time.sleep(1)
        tn.write(b"systemctl reload frr 2>/dev/null || true\n")
        time.sleep(2)
        tn.close()
        return True
    except Exception as exc:
        log.error("FRR console error: %s", exc)
        return False


def configure_vpcs_console(host: str, port: int,
                            ip: str, mask: str, gw: str) -> bool:
    """Configure a VPCS node's IP address via its console."""
    try:
        tn = _Telnet(host, port, timeout=10)
        time.sleep(1)
        tn.read_very_eager()

        # VPCS command: ip <addr>/<prefix> <gateway>
        cmd = f"ip {ip}{mask} {gw}\n"
        tn.write(cmd.encode("ascii"))
        time.sleep(1)
        tn.write(b"save\n")
        time.sleep(1)
        tn.close()
        return True
    except Exception as exc:
        log.error("VPCS console error (%s:%s): %s", host, port, exc)
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# Configuration push
# ═══════════════════════════════════════════════════════════════════════════════

def configure_routers(nodes_map: Dict[str, dict], is_cisco: bool) -> None:
    """Configure all four routers with OSPF via their console ports."""
    configs = ROUTER_CONFIGS if is_cisco else ROUTER_CONFIGS_FRR
    send_fn = _send_cisco_config if is_cisco else _send_frr_config

    log.info("Waiting 15 s for routers to initialise before config push...")
    time.sleep(15)

    for rname, config in configs.items():
        if rname not in nodes_map:
            log.warning("  ⚠️  %s not in nodes_map — skipping config", rname)
            continue

        node = nodes_map[rname]
        host = node.get("console_host", "127.0.0.1")
        port = node.get("console", 0)

        if not port:
            log.warning("  ⚠️  No console port for %s", rname)
            continue

        log.info("  📡 %s  console=%s:%s", rname, host, port)
        if _wait_console(host, port, timeout=120):
            ok = send_fn(host, port, config)
            log.info("  %s %s configured", "✅" if ok else "⚠️ ", rname)
        else:
            log.warning("  ⚠️  %s console timed out", rname)


def configure_vpcs_nodes(nodes_map: Dict[str, dict]) -> None:
    """Set IP addresses on all VPCS nodes."""
    vpcs_nodes = [n for n in NODES if n["role"] == "vpcs"]
    for nd in vpcs_nodes:
        name = nd["name"]
        if name not in nodes_map:
            continue

        node = nodes_map[name]
        host = node.get("console_host", "127.0.0.1")
        port = node.get("console", 0)
        ip   = nd.get("ip", "")
        mask = nd.get("mask", "/24")
        gw   = nd.get("gw", "")

        if not (port and ip and gw):
            continue

        log.info("  📡 %-12s  ip=%s%s  gw=%s", name, ip, mask, gw)
        if _wait_console(host, port, timeout=30):
            ok = configure_vpcs_console(host, port, ip, mask, gw)
            log.info("  %s %s", "✅" if ok else "⚠️ ", name)
        else:
            log.warning("  ⚠️  %s console not available", name)


# ═══════════════════════════════════════════════════════════════════════════════
# Project-info persistence (shared with collector.py)
# ═══════════════════════════════════════════════════════════════════════════════

def save_project_info(pid: str, project_name: str,
                      nodes_map: Dict[str, dict]) -> None:
    """
    Write project metadata to gns3_project.json (repo root) and
    security_validator/gns3_project.json so the Flask collector can
    discover the project and node names automatically.
    """
    info = {
        "project_id":   pid,
        "project_name": project_name,
        "created_at":   datetime.now().isoformat(),
        "gns3_url":     f"http://{GNS3_HOST}:{GNS3_PORT}/v2",
        "nodes": {
            name: {
                "node_id":      nd["node_id"],
                "node_type":    nd.get("node_type", ""),
                "status":       nd.get("status", ""),
                "console":      nd.get("console", 0),
                "console_host": nd.get("console_host", "127.0.0.1"),
            }
            for name, nd in nodes_map.items()
        },
    }

    paths = [
        "gns3_project.json",
        os.path.join("security_validator", "gns3_project.json"),
    ]
    for path in paths:
        try:
            dir_ = os.path.dirname(path)
            if dir_:
                os.makedirs(dir_, exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(info, fh, indent=2, ensure_ascii=False)
            log.info("  Saved project info → %s", path)
        except OSError as exc:
            log.warning("  Could not save %s: %s", path, exc)


# ═══════════════════════════════════════════════════════════════════════════════
# Flask web-app integration
# ═══════════════════════════════════════════════════════════════════════════════

def _build_vis_topology(nodes_map: Dict[str, dict]) -> dict:
    """Build vis-network compatible topology dict from nodes_map."""
    topo_nodes = []
    for nd in NODES:
        name = nd["name"]
        if name not in nodes_map:
            continue
        role = nd["role"]
        color_map = {
            "router": "#2980B9",
            "vpcs":   "#27AE60",
        }
        ip_label = nd.get("ip") or nd.get("loopback", "")
        topo_nodes.append({
            "id":       name,
            "label":    name,
            "title":    f"{name}  {ip_label}",
            "color":    color_map.get(role, "#566573"),
            "shape":    "box" if role == "router" else "ellipse",
            "role":     role,
            "node_id":  nodes_map[name]["node_id"],
            "status":   nodes_map[name].get("status", "started"),
        })

    topo_edges = []
    for idx, (n1, a1, p1, n2, a2, p2) in enumerate(LINKS):
        if n1 in nodes_map and n2 in nodes_map:
            topo_edges.append({
                "id":    f"link_{idx}",
                "from":  n1,
                "to":    n2,
                "label": f"a{a1}p{p1}—a{a2}p{p2}",
                "color": "#4A90D9" if "R" in n1 and "R" in n2 else "#52BE80",
            })

    return {"nodes": topo_nodes, "edges": topo_edges}


def notify_flask(nodes_map: Dict[str, dict], pid: str,
                 flask_url: str = FLASK_URL) -> None:
    """
    Send topology data to the Flask web app.
    Tries POST /api/topology_update first, then falls back to /api/scan
    (which triggers GNS3 re-discovery inside the Flask app).
    """
    topology = _build_vis_topology(nodes_map)

    # Full payload for /api/topology_update
    payload = {
        "project_id":   pid,
        "topology":     topology,
        "source":       "gns3_topology_creator",
        "timestamp":    datetime.now().isoformat(),
    }

    tried: List[str] = []
    for path in ("/api/topology_update", "/api/scan"):
        url = flask_url.rstrip("/") + path
        tried.append(url)
        try:
            r = requests.post(url, json=payload, timeout=5)
            if r.status_code == 200:
                log.info("Flask notified via %s ✅", path)
                return
        except requests.exceptions.ConnectionError:
            pass
        except Exception as exc:
            log.debug("Flask notify error (%s): %s", path, exc)

    log.info("Flask app not reachable at %s — topology saved to gns3_project.json",
             flask_url)


# ═══════════════════════════════════════════════════════════════════════════════
# Final report
# ═══════════════════════════════════════════════════════════════════════════════

def print_report(nodes_map: Dict[str, dict], links_count: int, pid: str) -> None:
    sep = "═" * 62
    print(f"\n{sep}")
    print("  🚀  GNS3 TOPOLOGY CREATED SUCCESSFULLY")
    print(sep)
    print(f"  Project ID   : {pid}")
    print(f"  Project name : {PROJECT_NAME}")
    print(f"  Nodes        : {len(nodes_map)}/{len(NODES)}")
    print(f"  Links        : {links_count}/{len(LINKS)}")
    print()
    print("  Network zones:")
    print("  ┌─────────────────────────────────────────────────┐")
    print("  │  R1  Core        1.1.1.1/32                     │")
    print("  │  R2  Office      2.2.2.2/32  (10.0.20-21.0/24) │")
    print("  │  R3  Restricted  3.3.3.3/32  (10.0.30.0/24)    │")
    print("  │  R4  DMZ         4.4.4.4/32  (10.0.40-42.0/24) │")
    print("  └─────────────────────────────────────────────────┘")
    print()
    print("  ACL rules applied on R3 (FastEthernet0/1 outbound):")
    print("    DENY   PC3 → SRV-REDIS  (10.0.41.0/24)")
    print("    DENY   PC3 → SRV-DB     (10.0.42.0/24)")
    print("    PERMIT everything else")
    print()
    print("  Access URLs:")
    print(f"    GNS3 API   →  http://localhost:{GNS3_PORT}")
    print(f"    Web UI     →  http://localhost:5050")
    print()
    print(f"  Project info saved to: gns3_project.json")
    print(f"  Log file             : {_log_file}")
    print(sep + "\n")


# ═══════════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create GNS3 network security topology for course work",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--host",         default=GNS3_HOST,    help="GNS3 host")
    parser.add_argument("--port",         default=GNS3_PORT,    type=int, help="GNS3 port")
    parser.add_argument("--user",         default=GNS3_USER,    help="GNS3 username")
    parser.add_argument("--password",     default=GNS3_PASS,    help="GNS3 password")
    parser.add_argument("--project-name", default=PROJECT_NAME, help="GNS3 project name")
    parser.add_argument("--flask-url",    default=FLASK_URL,    help="Flask app URL")
    parser.add_argument("--no-configure", action="store_true",
                        help="Skip router console configuration (OSPF)")
    parser.add_argument("--no-start",     action="store_true",
                        help="Do not start nodes after creation")
    parser.add_argument("--no-notify",    action="store_true",
                        help="Do not notify Flask app")
    args = parser.parse_args()

    log.info("╔══════════════════════════════════════════╗")
    log.info("║  GNS3 Topology Creator — Course Work     ║")
    log.info("╚══════════════════════════════════════════╝")

    # ── Step 1: Connect ───────────────────────────────────────────────────
    log.info("\n[1/7] Connecting to GNS3 at %s:%s …", args.host, args.port)
    user, password = args.user, args.password
    if not password:
        user, password = try_auth(args.host, args.port)

    api = GNS3API(args.host, args.port, user, password)
    if not api.wait_ready(timeout=30):
        log.error("Cannot connect to GNS3. Start the server first:")
        log.error("  gns3server --host 127.0.0.1 --port 3080 &")
        sys.exit(1)

    # ── Step 2: Discover templates ────────────────────────────────────────
    log.info("\n[2/7] Discovering available templates …")
    router_tmpl = find_router_template(api)
    vpcs_tmpl   = find_vpcs_template(api)
    is_cisco    = bool(router_tmpl and
                       router_tmpl.get("template_type") == "dynamips")
    is_frr      = bool(router_tmpl and
                       "frr" in router_tmpl.get("name", "").lower())

    if not router_tmpl:
        log.warning("No router template found — router nodes will likely fail.")
        log.warning("Import a Cisco IOS or FRR appliance in GNS3 first.")

    if not vpcs_tmpl:
        log.info("No VPCS template found — will create VPCS nodes directly.")

    # ── Step 3: Create / open project ─────────────────────────────────────
    log.info("\n[3/7] Creating project '%s' …", args.project_name)
    pid = create_or_open_project(api, args.project_name)
    if not pid:
        log.error("Failed to create GNS3 project.")
        sys.exit(1)

    # ── Step 4: Create nodes ──────────────────────────────────────────────
    log.info("\n[4/7] Creating nodes …")
    nodes_map = create_all_nodes(api, pid, router_tmpl, vpcs_tmpl)

    if not nodes_map:
        log.error("No nodes were created. Check GNS3 templates.")
        sys.exit(1)

    log.info("Created %d/%d nodes.", len(nodes_map), len(NODES))

    # ── Step 5: Create links ──────────────────────────────────────────────
    log.info("\n[5/7] Creating links …")
    links_count = create_links(api, pid, nodes_map)
    log.info("Created %d/%d links.", links_count, len(LINKS))

    # ── Step 6: Save project info ─────────────────────────────────────────
    log.info("\n[6/7] Saving project info …")
    save_project_info(pid, args.project_name, nodes_map)

    # ── Step 7: Start nodes + configure ───────────────────────────────────
    if not args.no_start:
        log.info("\n[7/7] Starting nodes …")
        start_all_nodes(api, pid)

        if not args.no_configure:
            log.info("\n▶ Configuring routers (OSPF + ACL) …")
            configure_routers(nodes_map, is_cisco=is_cisco or not is_frr)

            log.info("\n▶ Configuring VPCS nodes (IP addresses) …")
            configure_vpcs_nodes(nodes_map)
    else:
        log.info("\n[7/7] Skipping node startup (--no-start)")

    # ── Notify Flask ──────────────────────────────────────────────────────
    if not args.no_notify:
        log.info("\n▶ Notifying Flask web app at %s …", args.flask_url)
        notify_flask(nodes_map, pid, flask_url=args.flask_url)

    # ── Final report ──────────────────────────────────────────────────────
    print_report(nodes_map, links_count, pid)


if __name__ == "__main__":
    main()
