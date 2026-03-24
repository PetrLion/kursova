"""
OSPF Neighbor Discovery — збирає топологію через vtysh
та автоматично валідує нові пристрої
"""
import telnetlib
import re
import time
import json
import os
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

@dataclass
class OSPFNeighbor:
    router_id:   str
    priority:    int
    state:       str        # Full, 2-Way, Init, etc.
    dead_time:   str
    interface:   str
    address:     str
    is_new:      bool = False

@dataclass
class RouterTopology:
    router_name: str
    router_id:   str
    neighbors:   List[OSPFNeighbor] = field(default_factory=list)
    interfaces:  List[dict]         = field(default_factory=list)
    routes:      List[str]          = field(default_factory=list)
    timestamp:   str = ""

def parse_ospf_neighbors(raw: str) -> List[OSPFNeighbor]:
    """
    Парсимо вивід: show ip ospf neighbor
    Neighbor ID  Pri  State     Dead Time  Address      Interface
    2.2.2.2        1  Full/DR   00:00:38   10.1.12.2    eth0:10.1.12.1
    """
    neighbors = []
    lines = raw.splitlines()
    for line in lines:
        # Паттерн: IP Pri State/Role DeadTime Address Interface
        m = re.match(
            r'(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)',
            line.strip()
        )
        if m:
            neighbors.append(OSPFNeighbor(
                router_id  = m.group(1),
                priority   = int(m.group(2)),
                state      = m.group(3),
                dead_time  = m.group(4),
                address    = m.group(5),
                interface  = m.group(6),
            ))
    return neighbors

def parse_ospf_router_id(raw: str) -> str:
    """Парсимо router-id з show ip ospf"""
    m = re.search(r'OSPF Routing Process.*?Router ID:\s*(\d+\.\d+\.\d+\.\d+)', raw)
    if not m:
        m = re.search(r'router-id\s+(\d+\.\d+\.\d+\.\d+)', raw)
    return m.group(1) if m else "unknown"

def parse_interfaces(raw: str) -> List[dict]:
    """Парсимо show interface brief"""
    interfaces = []
    for line in raw.splitlines():
        m = re.match(r'(\S+)\s+(\S+)\s+(\S+)\s+(\S+)', line)
        if m and m.group(1).startswith('eth'):
            interfaces.append({
                "name":   m.group(1),
                "status": m.group(2),
                "ip":     m.group(3),
            })
    return interfaces

def collect_ospf_via_telnet(host: str, port: int, timeout=12) -> dict:
    """Збирає OSPF дані через telnet консоль"""
    try:
        tn = telnetlib.Telnet(host, port, timeout=timeout)
        time.sleep(1)
        tn.write(b"\n")
        time.sleep(0.5)

        results = {}
        commands = {
            "neighbors":  b"vtysh -c 'show ip ospf neighbor'\n",
            "ospf_info":  b"vtysh -c 'show ip ospf'\n",
            "interfaces": b"vtysh -c 'show ip ospf interface'\n",
            "routes":     b"vtysh -c 'show ip route ospf'\n",
        }

        for key, cmd in commands.items():
            tn.write(cmd)
            time.sleep(1.5)
            data = tn.read_very_eager()
            results[key] = data.decode("utf-8", errors="ignore")

        tn.close()
        return results
    except Exception as e:
        return {}

class TopologyDiscovery:
    """
    Відстежує OSPF топологію в реальному часі
    та виявляє нових сусідів
    """
    CACHE_FILE = "configs/topology_cache.json"

    def __init__(self):
        self.previous: Dict[str, List[str]] = self._load_cache()
        self.current:  Dict[str, RouterTopology] = {}

    def _load_cache(self) -> dict:
        if os.path.exists(self.CACHE_FILE):
            try:
                return json.load(open(self.CACHE_FILE, encoding="utf-8"))
            except:
                pass
        return {}

    def _save_cache(self):
        data = {
            rname: [n.router_id for n in topo.neighbors]
            for rname, topo in self.current.items()
        }
        with open(self.CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def discover(self, nodes_info: dict) -> Dict[str, RouterTopology]:
        """
        Збирає OSPF топологію з усіх роутерів.
        nodes_info: {router_name: {console_host, console}}
        """
        self.current = {}

        for rname, info in nodes_info.items():
            host = info.get("console_host", "127.0.0.1")
            port = info.get("console", 0)
            if not port:
                continue

            print(f"  🔍 OSPF discovery: {rname}...", end=" ", flush=True)
            raw = collect_ospf_via_telnet(host, port)

            if not raw:
                print("⚠️  недоступний")
                continue

            neighbors = parse_ospf_neighbors(raw.get("neighbors",""))
            router_id = parse_ospf_router_id(raw.get("ospf_info",""))

            # Виявляємо нових сусідів
            prev_ids = set(self.previous.get(rname, []))
            for nb in neighbors:
                nb.is_new = nb.router_id not in prev_ids

            topo = RouterTopology(
                router_name = rname,
                router_id   = router_id,
                neighbors   = neighbors,
                timestamp   = datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
            self.current[rname] = topo
            new_count = sum(1 for nb in neighbors if nb.is_new)
            print(f"✅ {len(neighbors)} сусідів{' ('+str(new_count)+' нових!)' if new_count else ''}")

        self._save_cache()
        return self.current

    def get_new_neighbors(self) -> List[dict]:
        """Повертає список нових сусідів для автовалідації"""
        new = []
        for rname, topo in self.current.items():
            for nb in topo.neighbors:
                if nb.is_new:
                    new.append({
                        "discovered_on": rname,
                        "neighbor_id":   nb.router_id,
                        "address":       nb.address,
                        "interface":     nb.interface,
                        "state":         nb.state,
                    })
        return new

    def to_vis_graph(self) -> dict:
        """
        Конвертує топологію у формат для візуалізації:
        {nodes: [...], edges: [...]}
        """
        nodes_vis = []
        edges_vis = []
        seen_edges = set()

        for rname, topo in self.current.items():
            fail_count = 0  # буде заповнено з validator

            nodes_vis.append({
                "id":       rname,
                "label":    rname.replace("FRR-Router-","R"),
                "router_id":topo.router_id,
                "color":    "#2980B9",
                "shape":    "box",
                "ts":       topo.timestamp,
            })

            for nb in topo.neighbors:
                # Уникаємо дублікатів ребер
                edge_key = tuple(sorted([rname, nb.router_id]))
                if edge_key not in seen_edges:
                    seen_edges.add(edge_key)
                    state_color = "#3fb950" if "Full" in nb.state else "#d29922"
                    edges_vis.append({
                        "from":      rname,
                        "to":        nb.router_id,
                        "label":     nb.interface.split(":")[0],
                        "color":     state_color,
                        "state":     nb.state,
                        "is_new":    nb.is_new,
                    })

        return {"nodes": nodes_vis, "edges": edges_vis}
