import re
import subprocess
from dataclasses import dataclass

@dataclass
class LLDPNeighbor:
    local_device:     str = ""
    local_interface:  str = ""
    remote_device:    str = ""
    remote_interface: str = ""
    chassis_id:       str = ""

def get_docker_neighbors(device_name, container_name):
    """Отримує сусідів через Docker network inspect"""
    neighbors = []
    result = subprocess.run(
        ["docker", "network", "inspect", "org_network"],
        capture_output=True, text=True
    )

    import json
    try:
        data = json.loads(result.stdout)
        containers = data[0].get("Containers", {})
        for cid, info in containers.items():
            name = info.get("Name", "")
            ip   = info.get("IPv4Address", "").split("/")[0]
            mac  = info.get("MacAddress", "")
            if name != container_name:
                nb = LLDPNeighbor(
                    local_device    = device_name,
                    local_interface = "eth0",
                    remote_device   = name,
                    remote_interface= "eth0",
                    chassis_id      = mac,
                )
                neighbors.append(nb)
    except Exception as e:
        print(f"  [!] Помилка парсингу для {device_name}: {e}")
    return neighbors

def parse_all_devices(collected_data):
    all_neighbors = []
    seen = set()

    result = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"],
        capture_output=True, text=True
    )
    containers = result.stdout.strip().split("\n")

    for d in collected_data:
        if d.get("error"):
            continue
        container = d["name"]
        neighbors = get_docker_neighbors(d["name"], container)
        for nb in neighbors:
            key = frozenset([nb.local_device, nb.remote_device])
            if key not in seen:
                seen.add(key)
                all_neighbors.append(nb)
        print(f"  [✔] {d['name']}: "
              f"знайдено {len(neighbors)} сусідів")

    return all_neighbors
