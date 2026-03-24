"""
Збирає running-config з FRR роутерів через Docker exec
(GNS3 Docker контейнери не мають telnet — використовуємо docker exec)
"""
import requests
import subprocess
import json
import os
from requests.auth import HTTPBasicAuth
from datetime import datetime

API  = "http://localhost:3080/v2"
PID  = "8fefb24e-f5a7-47d5-81e2-1882e35cb37d"
AUTH = HTTPBasicAuth(
    "admin",
    "QuEipKKmvKI6PS0ZizY00qOTHQj8ku32QWFvnlmtS0JTDQTrPmaOc7k8zfR4qbl1"
)

ROUTERS = ["FRR-Router-1","FRR-Router-2","FRR-Router-3","FRR-Router-4"]

# Container IDs з виводу вище
CONTAINER_IDS = {
    "FRR-Router-1": "3b268ba0f09d4379c99545e15869e73581440bcdfcfba2684368966026e8ee2f",
    "FRR-Router-2": "9a89a0f4b4728fef9c0789171f18ad81890a115a4e054d09a1feacb50de6998f",
    "FRR-Router-3": "8a104a961a6a2cb72e50bffe5a397e5e38364bed3eb95e9c4bbb4d53245eb144",
    "FRR-Router-4": "232b0dff07280c4ab9cea0ed19426d4b1684b8d2a405aab8e171325ce9063a99",
}

os.makedirs("configs", exist_ok=True)

def gns3_online() -> bool:
    try:
        r = requests.get(f"{API}/version", auth=AUTH, timeout=3)
        return r.status_code == 200
    except:
        return False

def get_nodes() -> dict:
    try:
        r = requests.get(f"{API}/projects/{PID}/nodes", auth=AUTH, timeout=5)
        return {n["name"]: n for n in r.json()}
    except:
        return {}

def get_container_id(node: dict) -> str:
    """Отримує container_id з node properties"""
    props = node.get("properties", {})
    cid = props.get("container_id", "")
    if cid:
        return cid[:12]  # скорочений ID
    # Fallback — з нашого словника
    name = node.get("name","")
    full = CONTAINER_IDS.get(name,"")
    return full[:12] if full else ""

def collect_via_docker(container_id: str, router_name: str) -> str:
    """Збирає конфіг через docker exec"""
    commands = [
        ["docker", "exec", container_id, "vtysh", "-c", "show running-config"],
        ["docker", "exec", container_id, "cat", "/etc/frr/frr.conf"],
        ["docker", "exec", container_id, "sh", "-c", "vtysh -c 'show running-config' 2>/dev/null || cat /etc/frr/frr.conf"],
    ]
    for cmd in commands:
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10
            )
            output = result.stdout.strip()
            if output and len(output) > 20:
                return output
        except Exception as e:
            continue
    return ""

def collect_via_telnet(host: str, port: int, timeout=8) -> str:
    """Fallback: telnet консоль"""
    import telnetlib, time
    try:
        tn = telnetlib.Telnet(host, port, timeout=timeout)
        time.sleep(1)
        tn.write(b"\n")
        time.sleep(0.5)
        tn.write(b"vtysh -c 'show running-config'\n")
        time.sleep(2)
        data = tn.read_very_eager()
        tn.close()
        return data.decode("utf-8", errors="ignore")
    except:
        return ""

def load_from_cache(router_name: str) -> dict:
    fname = f"configs/{router_name}_latest.cfg"
    if os.path.exists(fname):
        content = open(fname, encoding="utf-8").read()
        if content.strip():
            return {
                "status":    "cached",
                "config":    content,
                "timestamp": datetime.fromtimestamp(
                    os.path.getmtime(fname)
                ).strftime("%Y-%m-%d %H:%M:%S"),
            }
    return {"status": "offline", "config": "", "timestamp": ""}

def collect_configs() -> dict:
    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    configs = {}

    print(f"\n{'='*55}")
    print(f"  Збір конфігурацій — {ts}")
    print(f"{'='*55}\n")

    if not gns3_online():
        print("  ⚠️  GNS3 недоступний — завантажую кеш\n")
        for rname in ROUTERS:
            configs[rname] = load_from_cache(rname)
        return configs

    nodes = get_nodes()
    if not nodes:
        print("  ⚠️  Проект не відкритий — завантажую кеш\n")
        for rname in ROUTERS:
            configs[rname] = load_from_cache(rname)
        return configs

    for rname in ROUTERS:
        print(f"  📡 {rname:<20}", end=" ... ", flush=True)

        if rname not in nodes:
            print("не знайдено → кеш")
            configs[rname] = load_from_cache(rname)
            continue

        node = nodes[rname]
        cid  = get_container_id(node)

        config = ""

        # Спроба 1: docker exec
        if cid:
            config = collect_via_docker(cid, rname)
            if config:
                print(f"✅ docker exec ({len(config.splitlines())} рядків)", end="")

        # Спроба 2: telnet
        if not config:
            host = node.get("console_host","127.0.0.1")
            port = node.get("console", 0)
            if port:
                config = collect_via_telnet(host, port)
                if config:
                    print(f"✅ telnet ({len(config.splitlines())} рядків)", end="")

        # Fallback: кеш
        if not config:
            print("⚠️  → кеш", end="")
            configs[rname] = load_from_cache(rname)
            print()
            continue

        # Зберігаємо
        fname = f"configs/{rname}_{ts}.cfg"
        with open(fname, "w") as f: f.write(config)
        with open(f"configs/{rname}_latest.cfg","w") as f: f.write(config)

        configs[rname] = {
            "status":    "online",
            "config":    config,
            "timestamp": ts,
            "file":      fname,
        }
        print()

    return configs
