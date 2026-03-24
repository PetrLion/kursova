"""
Збирає running-config з FRR роутерів через GNS3 API + telnet консоль,
або із кешу, якщо GNS3/API офлайн.
"""
import os
from datetime import datetime

ROUTERS = ["FRR-Router-1","FRR-Router-2","FRR-Router-3","FRR-Router-4"]

os.makedirs("configs", exist_ok=True)

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
    configs = {}
    print(f"\n{'='*55}")
    print("  Збір конфігурацій з кешу")
    print(f"{'='*55}\n")
    for rname in ROUTERS:
        configs[rname] = load_from_cache(rname)
        print(f"  📂 {rname:<20} [{configs[rname]['status']}] {len(configs[rname]['config'].splitlines()) if configs[rname]['config'] else 0} рядків")
    return configs

# (залиште реальні collect_via_telnet/get_nodes тільки якщо справді підключаєтесь до GNS3)
