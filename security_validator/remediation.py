"""
Автоматичне виправлення знайдених проблем через GNS3 telnet консоль
"""

import telnetlib
import time
from rules.cis_rules import RuleResult
from typing import List

# FRR vtysh команди для виправлення
FIX_COMMANDS = {
    "CIS-R1": [
        "configure terminal",
        "router ospf",
        "area 0 authentication message-digest",
        "exit",
        "exit",
        "write memory",
    ],
    "CIS-R2": [
        "configure terminal",
        "router ospf",
        "passive-interface eth2",
        "passive-interface eth3",
        "exit",
        "exit",
        "write memory",
    ],
    "CIS-R6": [
        "configure terminal",
        "log syslog",
        "log file /var/log/frr/frr.log",
        "exit",
        "write memory",
    ],
}

def apply_fix(host: str, port: int, rule_id: str, router_name: str) -> bool:
    """Застосовує виправлення через vtysh консоль"""
    commands = FIX_COMMANDS.get(rule_id)
    if not commands:
        print(f"    ℹ️  Немає автоматичного виправлення для {rule_id}")
        return False

    print(f"    🔧 Застосовую {rule_id} на {router_name}...")
    try:
        tn = telnetlib.Telnet(host, port, timeout=10)
        time.sleep(1)
        tn.write(b"\n")
        time.sleep(0.5)

        full_cmd = "vtysh << 'VTYEOF'\n"
        full_cmd += "\n".join(commands)
        full_cmd += "\nVTYEOF\n"

        tn.write(full_cmd.encode())
        time.sleep(3)
        output = tn.read_very_eager().decode("utf-8", errors="ignore")
        tn.close()

        print(f"    ✅ {rule_id} виправлено")
        return True
    except Exception as e:
        print(f"    ❌ Помилка: {e}")
        return False

def auto_remediate(
    all_results: dict,
    nodes_info:  dict,
    auto_fix_severity: List[str] = ["HIGH"]
):
    """
    Автоматично виправляє FAIL результати для вказаних severity рівнів
    """
    print(f"\n{'='*60}")
    print(f"  🔧 АВТОМАТИЧНЕ ВИПРАВЛЕННЯ")
    print(f"  Auto-fix для severity: {auto_fix_severity}")
    print(f"{'='*60}\n")

    fixed = 0
    for router_name, results in all_results.items():
        node = nodes_info.get(router_name, {})
        host = node.get("console_host","127.0.0.1")
        port = node.get("console", 0)

        if not port:
            continue

        for r in results:
            if r.status == "FAIL" and r.severity in auto_fix_severity:
                success = apply_fix(host, port, r.rule_id, router_name)
                if success:
                    fixed += 1

    print(f"\n  📊 Виправлено: {fixed} проблем\n")
    return fixed
