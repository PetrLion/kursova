from collector   import load_inventory, collect_all
from parser      import parse_all_devices
from auditor     import audit_all
from topology    import build_topology
from acl_manager import generate_and_deploy_acl
import sys

def main():
    print("\n" + "=" * 60)
    print("  Система автоматизованої валідації конфігурацій")
    print("  Мережевих пристроїв — Мала організація")
    print("=" * 60)

    inventory = load_inventory("config.yaml")
    print(f"\n[*] Завантажено {len(inventory)} пристроїв з config.yaml")

    # ── Крок 1: SSH-збір ─────────────────────────────────────────
    print("\n" + "-" * 60)
    print("[1/4] Збір даних через SSH (LLDP + running-config)...")
    print("-" * 60)
    collected = collect_all("config.yaml")

    # ── Крок 2: Парсинг LLDP ─────────────────────────────────────
    print("\n" + "-" * 60)
    print("[2/4] Парсинг LLDP-виводу...")
    print("-" * 60)
    neighbors = parse_all_devices(collected)

    if not neighbors:
        print("[!] LLDP-сусідів не знайдено!")
        print("    Перевірте: lldp run на всіх пристроях")
        sys.exit(1)

    # ── Крок 3: Аудит CIS Benchmark ──────────────────────────────
    print("\n" + "-" * 60)
    print("[3/4] Аудит конфігурацій (CIS Benchmark)...")
    print("-" * 60)
    audit_results = audit_all(collected)

    # ── Крок 4: Топологія ─────────────────────────────────────────
    print("\n" + "-" * 60)
    print("[4/4] Побудова топологічної карти...")
    print("-" * 60)
    build_topology(neighbors, inventory, audit_results,
                   "topology.html")

    # ── Крок 5: ACL ───────────────────────────────────────────────
    generate_and_deploy_acl(inventory, collected)

    print("\n" + "=" * 60)
    print("[✓] ГОТОВО!")
    print("    → Відкрий topology.html у браузері")
    print("=" * 60 + "\n")

if __name__ == "__main__":
    main()
