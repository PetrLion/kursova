"""
Головний скрипт системи валідації конфігурацій мережевих пристроїв
Курсова робота — Маслов Петро, НаУКМА 2025
"""

import sys
import os
import requests
from requests.auth import HTTPBasicAuth

sys.path.insert(0, os.path.dirname(__file__))

from collector    import collect_configs, get_nodes, ROUTERS, API, AUTH, PID
from validator    import validate_config, print_report, save_json_report
from remediation  import auto_remediate

def load_latest_configs() -> dict:
    """Завантажує останні збережені конфіги (якщо роутери офлайн)"""
    configs = {}
    for router in ROUTERS:
        fname = f"configs/{router}_latest.cfg"
        if os.path.exists(fname):
            with open(fname) as f:
                content = f.read()
            configs[router] = {"status":"cached","config":content}
            print(f"  📂 {router} — завантажено з кешу ({fname})")
    return configs

def main():
    print("\n" + "="*60)
    print("  🛡️  СИСТЕМА ВАЛІДАЦІЇ КОНФІГУРАЦІЙ МЕРЕЖЕВИХ ПРИСТРОЇВ")
    print("  Курсова робота | Маслов Петро | НаУКМА 2025")
    print("="*60)

    # 1. Збираємо конфіги
    print("\n📡 Крок 1: Збір конфігурацій...")
    configs = collect_configs()

    # Якщо нічого не зібрали — беремо з кешу
    online = {k:v for k,v in configs.items() if v.get("config")}
    if not online:
        print("\n  ⚠️  Роутери офлайн або телнет не відповідає")
        print("  📂 Завантажую конфіги з кешу...")
        configs = load_latest_configs()
        if not configs:
            print("  ❌ Немає збережених конфігурацій")
            print("  💡 Запустіть спочатку роутери в GNS3")
            sys.exit(1)

    # 2. Валідуємо
    print("\n🔍 Крок 2: Валідація по CIS Benchmark правилах...")
    all_results = {}
    for router_name, data in configs.items():
        cfg = data.get("config","")
        if not cfg:
            print(f"  ⏭️  {router_name} — порожня конфігурація")
            continue
        print(f"  🔍 Перевіряю {router_name}...")
        all_results[router_name] = validate_config(router_name, cfg)

    if not all_results:
        print("  ❌ Немає даних для валідації")
        sys.exit(1)

    # 3. Звіт
    print("\n📊 Крок 3: Генерація звіту...")
    summary = print_report(all_results)
    save_json_report(all_results, summary)

    # 4. Автовиправлення (тільки якщо є онлайн роутери)
    if online and summary["fail"] > 0:
        answer = input("\n❓ Автоматично виправити HIGH проблеми? [y/N]: ").strip().lower()
        if answer == "y":
            nodes_info = {
                name: {
                    "console_host": node.get("console_host","127.0.0.1"),
                    "console":      node.get("console",0)
                }
                for name, node in get_nodes().items()
            }
            auto_remediate(all_results, nodes_info, auto_fix_severity=["HIGH"])

            # Повторна валідація після виправлень
            print("\n🔄 Повторна валідація після виправлень...")
            configs2  = collect_configs()
            results2  = {
                r: validate_config(r, configs2[r]["config"])
                for r in configs2 if configs2[r].get("config")
            }
            print_report(results2)
            save_json_report(results2, summary)

    print("\n✅ Готово!\n")

if __name__ == "__main__":
    main()
