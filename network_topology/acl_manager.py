import yaml
import subprocess

def load_inventory(path="config.yaml"):
    with open(path) as f:
        return yaml.safe_load(f)["devices"]

def get_container_by_ip(ip):
    result = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"],
        capture_output=True, text=True
    )
    for name in result.stdout.strip().split("\n"):
        inspect = subprocess.run(
            ["docker", "inspect", "--format",
             "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
             name],
            capture_output=True, text=True
        )
        if ip in inspect.stdout:
            return name
    return None

def generate_and_deploy_acl(inventory, collected_data,
                             target_role="core",
                             interface="eth0"):
    print("\n" + "=" * 60)
    print("      ГЕНЕРАЦІЯ ТА РОЗГОРТАННЯ ACL (IPTables)")
    print("=" * 60)

    attacker_ips = [
        d["host"] for d in inventory
        if d.get("role") == "attacker"
    ]

    if not attacker_ips:
        print("[!] Атакерів не знайдено")
        return

    print("\n[*] Генерація правил IPTables:")
    for ip in attacker_ips:
        print(f"    iptables -I INPUT -s {ip} -j DROP")
        print(f"    iptables -I FORWARD -s {ip} -j DROP")

    core_devices = [d for d in inventory
                    if d.get("role") == target_role]

    for device in core_devices:
        container = get_container_by_ip(device["host"])
        if not container:
            print(f"[!] Контейнер {device['name']} не знайдено")
            continue

        print(f"\n[*] Розгортання на {device['name']} "
              f"(container: {container})...")

        for ip in attacker_ips:
            # Блокуємо вхідний трафік від атакера
            r1 = subprocess.run(
                ["docker", "exec", container,
                 "iptables", "-I", "INPUT",
                 "-s", ip, "-j", "DROP"],
                capture_output=True, text=True
            )
            # Блокуємо forwarding
            r2 = subprocess.run(
                ["docker", "exec", container,
                 "iptables", "-I", "FORWARD",
                 "-s", ip, "-j", "DROP"],
                capture_output=True, text=True
            )
            if r1.returncode == 0:
                print(f"[+] Заблоковано: {ip} → DROP (INPUT)")
            if r2.returncode == 0:
                print(f"[+] Заблоковано: {ip} → DROP (FORWARD)")

        # Показати поточні правила
        rules = subprocess.run(
            ["docker", "exec", container,
             "iptables", "-L", "INPUT", "-n", "--line-numbers"],
            capture_output=True, text=True
        )
        print(f"\n[*] Поточні IPTables правила на {device['name']}:")
        print(rules.stdout)
        print(f"[+] ACL успішно розгорнуто на {device['name']}!")

    print("=" * 60)
