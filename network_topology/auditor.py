import re
import subprocess
from dataclasses import dataclass, field

@dataclass
class AuditResult:
    device_name: str
    warnings: list = field(default_factory=list)
    info:     list = field(default_factory=list)

    @property
    def is_clean(self):
        return len(self.warnings) == 0

def get_container_by_name(name):
    result = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"],
        capture_output=True, text=True
    )
    for c in result.stdout.strip().split("\n"):
        if name.lower() in c.lower() or c.lower() in name.lower():
            return c
    return name

def check_root_login(config, result):
    """CIS 1.1 — PermitRootLogin"""
    if re.search(r"PermitRootLogin\s+yes", config, re.IGNORECASE):
        result.warnings.append(
            "⚠ [CIS 1.1] PermitRootLogin yes — небезпечно! "
            "Встановіть: PermitRootLogin no"
        )
    else:
        result.info.append("✔ [CIS 1.1] PermitRootLogin OK")

def check_empty_passwords(config, result):
    """CIS 1.2 — PermitEmptyPasswords"""
    if re.search(r"PermitEmptyPasswords\s+yes", config, re.IGNORECASE):
        result.warnings.append(
            "⚠ [CIS 1.2] PermitEmptyPasswords yes — КРИТИЧНО!"
        )
    else:
        result.info.append("✔ [CIS 1.2] PermitEmptyPasswords OK")

def check_protocol_version(config, result):
    """CIS 1.3 — SSH Protocol version"""
    if re.search(r"Protocol\s+1", config, re.IGNORECASE):
        result.warnings.append(
            "⚠ [CIS 1.3] SSH Protocol 1 — застарілий!"
        )
    else:
        result.info.append("✔ [CIS 1.3] SSH Protocol OK")

def check_acl(config, result):
    """CIS 2.1 — IPTables ACL"""
    if "Chain INPUT (policy ACCEPT)" in config and \
       "0 references" not in config and \
       re.search(r"DROP|REJECT", config):
        result.info.append("✔ [CIS 2.1] IPTables правила є")
    else:
        result.warnings.append(
            "⚠ [CIS 2.1] IPTables порожній — немає фільтрації!"
        )

def check_password_auth(config, result):
    """CIS 1.4 — PasswordAuthentication"""
    if re.search(r"PasswordAuthentication\s+no", config, re.IGNORECASE):
        result.info.append("✔ [CIS 1.4] PasswordAuth вимкнено (ключі)")
    else:
        result.warnings.append(
            "⚠ [CIS 1.4] PasswordAuthentication yes — "
            "рекомендується аутентифікація по ключу"
        )

def check_banner(config, result):
    """CIS 4.1 — SSH Banner"""
    if re.search(r"Banner\s+\S+", config, re.IGNORECASE):
        result.info.append("✔ [CIS 4.1] SSH Banner налаштовано")
    else:
        result.warnings.append(
            "⚠ [CIS 4.1] SSH Banner відсутній"
        )

def audit_device(device_data):
    result = AuditResult(device_name=device_data["name"])
    if device_data.get("error"):
        result.warnings.append(
            f"Пристрій недоступний: {device_data['error']}"
        )
        return result
    config = device_data.get("running_config_raw", "")
    check_root_login(config, result)
    check_empty_passwords(config, result)
    check_protocol_version(config, result)
    check_acl(config, result)
    check_password_auth(config, result)
    check_banner(config, result)
    return result

def audit_all(collected_data):
    results = [audit_device(d) for d in collected_data]
    print("\n" + "=" * 60)
    print("      ЗВІТ АУДИТУ БЕЗПЕКИ — CIS BENCHMARK")
    print("=" * 60)
    for r in results:
        status = "✔ CLEAN" if r.is_clean else "⚠ ISSUES FOUND"
        print(f"\n┌─ [ {r.device_name} ] {status}")
        for msg in r.info:
            print(f"│  {msg}")
        for msg in r.warnings:
            print(f"│  {msg}")
        print("└" + "─" * 40)
    print("=" * 60)
    return results
