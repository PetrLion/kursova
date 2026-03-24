"""
CIS Benchmark правила для FRR роутерів
Джерело: CIS Controls v8, CIS Cisco IOS Benchmark (адаптовано під FRR/Quagga)
"""

from dataclasses import dataclass, field
from typing import List, Optional
import re

@dataclass
class RuleResult:
    rule_id:     str
    title:       str
    severity:    str          # HIGH / MEDIUM / LOW
    status:      str          # PASS / FAIL / WARN
    detail:      str
    fix:         Optional[str] = None   # команда для виправлення
    interface:   Optional[str] = None

class CISRuleChecker:
    """
    Перевіряє конфігурацію FRR роутера по правилах CIS Benchmark.
    """

    def __init__(self, router_name: str, config: str):
        self.name   = router_name
        self.config = config
        self.lines  = config.splitlines()

    def check_all(self) -> List[RuleResult]:
        results = []
        results += self._r1_ospf_authentication()
        results += self._r2_ospf_passive_interface()
        results += self._r3_no_telnet()
        results += self._r4_password_encryption()
        results += self._r5_acl_on_edge()
        results += self._r6_logging()
        results += self._r7_no_ip_redirects()
        results += self._r8_no_ip_proxy_arp()
        results += self._r9_ssh_only()
        results += self._r10_default_route_control()
        return results

    # ── R1: OSPF MD5 Authentication ──────────────────────────────────────
    def _r1_ospf_authentication(self) -> List[RuleResult]:
        """
        CIS Control 11.3 / CIS Cisco IOS Benchmark §3.3.1
        OSPF повинен використовувати MD5 автентифікацію щоб запобігти
        ін'єкції фейкових маршрутів.
        """
        results = []
        has_ospf = any("router ospf" in l for l in self.lines)
        if not has_ospf:
            return results

        # Перевіряємо чи є auth на area або interface рівні
        has_area_auth = any(
            re.search(r"area\s+\d+\s+authentication\s+message-digest", l)
            for l in self.lines
        )
        has_iface_auth = any(
            re.search(r"ip ospf authentication message-digest", l)
            for l in self.lines
        )

        if has_area_auth or has_iface_auth:
            results.append(RuleResult(
                rule_id="CIS-R1", title="OSPF MD5 Authentication",
                severity="HIGH", status="PASS",
                detail="OSPF MD5 автентифікація налаштована"
            ))
        else:
            results.append(RuleResult(
                rule_id="CIS-R1", title="OSPF MD5 Authentication",
                severity="HIGH", status="FAIL",
                detail="OSPF працює БЕЗ автентифікації — можлива ін'єкція маршрутів",
                fix="router ospf\n  area 0 authentication message-digest"
            ))
        return results

    # ── R2: OSPF passive-interface ────────────────────────────────────────
    def _r2_ospf_passive_interface(self) -> List[RuleResult]:
        """
        CIS Cisco IOS §3.3.2
        Інтерфейси до кінцевих хостів не повинні розсилати OSPF Hello пакети.
        """
        results = []
        has_ospf = any("router ospf" in l for l in self.lines)
        if not has_ospf:
            return results

        has_passive = any("passive-interface" in l for l in self.lines)
        if has_passive:
            results.append(RuleResult(
                rule_id="CIS-R2", title="OSPF passive-interface",
                severity="MEDIUM", status="PASS",
                detail="passive-interface налаштовано"
            ))
        else:
            results.append(RuleResult(
                rule_id="CIS-R2", title="OSPF passive-interface",
                severity="MEDIUM", status="WARN",
                detail="Жоден інтерфейс не є passive — OSPF Hello відправляються на всі інтерфейси",
                fix="router ospf\n  passive-interface eth2\n  passive-interface eth3"
            ))
        return results

    # ── R3: No Telnet ─────────────────────────────────────────────────────
    def _r3_no_telnet(self) -> List[RuleResult]:
        """
        CIS Control 4.1 — не використовувати незашифровані протоколи управління
        """
        telnet_lines = [l for l in self.lines if re.search(r"telnet", l, re.I)]
        if telnet_lines:
            return [RuleResult(
                rule_id="CIS-R3", title="No Telnet",
                severity="HIGH", status="FAIL",
                detail=f"Знайдено telnet конфігурацію: {telnet_lines}",
                fix="no telnet\nservice ssh"
            )]
        return [RuleResult(
            rule_id="CIS-R3", title="No Telnet",
            severity="HIGH", status="PASS",
            detail="Telnet не використовується"
        )]

    # ── R4: Password encryption ───────────────────────────────────────────
    def _r4_password_encryption(self) -> List[RuleResult]:
        """
        CIS Control 5.2 — паролі повинні бути захищені
        """
        plain_pass = [l.strip() for l in self.lines
                      if re.search(r"password\s+\S+", l)
                      and not re.search(r"(md5|sha|encrypted|hash)", l, re.I)]
        if plain_pass:
            return [RuleResult(
                rule_id="CIS-R4", title="Password Encryption",
                severity="HIGH", status="FAIL",
                detail=f"Знайдено паролі у відкритому вигляді: {plain_pass[:3]}",
                fix="service password-encryption"
            )]
        return [RuleResult(
            rule_id="CIS-R4", title="Password Encryption",
            severity="HIGH", status="PASS",
            detail="Паролі зашифровані або відсутні"
        )]

    # ── R5: ACL on edge interfaces ────────────────────────────────────────
    def _r5_acl_on_edge(self) -> List[RuleResult]:
        """
        CIS Control 12.2 / CIS Cisco IOS §5.1
        На edge інтерфейсах повинні бути ACL
        """
        has_acl = any(
            re.search(r"ip access-(list|group)", l)
            for l in self.lines
        )
        if has_acl:
            return [RuleResult(
                rule_id="CIS-R5", title="ACL on Edge Interfaces",
                severity="HIGH", status="PASS",
                detail="ACL налаштовані на інтерфейсах"
            )]
        return [RuleResult(
            rule_id="CIS-R5", title="ACL on Edge Interfaces",
            severity="HIGH", status="FAIL",
            detail="Жодного ACL не знайдено на інтерфейсах",
            fix="ip access-list extended RESTRICT_PC3\n  deny ip 10.0.30.0/24 10.0.42.0/24\n  deny ip 10.0.30.0/24 10.0.41.0/24\n  permit ip any any"
        )]

    # ── R6: Logging ───────────────────────────────────────────────────────
    def _r6_logging(self) -> List[RuleResult]:
        """
        CIS Control 8.2 — централізоване логування
        """
        has_log = any(re.search(r"^log\s+", l) for l in self.lines)
        if has_log:
            return [RuleResult(
                rule_id="CIS-R6", title="Logging Enabled",
                severity="MEDIUM", status="PASS",
                detail="Логування налаштоване"
            )]
        return [RuleResult(
            rule_id="CIS-R6", title="Logging Enabled",
            severity="MEDIUM", status="WARN",
            detail="Логування не налаштоване",
            fix="log syslog\nlog file /var/log/frr/frr.log"
        )]

    # ── R7: No IP redirects ───────────────────────────────────────────────
    def _r7_no_ip_redirects(self) -> List[RuleResult]:
        """
        CIS Cisco IOS §3.1.3 — IP redirects можуть використовуватись для MITM
        """
        redirects = [l for l in self.lines if re.search(r"ip redirects", l)]
        if redirects:
            return [RuleResult(
                rule_id="CIS-R7", title="No IP Redirects",
                severity="MEDIUM", status="FAIL",
                detail="IP redirects увімкнені",
                fix="no ip redirects"
            )]
        return [RuleResult(
            rule_id="CIS-R7", title="No IP Redirects",
            severity="MEDIUM", status="PASS",
            detail="IP redirects вимкнені"
        )]

    # ── R8: No proxy ARP ──────────────────────────────────────────────────
    def _r8_no_ip_proxy_arp(self) -> List[RuleResult]:
        """
        CIS Cisco IOS §3.1.4 — proxy ARP може дозволити ARP spoofing
        """
        proxy = [l for l in self.lines if re.search(r"ip proxy-arp", l)]
        if proxy:
            return [RuleResult(
                rule_id="CIS-R8", title="No Proxy ARP",
                severity="MEDIUM", status="FAIL",
                detail="Proxy ARP увімкнений",
                fix="no ip proxy-arp"
            )]
        return [RuleResult(
            rule_id="CIS-R8", title="No Proxy ARP",
            severity="MEDIUM", status="PASS",
            detail="Proxy ARP вимкнений"
        )]

    # ── R9: SSH only (no plain HTTP/API) ──────────────────────────────────
    def _r9_ssh_only(self) -> List[RuleResult]:
        """
        CIS Control 4.1 — тільки зашифровані канали управління
        """
        has_ssh = any(re.search(r"ssh", l, re.I) for l in self.lines)
        return [RuleResult(
            rule_id="CIS-R9", title="SSH Management",
            severity="LOW", status="PASS" if has_ssh else "WARN",
            detail="SSH налаштовано" if has_ssh else "SSH не знайдено в конфігурації",
            fix=None if has_ssh else "# Налаштуйте SSH на управлінському інтерфейсі"
        )]

    # ── R10: Default route control ────────────────────────────────────────
    def _r10_default_route_control(self) -> List[RuleResult]:
        """
        CIS Control 12.4 — default route не повинен розповсюджуватись неконтрольовано
        """
        default_info = any(
            re.search(r"default-information originate", l)
            for l in self.lines
        )
        if default_info:
            return [RuleResult(
                rule_id="CIS-R10", title="Default Route Control",
                severity="MEDIUM", status="WARN",
                detail="default-information originate активно — перевірте чи це навмисно",
                fix="# Якщо не потрібно: no default-information originate"
            )]
        return [RuleResult(
            rule_id="CIS-R10", title="Default Route Control",
            severity="LOW", status="PASS",
            detail="Default route не розповсюджується через OSPF"
        )]
