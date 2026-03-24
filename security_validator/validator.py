"""
Валідатор конфігурацій — запускає CIS правила + генерує звіт
"""

import os
import json
from datetime import datetime
from rules.cis_rules import CISRuleChecker, RuleResult
from typing import Dict, List

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
STATUS_ICON    = {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️ "}

def validate_config(router_name: str, config: str) -> List[RuleResult]:
    checker = CISRuleChecker(router_name, config)
    results = checker.check_all()
    return sorted(results, key=lambda r: SEVERITY_ORDER.get(r.severity, 9))

def print_report(all_results: Dict[str, List[RuleResult]]):
    print(f"\n{'='*70}")
    print(f"  🔒 ЗВІТ БЕЗПЕКОВОЇ ВАЛІДАЦІЇ КОНФІГУРАЦІЙ")
    print(f"  Час: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*70}\n")

    total_pass = total_fail = total_warn = 0

    for router, results in all_results.items():
        if not results:
            continue

        fails = [r for r in results if r.status == "FAIL"]
        warns = [r for r in results if r.status == "WARN"]
        passes= [r for r in results if r.status == "PASS"]

        total_fail += len(fails)
        total_warn += len(warns)
        total_pass += len(passes)

        # Заголовок роутера
        status_icon = "🔴" if fails else ("🟡" if warns else "🟢")
        print(f"  {status_icon} {router}")
        print(f"  {'─'*50}")

        for r in results:
            icon = STATUS_ICON[r.status]
            sev  = f"[{r.severity:6s}]"
            print(f"    {icon} {sev} {r.rule_id:10s} {r.title}")
            print(f"           {r.detail}")
            if r.fix and r.status in ("FAIL","WARN"):
                print(f"           💡 Fix: {r.fix.splitlines()[0]}")
            print()
        print()

    # Підсумок
    total = total_pass + total_fail + total_warn
    print(f"{'='*70}")
    print(f"  📊 ПІДСУМОК:")
    print(f"     ✅ PASS:  {total_pass}/{total}")
    print(f"     ❌ FAIL:  {total_fail}/{total}")
    print(f"     ⚠️  WARN:  {total_warn}/{total}")
    score = int((total_pass / total * 100) if total else 0)
    bar   = "█" * (score // 5) + "░" * (20 - score // 5)
    print(f"\n  🏆 Security Score: [{bar}] {score}%")
    print(f"{'='*70}\n")

    return {"pass": total_pass, "fail": total_fail, "warn": total_warn, "score": score}

def save_json_report(all_results: Dict[str, List[RuleResult]], summary: dict):
    os.makedirs("reports", exist_ok=True)
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    data = {
        "timestamp": ts,
        "summary":   summary,
        "routers": {
            router: [
                {
                    "rule_id":  r.rule_id,
                    "title":    r.title,
                    "severity": r.severity,
                    "status":   r.status,
                    "detail":   r.detail,
                    "fix":      r.fix,
                }
                for r in results
            ]
            for router, results in all_results.items()
        }
    }
    fname = f"reports/report_{ts}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"  💾 JSON звіт збережено: {fname}")
    return fname
