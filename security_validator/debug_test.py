import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from collector import collect_configs, ROUTERS
from validator import validate_config
from rules.cis_rules import RuleResult

print("=== Тест збору конфігурацій ===")
cfgs = collect_configs()
for rname, data in cfgs.items():
    cfg = data.get("config","")
    print(f"{rname}: {len(cfg)} chars, status={data.get('status')}")

print("\n=== Тест валідації ===")
results = {}
for rname, data in cfgs.items():
    cfg = data.get("config","")
    if not cfg:
        f = f"configs/{rname}_latest.cfg"
        if os.path.exists(f):
            cfg = open(f).read()
    if cfg:
        raw = validate_config(rname, cfg)
        results[rname] = [
            {"rule_id":r.rule_id,"title":r.title,"severity":r.severity,
             "status":r.status,"detail":r.detail,"fix":r.fix or ""}
            for r in raw
        ]
        print(f"{rname}: {len(results[rname])} правил")

import json
print("\n=== JSON серіалізація ===")
try:
    s = json.dumps(results)
    print(f"OK, {len(s)} chars")
except Exception as e:
    print(f"ПОМИЛКА: {e}")
