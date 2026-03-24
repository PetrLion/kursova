from flask import Flask, render_template_string, jsonify
import threading, json, os, glob, time
from datetime import datetime
from collector import collect_configs, ROUTERS
from validator import validate_config

app    = Flask(__name__)

state = {
    "configs":    {},
    "results":    {},
    "summary":    {"pass":0,"fail":0,"warn":0,"score":0,"total":0},
    "last_scan":  None,
    "scanning":   False,
}

def do_scan():
    if state["scanning"]: return
    state["scanning"] = True
    cfgs = collect_configs()
    results = {}
    for rname, data in cfgs.items():
        cfg = data.get("config","")
        if cfg:
            results[rname] = [dict(r._asdict()) for r in validate_config(rname, cfg)]
    all_c  = [r for v in results.values() for r in v]
    total  = len(all_c)
    passes = sum(1 for r in all_c if r["status"]=="PASS")
    fails  = sum(1 for r in all_c if r["status"]=="FAIL")
    warns  = sum(1 for r in all_c if r["status"]=="WARN")
    score  = round(passes/total*100) if total else 0
    summary = {"pass":passes,"fail":fails,"warn":warns,"score":score,"total":total}
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    state.update({
        "configs":    cfgs,
        "results":    results,
        "summary":    summary,
        "last_scan":  ts,
        "scanning":   False,
    })

@app.route("/")
def index():
    # Дуже простий шаблон для тесту
    return "<h1>Network Security Validator (DEMO)</h1>" \
           "<a href='/api/scan'>Scan configs</a> | <a href='/api/state'>State</a>"

@app.route("/api/state")
def api_state():
    return jsonify(state)

@app.route("/api/scan")
def api_scan():
    do_scan()
    return jsonify({"status":"ok"})

if __name__ == "__main__":
    app.run(port=5050)
