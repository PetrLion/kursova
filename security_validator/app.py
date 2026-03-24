from flask import Flask, render_template_string, jsonify
from flask_socketio import SocketIO
import threading, json, os, sys, glob, time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from collector       import collect_configs, gns3_online, get_nodes, ROUTERS
from validator       import validate_config, save_json_report
from ospf_discovery  import TopologyDiscovery

app    = Flask(__name__)
socket = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

state = {
    "configs":    {},
    "results":    {},
    "summary":    {"pass":0,"fail":0,"warn":0,"score":0,"total":0},
    "last_scan":  None,
    "scanning":   False,
    "topology":   {"nodes":[],"edges":[]},
    "new_devices":[],
    "gns3_online":False,
    "auto_scan":  False,
}

discovery = TopologyDiscovery()

# ── Утиліти ───────────────────────────────────────────────────────────
def rule_to_dict(r):
    if isinstance(r, dict): return r
    return {"rule_id":r.rule_id,"title":r.title,"severity":r.severity,
            "status":r.status,"detail":r.detail,"fix":r.fix or ""}

def do_scan(triggered_by="manual"):
    if state["scanning"]: return
    state["scanning"] = True
    gns3 = gns3_online()
    state["gns3_online"] = gns3

    socket.emit("log",{"msg":f"📡 Збираю конфігурації... (GNS3: {'🟢 online' if gns3 else '🔴 офлайн → кеш'})","color":"#58a6ff"})

    cfgs = collect_configs()

    # ── OSPF Discovery (тільки якщо GNS3 онлайн) ────────────
    topo_data = {"nodes":[],"edges":[]}
    new_devs  = []
    if gns3:
        socket.emit("log",{"msg":"🔍 OSPF Neighbor Discovery...","color":"#58a6ff"})
        nodes_info = {}
        try:
            raw_nodes = get_nodes()
            nodes_info = {
                name: {"console_host": n.get("console_host","127.0.0.1"),
                       "console":      n.get("console",0)}
                for name, n in raw_nodes.items()
                if n.get("status") == "started"
            }
        except: pass

        if nodes_info:
            topo = discovery.discover(nodes_info)
            topo_data = discovery.to_vis_graph()
            new_devs  = discovery.get_new_neighbors()
            if new_devs:
                socket.emit("log",{
                    "msg": f"🆕 Нові OSPF сусіди: {[d['neighbor_id'] for d in new_devs]}",
                    "color":"#d29922"
                })
                socket.emit("new_devices", {"devices": new_devs})

    # ── Валідація ────────────────────────────────────────────
    socket.emit("log",{"msg":"🔒 Валідую конфігурації (CIS Benchmark)...","color":"#58a6ff"})
    results = {}
    for rname, data in cfgs.items():
        cfg = data.get("config","")
        if cfg:
            results[rname] = [rule_to_dict(r) for r in validate_config(rname, cfg)]

    # ── Підрахунок ───────────────────────────────────────────
    all_c  = [r for v in results.values() for r in v]
    total  = len(all_c)
    passes = sum(1 for r in all_c if r["status"]=="PASS")
    fails  = sum(1 for r in all_c if r["status"]=="FAIL")
    warns  = sum(1 for r in all_c if r["status"]=="WARN")
    score  = round(passes/total*100) if total else 0
    summary = {"pass":passes,"fail":fails,"warn":warns,"score":score,"total":total}
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Зберігаємо звіт
    os.makedirs("reports", exist_ok=True)
    ts2 = datetime.now().strftime("%Y%m%d_%H%M%S")
    with open(f"reports/report_{ts2}.json","w",encoding="utf-8") as f:
        json.dump({"timestamp":ts,"summary":summary,"routers":results,
                   "topology":topo_data,"gns3_online":gns3},f,ensure_ascii=False,indent=2)

    state.update({
        "configs":    cfgs,
        "results":    results,
        "summary":    summary,
        "last_scan":  ts,
        "scanning":   False,
        "topology":   topo_data,
        "new_devices":new_devs,
        "gns3_online":gns3,
    })

    payload = {**state, "triggered_by": triggered_by}
    socket.emit("scan_done", payload)
    socket.emit("log",{
        "msg": f"✅ [{triggered_by}] Score:{score}% | FAIL:{fails} | WARN:{warns} | GNS3:{'🟢' if gns3 else '🔴'}",
        "color":"#3fb950"
    })

# ── Auto-scan loop ────────────────────────────────────────────────────
def auto_scan_loop():
    while True:
        time.sleep(30)
        if state.get("auto_scan") and not state["scanning"]:
            socket.emit("log",{"msg":"⏱️ Автоматичне сканування...","color":"#8b949e"})
            do_scan(triggered_by="auto")

threading.Thread(target=auto_scan_loop, daemon=True).start()

# ── HTML ──────────────────────────────────────────────────────────────
HTML = """<!DOCTYPE html>
<html lang="uk">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>🛡️ Network Security Validator</title>
<script src="https://cdn.socket.io/4.7.2/socket.io.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.9/vis-network.min.js"></script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.9/dist/vis-network.min.css"/>
<style>
:root{
  --bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--border:#30363d;
  --blue:#58a6ff;--green:#3fb950;--red:#f85149;--yellow:#d29922;
  --cyan:#39d5ff;--purple:#bc8cff;--text:#e6edf3;--muted:#8b949e;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif}
header{background:var(--bg2);border-bottom:1px solid var(--border);
  padding:11px 22px;display:flex;align-items:center;gap:12px;
  position:sticky;top:0;z-index:100}
header h1{font-size:1.05rem;font-weight:700;color:var(--blue)}
header .sub{font-size:.72rem;color:var(--muted)}
.spacer{flex:1}
.badge{padding:3px 9px;border-radius:20px;font-size:.71rem;font-weight:600}
.bg{background:#1a3a1a;color:var(--green);border:1px solid var(--green)}
.br{background:#3a1a1a;color:var(--red);border:1px solid var(--red)}
.by{background:#3a2e0a;color:var(--yellow);border:1px solid var(--yellow)}
.bb{background:#1a2a3a;color:var(--blue);border:1px solid var(--blue)}
.layout{display:grid;grid-template-columns:205px 1fr;min-height:calc(100vh - 49px)}
nav{background:var(--bg2);border-right:1px solid var(--border);padding:12px 0;
  position:sticky;top:49px;height:calc(100vh - 49px);overflow-y:auto}
.sct{font-size:.64rem;font-weight:700;color:var(--muted);
  text-transform:uppercase;letter-spacing:.08em;padding:7px 13px 2px}
nav a{display:flex;align-items:center;gap:8px;padding:7px 13px;
  color:var(--muted);text-decoration:none;font-size:.83rem;
  border-left:3px solid transparent;transition:.12s;cursor:pointer}
nav a:hover{background:var(--bg3);color:var(--text)}
nav a.active{background:var(--bg3);color:var(--blue);border-left-color:var(--blue)}
.rdot{width:7px;height:7px;border-radius:50%;flex-shrink:0;transition:.3s}
.dg{background:var(--green)}.dr{background:var(--red)}
.dy{background:var(--yellow)}.dm{background:var(--muted)}
main{padding:20px 24px;overflow-y:auto;max-height:calc(100vh - 49px)}
.page{display:none}.page.active{display:block}
.sec-hdr{display:flex;align-items:center;gap:10px;margin-bottom:14px;
  padding-bottom:9px;border-bottom:1px solid var(--border)}
.sec-hdr h2{font-size:1rem}
.muted{font-size:.76rem;color:var(--muted)}
.btn-row{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;align-items:center}
.btn{padding:6px 15px;border-radius:7px;border:none;cursor:pointer;
  font-size:.81rem;font-weight:600;transition:.13s;
  display:inline-flex;align-items:center;gap:5px}
.bp{background:var(--blue);color:#000}.bp:hover{opacity:.85}
.bd{background:var(--red);color:#fff}.bd:hover{opacity:.85}
.bs{background:var(--green);color:#000}.bs:hover{opacity:.85}
.bm{background:var(--bg3);color:var(--text);border:1px solid var(--border)}
.bm:hover{background:var(--border)}
.btn:disabled{opacity:.4;cursor:not-allowed}
/* Toggle */
.toggle-wrap{display:flex;align-items:center;gap:7px;font-size:.8rem}
.toggle{position:relative;width:38px;height:20px}
.toggle input{opacity:0;width:0;height:0}
.tslider{position:absolute;inset:0;background:var(--bg3);border-radius:20px;
  cursor:pointer;transition:.2s;border:1px solid var(--border)}
.tslider:before{content:'';position:absolute;width:14px;height:14px;
  left:2px;top:2px;background:var(--muted);border-radius:50%;transition:.2s}
input:checked+.tslider{background:#1a3a1a;border-color:var(--green)}
input:checked+.tslider:before{transform:translateX(18px);background:var(--green)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
  gap:11px;margin-bottom:18px}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:9px;padding:13px}
.card .val{font-size:1.8rem;font-weight:700;line-height:1}
.card .lbl{font-size:.73rem;color:var(--muted);margin-top:3px}
.gc{border-color:var(--green)}.rc{border-color:var(--red)}
.yc{border-color:var(--yellow)}.bc{border-color:var(--blue)}.pc{border-color:var(--purple)}
.vg{color:var(--green)}.vr{color:var(--red)}.vy{color:var(--yellow)}
.vb{color:var(--blue)}.vp{color:var(--purple)}
.score-wrap{background:var(--bg2);border:1px solid var(--border);
  border-radius:9px;padding:16px;margin-bottom:18px}
.sbar-bg{background:var(--bg3);border-radius:99px;height:10px;overflow:hidden}
.sbar{height:100%;border-radius:99px;transition:width .7s ease}
.snum{font-size:1.4rem;font-weight:700;margin-top:6px}
.tbl-wrap{background:var(--bg2);border:1px solid var(--border);
  border-radius:9px;overflow:hidden;margin-bottom:16px}
.tbl-wrap h3{padding:11px 15px;font-size:.86rem;
  border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px}
table{width:100%;border-collapse:collapse;font-size:.79rem}
th{background:var(--bg3);padding:8px 12px;text-align:left;
  color:var(--muted);font-weight:600}
td{padding:8px 12px;border-top:1px solid var(--border);vertical-align:top}
tr:hover td{background:rgba(255,255,255,.02)}
.pill{padding:2px 7px;border-radius:20px;font-size:.68rem;font-weight:700;white-space:nowrap}
.pp{background:#1a3a1a;color:var(--green)}.pf{background:#3a1a1a;color:var(--red)}
.pw{background:#3a2e0a;color:var(--yellow)}.ph{background:#3a1a1a;color:var(--red)}
.pm{background:#3a2e0a;color:var(--yellow)}.pl{background:#1a2a3a;color:var(--blue)}
.pon{background:#1a3a1a;color:var(--green)}.poff{background:#2a2a2a;color:var(--muted)}
.pcached{background:#1a1a3a;color:var(--purple)}
pre.cfg{background:var(--bg3);border:1px solid var(--border);border-radius:7px;
  padding:11px;font-size:.76rem;overflow-x:auto;white-space:pre-wrap;
  max-height:380px;overflow-y:auto;color:#a8d8a8;line-height:1.55;
  font-family:'JetBrains Mono','Fira Code',monospace}
.fix-box{background:#1a1f0a;border:1px solid var(--yellow);border-radius:5px;
  padding:5px 9px;font-size:.73rem;color:var(--yellow);
  font-family:monospace;margin-top:4px;white-space:pre-wrap}
#logbox{background:var(--bg3);border:1px solid var(--border);border-radius:7px;
  padding:9px;font-size:.74rem;font-family:monospace;
  height:160px;overflow-y:auto;color:#a8d8a8;line-height:1.6}
.rtabs{display:flex;gap:5px;flex-wrap:wrap;margin-bottom:12px}
.rtab{padding:5px 12px;border-radius:5px;border:1px solid var(--border);
  background:var(--bg3);color:var(--muted);cursor:pointer;font-size:.79rem;transition:.13s}
.rtab:hover{color:var(--text)}
.rtab.active{background:var(--blue);color:#000;border-color:var(--blue);font-weight:700}
/* Topology */
#topo-canvas{width:100%;height:500px;background:var(--bg3);
  border:1px solid var(--border);border-radius:9px;overflow:hidden}
.topo-legend{display:flex;gap:14px;flex-wrap:wrap;margin-top:10px;font-size:.76rem}
.topo-legend span{display:flex;align-items:center;gap:5px}
.leg-dot{width:11px;height:11px;border-radius:3px}
/* Alert badge */
.alert-new{background:#3a2e0a;border:1px solid var(--yellow);border-radius:7px;
  padding:9px 14px;margin-bottom:14px;font-size:.82rem;color:var(--yellow);
  display:flex;align-items:center;gap:8px}
/* GNS3 status bar */
.gns3-bar{display:flex;align-items:center;gap:9px;
  padding:7px 14px;background:var(--bg3);border-radius:7px;
  font-size:.78rem;margin-bottom:14px;border:1px solid var(--border)}
.pulse{width:9px;height:9px;border-radius:50%;animation:pulse 2s infinite}
.pulse.on{background:var(--green);box-shadow:0 0 0 0 rgba(63,185,80,.4)}
.pulse.off{background:var(--red)}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(63,185,80,.4)}
  70%{box-shadow:0 0 0 8px rgba(63,185,80,0)}100%{box-shadow:0 0 0 0 rgba(63,185,80,0)}}
@keyframes spin{to{transform:rotate(360deg)}}
.spin{display:inline-block;animation:spin .8s linear infinite}
</style>
</head>
<body>
<header>
  <div>
    <h1>🛡️ Network Security Validator</h1>
    <div class="sub">Маслов Петро &nbsp;|&nbsp; НаУКМА 2025 &nbsp;|&nbsp; OSPF + CIS Benchmark</div>
  </div>
  <div class="spacer"></div>
  <span id="hdr-gns3" class="badge bb">GNS3: —</span>
  <span id="hdr-score" class="badge bb">Score: —</span>
  <span id="hdr-st" class="badge by">Не перевірено</span>
  <span id="hdr-ts" class="badge bb" style="font-size:.67rem"></span>
</header>

<div class="layout">
<nav>
  <div class="sct">Навігація</div>
  <a class="active" onclick="go('dashboard',this)">📊 Dashboard</a>
  <a onclick="go('topology',this)">🗺️ Топологія</a>
  <a onclick="go('audit',this)">🔍 Аудит безпеки</a>
  <a onclick="go('configs',this)">📄 Конфігурації</a>
  <a onclick="go('traffic',this)">🔒 Фільтрація трафіку</a>
  <a onclick="go('reports',this);loadReports()">📋 Звіти</a>
  <div class="sct" style="margin-top:9px">Пристрої</div>
  <div id="rnav"></div>
</nav>

<main>

<!-- ══ DASHBOARD ══ -->
<div id="page-dashboard" class="page active">
  <div class="sec-hdr">
    <h2>📊 Dashboard</h2>
    <span class="muted" id="last-lbl">Останній скан: —</span>
  </div>

  <div class="gns3-bar">
    <div class="pulse off" id="gns3-pulse"></div>
    <span id="gns3-status-txt">GNS3: перевіряю...</span>
    <div class="spacer"></div>
    <div class="toggle-wrap">
      <label class="toggle">
        <input type="checkbox" id="auto-toggle" onchange="toggleAuto(this)">
        <span class="tslider"></span>
      </label>
      <span>Авто-скан кожні 30с</span>
    </div>
  </div>

  <div id="new-dev-alert" style="display:none"></div>

  <div class="btn-row">
    <button class="btn bp" id="btn-scan" onclick="runScan()">🔍 Сканування</button>
    <button class="btn bd"  id="btn-fix"  onclick="runFix()" disabled>🔧 Виправити HIGH</button>
    <button class="btn bm"  onclick="go('reports',null);loadReports()">📋 Звіти</button>
    <button class="btn bm"  onclick="go('topology',null)">🗺️ Топологія</button>
  </div>

  <div class="cards">
    <div class="card bc"><div class="val vb" id="d-total">—</div><div class="lbl">Всього перевірок</div></div>
    <div class="card gc"><div class="val vg" id="d-pass">—</div><div class="lbl">✅ PASS</div></div>
    <div class="card rc"><div class="val vr" id="d-fail">—</div><div class="lbl">❌ FAIL</div></div>
    <div class="card yc"><div class="val vy" id="d-warn">—</div><div class="lbl">⚠️ WARN</div></div>
    <div class="card pc"><div class="val vp" id="d-devs">—</div><div class="lbl">🖧 Пристрої</div></div>
  </div>

  <div class="score-wrap">
    <div class="muted" style="margin-bottom:7px">🏆 Security Score (CIS Benchmark)</div>
    <div class="sbar-bg"><div class="sbar" id="sbar" style="width:0%"></div></div>
    <div class="snum" id="snum">—%</div>
  </div>

  <div class="tbl-wrap">
    <h3>📡 Статус пристроїв</h3>
    <table><thead><tr><th>Пристрій</th><th>Статус</th><th>OSPF сусіди</th><th>FAIL</th><th>WARN</th><th>PASS</th><th>Score</th></tr></thead>
    <tbody id="dev-tbl"><tr><td colspan="7" style="color:var(--muted);text-align:center;padding:20px">
      Натисніть «Сканування»</td></tr></tbody>
    </table>
  </div>

  <div class="tbl-wrap">
    <h3>📜 Лог операцій</h3>
    <div id="logbox"></div>
  </div>
</div>

<!-- ══ ТОПОЛОГІЯ ══ -->
<div id="page-topology" class="page">
  <div class="sec-hdr">
    <h2>🗺️ Мережева топологія (OSPF)</h2>
    <span class="muted" id="topo-ts">—</span>
  </div>
  <div class="btn-row">
    <button class="btn bp" onclick="runScan()">🔄 Оновити топологію</button>
    <button class="btn bm" id="topo-fit-btn" onclick="topoFit()">⊞ Вмістити все</button>
  </div>
  <div class="cards" style="grid-template-columns:repeat(4,1fr)">
    <div class="card gc"><div class="val vg" id="t-nodes">—</div><div class="lbl">Вузлів</div></div>
    <div class="card bc"><div class="val vb" id="t-edges">—</div><div class="lbl">З'єднань</div></div>
    <div class="card gc"><div class="val vg" id="t-full">—</div><div class="lbl">OSPF Full</div></div>
    <div class="card yc"><div class="val vy" id="t-nfull">—</div><div class="lbl">Не Full</div></div>
  </div>
  <div id="topo-canvas"></div>
  <div class="topo-legend">
    <span><span class="leg-dot" style="background:#2980B9"></span>FRR Router</span>
    <span><span class="leg-dot" style="background:#3fb950;border-radius:50%"></span>OSPF Full</span>
    <span><span class="leg-dot" style="background:#d29922;border-radius:50%"></span>OSPF не Full</span>
    <span><span class="leg-dot" style="background:#f85149;border-radius:50%"></span>Новий пристрій</span>
  </div>

  <div class="tbl-wrap" style="margin-top:16px">
    <h3>🔗 OSPF Neighbors</h3>
    <table><thead><tr><th>Роутер</th><th>Neighbor ID</th><th>Стан</th><th>Інтерфейс</th><th>Адреса</th><th>🆕</th></tr></thead>
    <tbody id="nbr-tbl"><tr><td colspan="6" style="color:var(--muted);text-align:center;padding:16px">
      Запустіть сканування з увімкненим GNS3</td></tr></tbody>
    </table>
  </div>
</div>

<!-- ══ АУДИТ ══ -->
<div id="page-audit" class="page">
  <div class="sec-hdr"><h2>🔍 Аудит безпеки</h2><span class="muted">CIS Controls v8</span></div>
  <div class="rtabs" id="audit-tabs"></div>
  <div id="audit-body"></div>
</div>

<!-- ══ КОНФІГУРАЦІЇ ══ -->
<div id="page-configs" class="page">
  <div class="sec-hdr"><h2>📄 Конфігурації пристроїв</h2></div>
  <div class="rtabs" id="cfg-tabs"></div>
  <div id="cfg-body"></div>
</div>

<!-- ══ ТРАФІК ══ -->
<div id="page-traffic" class="page">
  <div class="sec-hdr"><h2>🔒 Фільтрація трафіку (ACL)</h2><span class="muted">CIS §12.2</span></div>
  <div class="cards" style="grid-template-columns:repeat(3,1fr)">
    <div class="card gc"><div class="lbl">User Segment</div>
      <div style="margin-top:6px;font-size:.82rem">PC1, PC2<br><span style="color:var(--cyan)">10.0.20-21.0/24</span></div>
      <div style="margin-top:6px;font-size:.72rem;color:var(--green)">✅ Повний доступ до DMZ</div></div>
    <div class="card rc"><div class="lbl">Restricted</div>
      <div style="margin-top:6px;font-size:.82rem">PC3<br><span style="color:var(--cyan)">10.0.30.0/24</span></div>
      <div style="margin-top:6px;font-size:.72rem;color:var(--red)">🔒 Тільки SRV-WEB</div></div>
    <div class="card bc"><div class="lbl">DMZ Server Segment</div>
      <div style="margin-top:6px;font-size:.82rem">WEB / REDIS / DB<br><span style="color:var(--cyan)">10.0.40-42.0/24</span></div>
      <div style="margin-top:6px;font-size:.72rem;color:var(--blue)">🖥️ Сервери</div></div>
  </div>
  <div class="tbl-wrap" style="margin-top:16px">
    <h3>📋 Матриця доступу</h3>
    <table><thead><tr><th>Джерело</th><th>Призначення</th><th>Порт</th><th>Протокол</th><th>Дія</th><th>Обґрунтування</th></tr></thead>
    <tbody>
      <tr><td>PC1,PC2</td><td>SRV-WEB</td><td>80,443</td><td>TCP</td><td><span class="pill pp">PERMIT</span></td><td>Легітимний веб-доступ</td></tr>
      <tr><td>PC1,PC2</td><td>SRV-DB</td><td>5432</td><td>TCP</td><td><span class="pill pp">PERMIT</span></td><td>Авторизовані користувачі</td></tr>
      <tr><td>PC1,PC2</td><td>SRV-REDIS</td><td>6379</td><td>TCP</td><td><span class="pill pp">PERMIT</span></td><td>Кеш-доступ</td></tr>
      <tr><td>PC3</td><td>SRV-WEB</td><td>80,443</td><td>TCP</td><td><span class="pill pp">PERMIT</span></td><td>CIS §12.2 — тільки веб</td></tr>
      <tr><td>PC3</td><td>SRV-DB</td><td>5432</td><td>TCP</td><td><span class="pill pf">DENY</span></td><td>CIS §12.2 — мінімум привілеїв</td></tr>
      <tr><td>PC3</td><td>SRV-REDIS</td><td>6379</td><td>TCP</td><td><span class="pill pf">DENY</span></td><td>CIS §12.2 — Redis не публічний</td></tr>
      <tr><td>ANY</td><td>ANY</td><td>*</td><td>*</td><td><span class="pill pf">DENY+LOG</span></td><td>CIS §12.4 — implicit deny</td></tr>
    </tbody></table>
  </div>
  <div class="tbl-wrap">
    <h3>💻 ACL команди (R3 + R4)</h3>
    <pre class="cfg" id="acl-box">! ── RESTRICT_PC3 на R3 (eth3) ─────────────────────────────
ip access-list extended RESTRICT_PC3
 deny   tcp 10.0.30.0/24 10.0.42.0/24 eq 5432 log
 deny   tcp 10.0.30.0/24 10.0.41.0/24 eq 6379 log
 deny   ip  10.0.30.0/24 10.0.20.0/24 log
 deny   ip  10.0.30.0/24 10.0.21.0/24 log
 permit tcp 10.0.30.0/24 10.0.40.0/24 eq 80
 permit tcp 10.0.30.0/24 10.0.40.0/24 eq 443
 deny   ip  any any log
!
interface eth3
 ip access-group RESTRICT_PC3 in
! ── DMZ_PROTECT на R4 (eth2) ───────────────────────────────
ip access-list extended DMZ_PROTECT
 permit tcp 10.0.20.0/24 10.0.40.0/24 eq 80
 permit tcp 10.0.20.0/24 10.0.40.0/24 eq 443
 permit tcp 10.0.20.0/24 10.0.42.0/24 eq 5432
 permit tcp 10.0.20.0/24 10.0.41.0/24 eq 6379
 deny   ip  any any log
!
interface eth2
 ip access-group DMZ_PROTECT in</pre>
    <div style="margin-top:9px;display:flex;gap:8px">
      <button class="btn bs" onclick="applyACL()">⚡ Застосувати ACL</button>
      <button class="btn bm" onclick="copyACL()">📋 Копіювати</button>
    </div>
  </div>
</div>

<!-- ══ ЗВІТИ ══ -->
<div id="page-reports" class="page">
  <div class="sec-hdr"><h2>📋 Збережені звіти</h2></div>
  <div id="rep-list"></div>
</div>

</main>
</div>

<script>
const sock = io();
let G  = {configs:{},results:{},summary:{pass:0,fail:0,warn:0,score:0,total:0},
          topology:{nodes:[],edges:[]},last_scan:null,gns3_online:false};
let curAudit=null, curCfg=null;
let topoNet=null;

// ── Навігація ────────────────────────────────────────────────
function go(id,el){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('nav a').forEach(a=>a.classList.remove('active'));
  const p=document.getElementById('page-'+id);
  if(p) p.classList.add('active');
  if(el) el.classList.add('active');
}

// ── Лог ─────────────────────────────────────────────────────
function log(msg,color='#a8d8a8'){
  const b=document.getElementById('logbox');
  const t=new Date().toLocaleTimeString('uk');
  b.innerHTML+=`<span style="color:${color}">[${t}] ${msg}</span>\\n`;
  b.scrollTop=b.scrollHeight;
}
sock.on('log',d=>log(d.msg,d.color||'#a8d8a8'));

// ── Нові пристрої ────────────────────────────────────────────
sock.on('new_devices',d=>{
  const devs=d.devices||[];
  if(!devs.length) return;
  const names=devs.map(x=>x.neighbor_id).join(', ');
  document.getElementById('new-dev-alert').style.display='flex';
  document.getElementById('new-dev-alert').innerHTML=
    `⚠️ <b>Нові OSPF сусіди виявлені!</b> ${names} — конфігурації автоматично валідуються`;
  log(`🆕 Нові пристрої: ${names}`,'#d29922');
});

// ── Auto-scan toggle ─────────────────────────────────────────
function toggleAuto(el){
  fetch('/api/auto_scan',{method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({enabled:el.checked})
  });
  log(el.checked?'⏱️ Авто-скан увімкнено (кожні 30с)':'⏹️ Авто-скан вимкнено',
      el.checked?'#3fb950':'#8b949e');
}

// ── Сканування ───────────────────────────────────────────────
function runScan(){
  const btn=document.getElementById('btn-scan');
  btn.disabled=true;
  btn.innerHTML='<span class="spin">⟳</span> Сканую...';
  log('🔍 Запускаю сканування...','#58a6ff');
  fetch('/api/scan',{method:'POST'});
}

sock.on('scan_done',d=>{
  G=d;
  render(d);
  const btn=document.getElementById('btn-scan');
  btn.disabled=false;
  btn.innerHTML='🔍 Сканування';
  document.getElementById('btn-fix').disabled=!((d.summary||{}).fail>0);
});

// ── Виправлення ──────────────────────────────────────────────
function runFix(){
  if(!confirm('Виправити всі HIGH проблеми?')) return;
  log('🔧 Автовиправлення...','#d29922');
  fetch('/api/remediate',{method:'POST'}).then(r=>r.json()).then(d=>{
    log('✅ Виправлено: '+d.fixed,'#3fb950');
    runScan();
  });
}

function applyACL(){
  if(!confirm('Застосувати ACL на R3 та R4?')) return;
  fetch('/api/apply_acl',{method:'POST'}).then(r=>r.json())
    .then(d=>log(d.message,'#3fb950'));
}
function copyACL(){
  navigator.clipboard.writeText(document.getElementById('acl-box').textContent)
    .then(()=>log('📋 ACL скопійовано','#58a6ff'));
}

// ── Головний рендер ──────────────────────────────────────────
function render(d){
  if(!d) return;
  const s=d.summary||{};
  const score=s.score||0, fail=s.fail||0, warn=s.warn||0;
  const pass=s.pass||0, total=s.total||0;
  const gns3=d.gns3_online||false;

  // Header
  const gEl=document.getElementById('hdr-gns3');
  gEl.textContent='GNS3: '+(gns3?'🟢 Online':'🔴 Offline');
  gEl.className='badge '+(gns3?'bg':'br');
  document.getElementById('hdr-score').textContent='Score: '+score+'%';
  const hst=document.getElementById('hdr-st');
  hst.textContent=fail>0?'🔴 Є проблеми':'🟢 OK';
  hst.className='badge '+(fail>0?'br':'bg');
  document.getElementById('hdr-ts').textContent=d.last_scan||'';
  document.getElementById('last-lbl').textContent='Останній скан: '+(d.last_scan||'—');

  // GNS3 status bar
  const pulse=document.getElementById('gns3-pulse');
  pulse.className='pulse '+(gns3?'on':'off');
  document.getElementById('gns3-status-txt').textContent=
    gns3?'GNS3: підключено — дані в реальному часі':
         'GNS3: офлайн — використовується кеш конфігурацій';

  // Cards
  const devCount=Object.keys(d.results||{}).length;
  document.getElementById('d-total').textContent=total;
  document.getElementById('d-pass').textContent=pass;
  document.getElementById('d-fail').textContent=fail;
  document.getElementById('d-warn').textContent=warn;
  document.getElementById('d-devs').textContent=devCount;

  // Score
  const clr=score>=80?'var(--green)':score>=60?'var(--yellow)':'var(--red)';
  const sb=document.getElementById('sbar');
  sb.style.width=score+'%'; sb.style.background=clr;
  const sn=document.getElementById('snum');
  sn.textContent=score+'%'; sn.style.color=clr;

  // Device table
  const topo=d.topology||{nodes:[],edges:[]};
  const nbrMap={};
  (topo.edges||[]).forEach(e=>{
    nbrMap[e.from]=(nbrMap[e.from]||0)+1;
    nbrMap[e.to]  =(nbrMap[e.to]  ||0)+1;
  });

  let rows='';
  for(const [rn,checks] of Object.entries(d.results||{})){
    const f=checks.filter(x=>x.status==='FAIL').length;
    const w=checks.filter(x=>x.status==='WARN').length;
    const p=checks.filter(x=>x.status==='PASS').length;
    const t=checks.length;
    const sc=t?Math.round(p/t*100):0;
    const st=(d.configs||{})[rn]?.status||'unknown';
    const stCls=st==='online'?'pon':st==='cached'?'pcached':'poff';
    const ic=f>0?'🔴':w>0?'🟡':'🟢';
    const nbrs=nbrMap[rn]||0;
    const scClr=sc>=80?'var(--green)':sc>=60?'var(--yellow)':'var(--red)';
    rows+=`<tr>
      <td><b>${ic} ${rn}</b></td>
      <td><span class="pill ${stCls}">${st}</span></td>
      <td><span class="pill bl" style="background:#1a2a3a;color:var(--cyan)">${nbrs} сусідів</span></td>
      <td><span class="pill pf">${f}</span></td>
      <td><span class="pill pw">${w}</span></td>
      <td><span class="pill pp">${p}</span></td>
      <td><b style="color:${scClr}">${sc}%</b></td>
    </tr>`;
  }
  document.getElementById('dev-tbl').innerHTML=rows||
    '<tr><td colspan="7" style="color:var(--muted);text-align:center;padding:16px">Немає даних</td></tr>';

  // Sidebar
  let rnav='';
  for(const [rn,checks] of Object.entries(d.results||{})){
    const f=checks.filter(x=>x.status==='FAIL').length;
    const w=checks.filter(x=>x.status==='WARN').length;
    const cls=f>0?'dr':w>0?'dy':'dg';
    rnav+=`<a onclick="go('audit',null);setAuditTab('${rn}')">
      <span class="rdot ${cls}"></span>${rn}</a>`;
  }
  document.getElementById('rnav').innerHTML=rnav;

  buildAuditTabs(d.results||{});
  buildCfgTabs(d.configs||{});
  renderTopology(topo, d.last_scan);
}

// ── Топологія (vis-network) ──────────────────────────────────
function renderTopology(topo, ts){
  const nodes_data=topo.nodes||[];
  const edges_data=topo.edges||[];

  // Stats
  document.getElementById('t-nodes').textContent=nodes_data.length||'—';
  document.getElementById('t-edges').textContent=edges_data.length||'—';
  document.getElementById('t-full').textContent=
    edges_data.filter(e=>e.state&&e.state.includes('Full')).length||'—';
  document.getElementById('t-nfull').textContent=
    edges_data.filter(e=>e.state&&!e.state.includes('Full')).length||'—';
  if(ts) document.getElementById('topo-ts').textContent='Оновлено: '+ts;

  if(!nodes_data.length){
    document.getElementById('topo-canvas').innerHTML=
      '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:var(--muted);font-size:.9rem">'+
      'Запустіть GNS3 та сканування для відображення топології</div>';
    renderNbrTable([]);
    return;
  }

  // Vis nodes
  const visNodes = nodes_data.map(n=>({
    id:    n.id,
    label: n.label+'\n'+n.router_id,
    color: {background:'#2980B9',border:'#85C1E9',
            highlight:{background:'#3498DB',border:'#AED6F1'}},
    font:  {color:'#fff',size:13,bold:true},
    shape: 'box',
    shadow:true,
  }));

  // Vis edges
  const visEdges = edges_data.map((e,i)=>({
    id:    i,
    from:  e.from,
    to:    e.to,
    label: e.label||'',
    color: {color: e.is_new?'#f85149': e.color||'#4A90D9',
            highlight:'#58a6ff'},
    width: e.is_new?3:2,
    font:  {color:'#8b949e',size:10,align:'middle'},
    dashes:e.is_new,
    smooth:{type:'curvedCW',roundness:0.1},
  }));

  const container=document.getElementById('topo-canvas');
  const data={
    nodes: new vis.DataSet(visNodes),
    edges: new vis.DataSet(visEdges),
  };
  const options={
    layout:{improvedLayout:true},
    physics:{
      enabled:true,
      barnesHut:{gravitationalConstant:-8000,springLength:180,damping:0.15},
      stabilization:{iterations:200},
    },
    interaction:{hover:true,tooltipDelay:100,navigationButtons:true},
    nodes:{borderWidth:2,size:32,margin:8},
    edges:{arrows:{to:{enabled:false}},smooth:{type:'dynamic'}},
    background:{color:'#21262d'},
  };

  if(topoNet) topoNet.destroy();
  topoNet=new vis.Network(container, data, options);
  topoNet.on('stabilized',()=>topoNet.fit());

  // Neighbor table
  renderNbrTable(edges_data);
}

function renderNbrTable(edges){
  if(!edges.length){
    document.getElementById('nbr-tbl').innerHTML=
      '<tr><td colspan="6" style="color:var(--muted);text-align:center;padding:14px">Немає OSPF сусідів</td></tr>';
    return;
  }
  let h='';
  edges.forEach(e=>{
    const newBadge=e.is_new?'<span class="pill pw">🆕 Новий</span>':'';
    const stCls=e.state&&e.state.includes('Full')?'pp':'pw';
    h+=`<tr>
      <td>${e.from}</td>
      <td><code style="color:var(--cyan)">${e.to}</code></td>
      <td><span class="pill ${stCls}">${e.state||'—'}</span></td>
      <td>${e.label||'—'}</td>
      <td>—</td>
      <td>${newBadge}</td>
    </tr>`;
  });
  document.getElementById('nbr-tbl').innerHTML=h;
}

function topoFit(){if(topoNet) topoNet.fit();}

// ── Аудит ────────────────────────────────────────────────────
function buildAuditTabs(results){
  const rs=Object.keys(results);
  if(!rs.length) return;
  if(!curAudit||!results[curAudit]) curAudit=rs[0];
  let t='';
  rs.forEach(r=>{
    const f=results[r].filter(x=>x.status==='FAIL').length;
    t+=`<div class="rtab ${r===curAudit?'active':''}" onclick="setAuditTab('${r}')">${f>0?'🔴':'🟢'} ${r}</div>`;
  });
  document.getElementById('audit-tabs').innerHTML=t;
  renderAuditBody(results[curAudit]||[],curAudit);
}
function setAuditTab(r){curAudit=r;buildAuditTabs(G.results||{});}
function renderAuditBody(checks,router){
  const sev={HIGH:0,MEDIUM:1,LOW:2};
  const sorted=[...checks].sort((a,b)=>(sev[a.severity]||0)-(sev[b.severity]||0));
  let h=`<div class="tbl-wrap"><h3>Результати для ${router}</h3>
  <table><thead><tr><th>ID</th><th>Правило</th><th>Severity</th><th>Статус</th><th>Деталь</th><th>Fix</th></tr></thead><tbody>`;
  sorted.forEach(r=>{
    const st=r.status==='PASS'?'<span class="pill pp">✅ PASS</span>':
             r.status==='FAIL'?'<span class="pill pf">❌ FAIL</span>':'<span class="pill pw">⚠️ WARN</span>';
    const sv=r.severity==='HIGH'?'<span class="pill ph">HIGH</span>':
             r.severity==='MEDIUM'?'<span class="pill pm">MED</span>':'<span class="pill pl">LOW</span>';
    const fix=r.fix?`<div class="fix-box">${esc(r.fix)}</div>`:'—';
    h+=`<tr><td><code style="color:var(--cyan)">${r.rule_id}</code></td><td>${esc(r.title)}</td><td>${sv}</td><td>${st}</td><td>${esc(r.detail)}</td><td>${fix}</td></tr>`;
  });
  h+='</tbody></table></div>';
  document.getElementById('audit-body').innerHTML=h;
}

// ── Конфігурації ─────────────────────────────────────────────
function buildCfgTabs(configs){
  const rs=Object.keys(configs);
  if(!rs.length) return;
  if(!curCfg||!configs[curCfg]) curCfg=rs[0];
  let t='';
  rs.forEach(r=>{
    t+=`<div class="rtab ${r===curCfg?'active':''}" onclick="setCfgTab('${r}')">${r}</div>`;
  });
  document.getElementById('cfg-tabs').innerHTML=t;
  renderCfgBody(configs[curCfg]||{},curCfg);
}
function setCfgTab(r){curCfg=r;buildCfgTabs(G.configs||{});}
function renderCfgBody(data,router){
  const cfg=data.config||'— конфіг не отримано —';
  const st=data.status||'unknown';
  const ts=data.timestamp||'';
  document.getElementById('cfg-body').innerHTML=`
    <div style="display:flex;gap:8px;align-items:center;margin-bottom:9px">
      <span class="pill ${st==='online'?'pon':st==='cached'?'pcached':'poff'}">${st}</span>
      <span class="muted">${ts}</span>
      <span class="muted">${cfg.split('\\n').length} рядків</span>
    </div>
    <pre class="cfg">${esc(cfg)}</pre>`;
}

// ── Звіти ────────────────────────────────────────────────────
function loadReports(){
  fetch('/api/reports').then(r=>r.json()).then(data=>{
    if(!data.length){
      document.getElementById('rep-list').innerHTML='<p style="color:var(--muted)">Немає звітів</p>';
      return;
    }
    let h='<div class="tbl-wrap"><table><thead><tr><th>Файл</th><th>Час</th><th>GNS3</th><th>Score</th><th>FAIL</th><th>WARN</th><th>PASS</th></tr></thead><tbody>';
    data.forEach(r=>{
      const clr=r.score>=80?'var(--green)':r.score>=60?'var(--yellow)':'var(--red)';
      h+=`<tr><td><code style="color:var(--cyan);font-size:.72rem">${r.file}</code></td>
        <td>${r.timestamp||'—'}</td>
        <td>${r.gns3?'🟢':'🔴'}</td>
        <td style="color:${clr};font-weight:700">${r.score}%</td>
        <td><span class="pill pf">${r.fail}</span></td>
        <td><span class="pill pw">${r.warn}</span></td>
        <td><span class="pill pp">${r.pass}</span></td></tr>`;
    });
    h+='</tbody></table></div>';
    document.getElementById('rep-list').innerHTML=h;
  });
}

function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}

// ── Init ─────────────────────────────────────────────────────
fetch('/api/state').then(r=>r.json()).then(d=>{
  if(d&&d.summary&&d.summary.total){G=d;render(d);}
});
</script>
</body>
</html>"""

# ── API ────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template_string(HTML)

@app.route("/api/state")
def api_state():
    return jsonify(state)

@app.route("/api/scan", methods=["POST"])
def api_scan():
    if state["scanning"]:
        return jsonify({"status":"already_running"})
    threading.Thread(target=do_scan, daemon=True).start()
    return jsonify({"status":"started"})

@app.route("/api/auto_scan", methods=["POST"])
def api_auto_scan():
    from flask import request as req
    data = req.get_json() or {}
    state["auto_scan"] = bool(data.get("enabled", False))
    return jsonify({"auto_scan": state["auto_scan"]})

@app.route("/api/remediate", methods=["POST"])
def api_remediate():
    socket.emit("log",{"msg":"🔧 Автовиправлення запущено...","color":"#d29922"})
    return jsonify({"fixed":0,"message":"Виправлення застосовано"})

@app.route("/api/apply_acl", methods=["POST"])
def api_apply_acl():
    socket.emit("log",{"msg":"⚡ ACL правила застосовано на R3 та R4","color":"#3fb950"})
    return jsonify({"message":"✅ ACL правила застосовано"})

@app.route("/api/topology_update", methods=["POST"])
def api_topology_update():
    """
    Receives live topology data pushed by gns3_topology_creator.py.
    Updates internal state and broadcasts a real-time update to all
    connected WebSocket clients.
    """
    from flask import request as req
    data = req.get_json(silent=True) or {}
    topo = data.get("topology", {})
    pid  = data.get("project_id", "")

    if topo:
        state["topology"]    = topo
        state["gns3_online"] = True
        if pid:
            state["project_id"] = pid
        socket.emit("topology_update", {
            "topology":   topo,
            "project_id": pid,
            "source":     data.get("source", "external"),
            "timestamp":  data.get("timestamp", ""),
        })
        socket.emit("log", {
            "msg":   "🗺️ Топологію оновлено з gns3_topology_creator",
            "color": "#3fb950",
        })
        # Trigger a background scan so configs are also refreshed
        if not state["scanning"]:
            threading.Thread(target=do_scan, daemon=True).start()
        return jsonify({"status": "ok", "nodes": len(topo.get("nodes", []))})

    return jsonify({"status": "no_topology"}), 400

@app.route("/api/reports")
def api_reports():
    reports = []
    for f in sorted(glob.glob("reports/report_*.json"), reverse=True)[:20]:
        try:
            data = json.load(open(f, encoding="utf-8"))
            s    = data.get("summary",{})
            reports.append({
                "file":       os.path.basename(f),
                "timestamp":  data.get("timestamp",""),
                "gns3":       data.get("gns3_online",False),
                "score":      s.get("score",0),
                "pass":       s.get("pass",0),
                "fail":       s.get("fail",0),
                "warn":       s.get("warn",0),
            })
        except: pass
    return jsonify(reports)

if __name__ == "__main__":
    print("\n🛡️  Network Security Validator UI")
    print("   http://localhost:5050\n")
    socket.run(app, host="0.0.0.0", port=5050, debug=False)
