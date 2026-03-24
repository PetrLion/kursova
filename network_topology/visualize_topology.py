import requests
import networkx as nx
import matplotlib
matplotlib.rcParams['font.family'] = ['DejaVu Sans']
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.patheffects as pe
from matplotlib.patches import FancyBboxPatch
from requests.auth import HTTPBasicAuth

API  = "http://localhost:3080/v2"
PID  = "9f113df3-4dd5-4203-bc25-7d05c3bb83cf"
AUTH = HTTPBasicAuth("admin","QuEipKKmvKI6PS0ZizY00qOTHQj8ku32QWFvnlmtS0JTDQTrPmaOc7k8zfR4qbl1")

nodes_raw = requests.get(f"{API}/projects/{PID}/nodes", auth=AUTH).json()
links_raw = requests.get(f"{API}/projects/{PID}/links", auth=AUTH).json()

NODE_IP = {
    "FRR-Router-1": "1.1.1.1/32",
    "FRR-Router-2": "2.2.2.2/32",
    "FRR-Router-3": "3.3.3.3/32",
    "FRR-Router-4": "4.4.4.4/32",
    "PC1":          "10.0.20.10/24",
    "PC2":          "10.0.21.10/24",
    "PC3":          "10.0.30.10/24",
    "SRV-WEB":      "10.0.40.10/24",
    "SRV-REDIS":    "10.0.41.10/24",
    "SRV-DB":       "10.0.42.10/24",
}

MANUAL_POS = {
    "FRR-Router-1": (8.0,  9.5),
    "FRR-Router-2": (4.0,  7.2),
    "FRR-Router-3": (8.0,  7.2),
    "FRR-Router-4": (13.0, 7.2),
    "PC1":          (2.0,  4.0),
    "PC2":          (5.0,  4.0),
    "PC3":          (8.0,  4.0),
    "SRV-WEB":      (10.5, 4.0),
    "SRV-REDIS":    (13.0, 4.0),
    "SRV-DB":       (15.5, 4.0),
}

def node_style(name):
    n = name.lower()
    if "router" in n: return {"color":"#2980B9","ecolor":"#85C1E9","shape":"s","size":2800}
    elif "web"   in n: return {"color":"#27AE60","ecolor":"#82E0AA","shape":"o","size":2400}
    elif "redis" in n: return {"color":"#C0392B","ecolor":"#F1948A","shape":"o","size":2400}
    elif "db"    in n: return {"color":"#7D3C98","ecolor":"#C39BD3","shape":"o","size":2400}
    elif "pc"    in n: return {"color":"#D68910","ecolor":"#F8C471","shape":"^","size":2200}
    return               {"color":"#566573","ecolor":"#ABB2B9","shape":"o","size":1800}

G = nx.Graph()
nid_name = {}
for n in nodes_raw:
    nid_name[n["node_id"]] = n["name"]
    G.add_node(n["node_id"], name=n["name"])

edge_ports = {}
for lnk in links_raw:
    a,b = lnk["nodes"][0], lnk["nodes"][1]
    G.add_edge(a["node_id"], b["node_id"])
    key = tuple(sorted([a["node_id"], b["node_id"]]))
    edge_ports[key] = f"eth{a['adapter_number']}—eth{b['adapter_number']}"

pos = {nid: MANUAL_POS.get(nid_name[nid], (8.0,1.0)) for nid in G.nodes()}

fig, ax = plt.subplots(figsize=(24, 12))
fig.patch.set_facecolor("#0D1117")
ax.set_facecolor("#0D1117")

# === Zones ===
def zone(ax, x0, y0, x1, y1, color, label):
    rect = FancyBboxPatch((x0,y0), x1-x0, y1-y0,
        boxstyle="round,pad=0.25", linewidth=2.0,
        edgecolor=color, facecolor=color, alpha=0.09, zorder=1)
    ax.add_patch(rect)
    ax.text((x0+x1)/2, y1+0.15, label,
        ha="center", va="bottom", fontsize=9, fontweight="bold",
        color=color, alpha=0.95,
        path_effects=[pe.withStroke(linewidth=2, foreground="#0D1117")])

zone(ax,  1.5,  6.3, 16.5, 10.3, "#2980B9", "Core / Distribution  (OSPF Area 0)")
zone(ax,  0.8,  2.8,  6.8,  5.5, "#D68910", "Access — User Segment  (10.0.20-21.0/24)")
zone(ax,  7.0,  2.8,  9.3,  5.5, "#E74C3C", "Restricted  (10.0.30.0/24)")
zone(ax,  9.5,  2.8, 16.8,  5.5, "#27AE60", "DMZ — Server Segment  (10.0.40-42.0/24)")

# === Edges ===
def edge_style(u, v):
    nu = nid_name[u].lower()
    nv = nid_name[v].lower()
    if "router" in nu and "router" in nv: return "#4A90D9", 2.5, "solid"
    if "pc3"    in nu or "pc3"    in nv:  return "#E74C3C", 2.0, "dashed"
    if "pc"     in nu or "pc"     in nv:  return "#E59866", 1.8, "solid"
    return "#52BE80", 1.8, "solid"

for u,v in G.edges():
    ec, lw, ls = edge_style(u,v)
    nx.draw_networkx_edges(G, pos, edgelist=[(u,v)],
        edge_color=ec, width=lw, alpha=0.85, ax=ax, style=ls)

# === Nodes ===
groups = {}
for nid in G.nodes():
    st = node_style(nid_name[nid])
    key = (st["color"], st["ecolor"], st["shape"], st["size"])
    groups.setdefault(key,[]).append(nid)

for (col,ecol,shape,size), nids in groups.items():
    nx.draw_networkx_nodes(G, pos,
        nodelist=nids,
        node_color=col,
        edgecolors=ecol,
        linewidths=2.5,
        node_shape=shape,
        node_size=size,
        ax=ax)

# === Node labels + IP ===
for nid,(x,y) in pos.items():
    name  = nid_name[nid]
    label = name.replace("FRR-Router-","R")
    ax.text(x, y, label,
        ha="center", va="center",
        fontsize=8.5, fontweight="bold", color="white", zorder=6,
        path_effects=[pe.withStroke(linewidth=3, foreground="#0D1117")])
    ip = NODE_IP.get(name,"")
    if ip:
        ax.text(x, y-0.42, ip,
            ha="center", va="top",
            fontsize=6.8, color="#00E5CC", zorder=6,
            path_effects=[pe.withStroke(linewidth=1.8, foreground="#0D1117")])

# === Port labels (тільки між роутерами) ===
router_ids = {nid for nid,name in nid_name.items() if "router" in name.lower()}
for (u,v) in G.edges():
    if u not in router_ids or v not in router_ids:
        continue
    key = tuple(sorted([u,v]))
    lbl = edge_ports.get(key,"")
    if not lbl: continue
    x0,y0 = pos[u]; x1,y1 = pos[v]
    ax.text((x0+x1)/2, (y0+y1)/2+0.15, lbl,
        ha="center", va="center",
        fontsize=5.8, color="#BDC3C7", zorder=7,
        bbox=dict(boxstyle="round,pad=0.2", fc="#1C2833", ec="none", alpha=0.85))

# === ACL box — під зоною Restricted, не перекриває ===
ax.text(8.15, 2.35,
    "ACL on R3 (eth3):\n"
    "DENY   PC3 → SRV-DB\n"
    "DENY   PC3 → SRV-REDIS\n"
    "PERMIT PC3 → SRV-WEB",
    fontsize=7, color="#F1948A", va="top", ha="center",
    bbox=dict(boxstyle="round,pad=0.5", fc="#1C2833", ec="#E74C3C", lw=1.5, alpha=0.97))

# === Legend ===
legend_items = [
    mpatches.Patch(color="#2980B9", label="FRR Router (OSPF)"),
    mpatches.Patch(color="#D68910", label="PC1 / PC2  — User"),
    mpatches.Patch(color="#E74C3C", label="PC3  — Restricted"),
    mpatches.Patch(color="#27AE60", label="SRV-WEB  (PHP/Apache)"),
    mpatches.Patch(color="#C0392B", label="SRV-REDIS  (Redis 7)"),
    mpatches.Patch(color="#7D3C98", label="SRV-DB  (PostgreSQL 14)"),
]
leg = ax.legend(handles=legend_items,
    loc="upper left", fontsize=9,
    facecolor="#161B22", edgecolor="#30363D",
    labelcolor="white", framealpha=0.97,
    title="Legend", title_fontsize=10)
leg.get_title().set_color("#58A6FF")

ax.set_title(
    "Мережева топологiя  —  Курсова робота\n"
    "Маслов Петро  |  OSPF + Security Zones + ACL  |  НаУКМА 2025",
    color="white", fontsize=14, fontweight="bold", pad=18,
    path_effects=[pe.withStroke(linewidth=3, foreground="#0D1117")])

ax.set_xlim(0.3, 17.5)
ax.set_ylim(1.8, 11.2)
ax.axis("off")
plt.tight_layout()

out = "/home/petr0/kursovichy/network_topology/topology.png"
plt.savefig(out, dpi=160, bbox_inches="tight", facecolor=fig.get_facecolor())
print(f"Saved: {out}")
plt.show()
