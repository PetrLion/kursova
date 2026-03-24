from pyvis.network import Network

ROLE_COLORS = {
    "core":     {"bg": "#e74c3c", "shape": "diamond"},
    "office":   {"bg": "#2ecc71", "shape": "dot"},
    "server":   {"bg": "#3498db", "shape": "square"},
    "attacker": {"bg": "#e67e22", "shape": "triangle"},
    "switch":   {"bg": "#9b59b6", "shape": "dot"},
    "default":  {"bg": "#95a5a6", "shape": "dot"},
}

ROLE_LABELS = {
    "core":     "🔴 Шлюз",
    "office":   "🟢 Офіс",
    "server":   "🔵 Сервер",
    "attacker": "🟠 Зловмисник",
    "switch":   "🟣 Комутатор",
    "default":  "⚪ Пристрій",
}

def build_topology(neighbors, inventory,
                   audit_results=None,
                   output_file="topology.html"):

    net = Network(
        height="750px", width="100%",
        bgcolor="#0d1117",
        font_color="#c9d1d9",
        notebook=False,
        heading="Топологія мережі — Мала організація"
    )
    net.barnes_hut(
        gravity=-8000,
        central_gravity=0.3,
        spring_length=200,
        spring_strength=0.05,
        damping=0.09,
    )

    role_map = {d["name"]: d.get("role", "default") for d in inventory}
    ip_map   = {d["name"]: d.get("host", "")         for d in inventory}

    warn_map = {}
    if audit_results:
        for ar in audit_results:
            warn_map[ar.device_name] = ar.warnings

    node_names = set(d["name"] for d in inventory)
    for nb in neighbors:
        node_names.add(nb.local_device)
        node_names.add(nb.remote_device)

    for name in node_names:
        role    = role_map.get(name, "default")
        style   = ROLE_COLORS.get(role, ROLE_COLORS["default"])
        warns   = warn_map.get(name, [])
        ip      = ip_map.get(name, "")
        rlabel  = ROLE_LABELS.get(role, "")

        border  = "#f1c40f" if warns else style["bg"]
        bwidth  = 5 if warns else 2

        tooltip = f"<b>{name}</b><br>"
        tooltip += f"Роль: {rlabel}<br>"
        tooltip += f"IP: {ip}<br>"
        if warns:
            tooltip += "<br><b>⚠ Вразливості:</b><br>"
            tooltip += "<br>".join(warns)
        else:
            tooltip += "<br>✔ Порушень не виявлено"

        display_label = f"{name}\n{ip}"

        net.add_node(
            name,
            label=display_label,
            title=tooltip,
            color={
                "background": style["bg"],
                "border":     border,
                "highlight":  {"background": "#f1c40f",
                               "border":     "#e67e22"},
            },
            shape=style["shape"],
            borderWidth=bwidth,
            size=35,
            font={"size": 13, "face": "monospace",
                  "color": "#ffffff"},
        )

    added = set()
    for nb in neighbors:
        key = frozenset([
            f"{nb.local_device}:{nb.local_interface}",
            f"{nb.remote_device}:{nb.remote_interface}",
        ])
        if key in added:
            continue
        added.add(key)
        lbl = f"{nb.local_interface} ↔ {nb.remote_interface}"
        net.add_edge(
            nb.local_device,
            nb.remote_device,
            title=lbl,
            label=lbl,
            color={"color": "#58a6ff", "highlight": "#f1c40f"},
            width=2,
            font={"size": 10, "color": "#8b949e"},
            smooth={"type": "curvedCW", "roundness": 0.1},
        )

    net.save_graph(output_file)
    nodes_count = len(node_names)
    edges_count = len(added)
    print(f"[+] Топологію збережено: {output_file}")
    print(f"    Вузлів: {nodes_count}, Лінків: {edges_count}")
