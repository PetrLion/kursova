with open("visualize_topology.py", "r") as f:
    content = f.read()

# Для R3 зокрема — виводимо IP праворуч
old = '''        if is_router:
            # Роутери — IP зліва від вузла
            ax.text(x - 0.85, y, ip,
                ha="right", va="center",
                fontsize=6.8, color="#00E5CC", zorder=6,
                path_effects=[pe.withStroke(linewidth=2.0, foreground="#0D1117")])'''

new = '''        if is_router:
            # R3 — IP праворуч, інші роутери — зліва
            if "Router-3" in name:
                ax.text(x + 0.85, y, ip,
                    ha="left", va="center",
                    fontsize=6.8, color="#00E5CC", zorder=6,
                    path_effects=[pe.withStroke(linewidth=2.0, foreground="#0D1117")])
            else:
                ax.text(x - 0.85, y, ip,
                    ha="right", va="center",
                    fontsize=6.8, color="#00E5CC", zorder=6,
                    path_effects=[pe.withStroke(linewidth=2.0, foreground="#0D1117")])'''

content = content.replace(old, new)

with open("visualize_topology.py", "w") as f:
    f.write(content)
print("Done")
