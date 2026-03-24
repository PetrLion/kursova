import re

with open("visualize_topology.py", "r") as f:
    content = f.read()

# Замінюємо блок IP labels для роутерів — виводимо збоку
old = '''    ip = NODE_IP.get(name,"")
    if ip:
        # Роутери — IP знизу від вузла з більшим відступом
        y_off = 0.90 if is_router else 0.48
        ax.text(x, y - y_off, ip,
            ha="center", va="top",
            fontsize=7.0, color="#00E5CC", zorder=6,
            path_effects=[pe.withStroke(linewidth=2.0, foreground="#0D1117")])'''

new = '''    ip = NODE_IP.get(name,"")
    if ip:
        if is_router:
            # Роутери — IP зліва від вузла
            ax.text(x - 0.85, y, ip,
                ha="right", va="center",
                fontsize=6.8, color="#00E5CC", zorder=6,
                path_effects=[pe.withStroke(linewidth=2.0, foreground="#0D1117")])
        else:
            # Інші вузли — IP знизу
            ax.text(x, y - 0.55, ip,
                ha="center", va="top",
                fontsize=6.8, color="#00E5CC", zorder=6,
                path_effects=[pe.withStroke(linewidth=2.0, foreground="#0D1117")])'''

content = content.replace(old, new)

with open("visualize_topology.py", "w") as f:
    f.write(content)

print("Done")
