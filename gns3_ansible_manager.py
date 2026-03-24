#!/usr/bin/env python3
"""
gns3_ansible_manager.py — Менеджер Ansible автоматизації для GNS3 топології.

Запуск:
    python3 gns3_ansible_manager.py --playbook all
    python3 gns3_ansible_manager.py --playbook setup
    python3 gns3_ansible_manager.py --playbook validate
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import requests

# ── Константи ─────────────────────────────────────────────────────────────────
ANSIBLE_DIR = Path(__file__).parent / "network_topology" / "ansible"
INVENTORY = ANSIBLE_DIR / "inventory.ini"
PLAYBOOKS_DIR = ANSIBLE_DIR / "playbooks"
LOG_FILE = "/tmp/ansible_gns3.log"
GNS3_URL = "http://127.0.0.1:3080/v3"
FLASK_URL = "http://localhost:5050"

PLAYBOOK_MAP = {
    "setup":     "gns3_setup.yml",
    "project":   "gns3_project.yml",
    "nodes":     "gns3_nodes.yml",
    "links":     "gns3_links.yml",
    "configure": "gns3_configure.yml",
    "start":     "gns3_start.yml",
    "validate":  "gns3_validate.yml",
}

# ── Налаштування логування ────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(__name__)


# ── Допоміжні функції ─────────────────────────────────────────────────────────

def log_ua(msg: str, level: str = "info") -> None:
    """Логування з українськими повідомленнями."""
    getattr(logger, level)(msg)


def check_gns3_available(auth: bool = False) -> dict:
    """Перевірити доступність GNS3 сервера (спочатку без авторизації, потім з)."""
    log_ua("🔍 Перевіряємо доступність GNS3 сервера...")
    result = {"online": False, "auth_required": False, "version": None}

    try:
        resp = requests.get(f"{GNS3_URL}/version", timeout=5)
        if resp.status_code == 200:
            result["online"] = True
            result["version"] = resp.json().get("version", "невідомо")
            log_ua(f"✅ GNS3 сервер доступний. Версія: {result['version']}")
            return result
        if resp.status_code == 401:
            result["auth_required"] = True
            log_ua("⚠️  GNS3 потребує авторизацію (HTTP 401)", "warning")
    except requests.exceptions.ConnectionError:
        log_ua("❌ GNS3 сервер недоступний — з'єднання відхилено", "error")
    except requests.exceptions.Timeout:
        log_ua("❌ GNS3 сервер не відповідає (timeout)", "error")
    except Exception as exc:
        log_ua(f"❌ Помилка підключення до GNS3: {exc}", "error")

    return result


def collect_gns3_topology(project_name: str = "network-security-topology") -> dict:
    """Зібрати дані топології з GNS3 API."""
    log_ua(f"📊 Збираємо дані топології проекту '{project_name}'...")
    topology = {
        "project_name": project_name,
        "project_id": None,
        "nodes": [],
        "links": [],
        "timestamp": datetime.now().isoformat(),
    }

    try:
        # Отримати список проектів
        resp = requests.get(f"{GNS3_URL}/projects", timeout=10)
        if resp.status_code != 200:
            log_ua(f"⚠️  Не вдалось отримати список проектів (HTTP {resp.status_code})", "warning")
            return topology

        projects = resp.json()
        project = next(
            (p for p in projects if p.get("name") == project_name), None
        )
        if not project:
            log_ua(f"⚠️  Проект '{project_name}' не знайдено в GNS3", "warning")
            return topology

        project_id = project["project_id"]
        topology["project_id"] = project_id
        log_ua(f"✅ Знайдено проект: {project_name} (id: {project_id})")

        # Отримати вузли
        resp_nodes = requests.get(
            f"{GNS3_URL}/projects/{project_id}/nodes", timeout=10
        )
        if resp_nodes.status_code == 200:
            raw_nodes = resp_nodes.json()
            topology["nodes"] = [
                {
                    "id": n["node_id"],
                    "name": n["name"],
                    "type": n.get("node_type", "unknown"),
                    "status": n.get("status", "unknown"),
                    "x": n.get("x", 0),
                    "y": n.get("y", 0),
                }
                for n in raw_nodes
            ]
            log_ua(f"✅ Отримано {len(topology['nodes'])} вузлів")

        # Отримати з'єднання
        resp_links = requests.get(
            f"{GNS3_URL}/projects/{project_id}/links", timeout=10
        )
        if resp_links.status_code == 200:
            raw_links = resp_links.json()
            topology["links"] = [
                {
                    "id": lnk["link_id"],
                    "nodes": [
                        {
                            "node_id": ep.get("node_id"),
                            "adapter": ep.get("adapter_number"),
                            "port": ep.get("port_number"),
                        }
                        for ep in lnk.get("nodes", [])
                    ],
                }
                for lnk in raw_links
            ]
            log_ua(f"✅ Отримано {len(topology['links'])} з'єднань")

    except Exception as exc:
        log_ua(f"❌ Помилка збору даних топології: {exc}", "error")

    return topology


def send_to_flask(data: dict, endpoint: str = "/api/ansible_update") -> bool:
    """Надіслати дані до Flask веб-застосунку."""
    url = f"{FLASK_URL}{endpoint}"
    log_ua(f"📤 Надсилаємо дані до Flask ({url})...")

    try:
        resp = requests.post(
            url,
            json=data,
            timeout=10,
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code == 200:
            log_ua(f"✅ Дані успішно надіслано до Flask. Відповідь: {resp.json()}")
            return True
        log_ua(
            f"⚠️  Flask повернув HTTP {resp.status_code}: {resp.text[:200]}", "warning"
        )
        return False
    except requests.exceptions.ConnectionError:
        log_ua("⚠️  Flask сервер недоступний — пропускаємо надсилання", "warning")
        return False
    except Exception as exc:
        log_ua(f"❌ Помилка надсилання до Flask: {exc}", "error")
        return False


def run_playbook(playbook_name: str, extra_vars: dict | None = None) -> tuple[int, str, str]:
    """Запустити ansible-playbook та повернути (returncode, stdout, stderr)."""
    playbook_path = PLAYBOOKS_DIR / playbook_name

    if not playbook_path.exists():
        log_ua(f"❌ Playbook не знайдено: {playbook_path}", "error")
        return 1, "", f"Playbook не знайдено: {playbook_path}"

    cmd = [
        "ansible-playbook",
        "-i", str(INVENTORY),
        str(playbook_path),
        "-v",
    ]

    if extra_vars:
        cmd += ["--extra-vars", json.dumps(extra_vars)]

    log_ua(f"▶️  Запускаємо playbook: {playbook_name}")
    log_ua(f"   Команда: {' '.join(cmd)}")

    start_time = time.time()

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
            cwd=str(ANSIBLE_DIR),
        )
    except subprocess.TimeoutExpired:
        log_ua(f"❌ Playbook '{playbook_name}' перевищив ліміт часу (600 сек)", "error")
        return 1, "", "Timeout"
    except FileNotFoundError:
        log_ua("❌ ansible-playbook не знайдено. Встановіть ansible-core!", "error")
        return 1, "", "ansible-playbook не встановлено"
    except Exception as exc:
        log_ua(f"❌ Помилка запуску playbook: {exc}", "error")
        return 1, "", str(exc)

    elapsed = round(time.time() - start_time, 1)

    if proc.returncode == 0:
        log_ua(f"✅ Playbook '{playbook_name}' виконано успішно за {elapsed} сек")
    else:
        log_ua(
            f"❌ Playbook '{playbook_name}' завершився з помилкою (код {proc.returncode}) за {elapsed} сек",
            "error",
        )

    # Записати вивід у лог-файл
    with open(LOG_FILE, "a", encoding="utf-8") as lf:
        lf.write(f"\n{'='*60}\n")
        lf.write(f"Playbook: {playbook_name} | {datetime.now().isoformat()}\n")
        lf.write(f"STDOUT:\n{proc.stdout}\n")
        if proc.stderr:
            lf.write(f"STDERR:\n{proc.stderr}\n")
        lf.write(f"{'='*60}\n")

    return proc.returncode, proc.stdout, proc.stderr


def parse_ansible_output(stdout: str) -> dict:
    """Витягти статистику з виводу ansible-playbook."""
    summary = {
        "ok": 0,
        "changed": 0,
        "failed": 0,
        "skipped": 0,
        "unreachable": 0,
    }

    for line in stdout.splitlines():
        if "ok=" in line and "changed=" in line:
            for key in summary:
                try:
                    idx = line.index(f"{key}=")
                    val_start = idx + len(key) + 1
                    val_str = line[val_start:].split()[0]
                    summary[key] = int(val_str)
                except (ValueError, IndexError):
                    pass
            break

    return summary


def run_selected_playbooks(playbook_key: str) -> int:
    """Запустити вибрані playbooks та відправити результати до Flask."""
    log_ua(f"\n{'='*60}")
    log_ua(f"🚀 Ansible GNS3 Manager — запуск: {playbook_key}")
    log_ua(f"{'='*60}")

    # Перевірити доступність GNS3
    gns3_status = check_gns3_available()
    if not gns3_status["online"]:
        log_ua("⚠️  GNS3 недоступний — деякі задачі можуть не виконатись", "warning")

    # Визначити які playbooks запускати
    if playbook_key == "all":
        playbooks_to_run = [
            ("setup",     "gns3_setup.yml"),
        ]
    else:
        if playbook_key not in PLAYBOOK_MAP:
            log_ua(f"❌ Невідомий playbook: '{playbook_key}'. Доступні: {list(PLAYBOOK_MAP.keys()) + ['all']}", "error")
            return 1
        playbooks_to_run = [(playbook_key, PLAYBOOK_MAP[playbook_key])]

    overall_status = "success"
    results = []

    for pb_key, pb_file in playbooks_to_run:
        log_ua(f"\n📋 Виконуємо: {pb_key} ({pb_file})")
        rc, stdout, stderr = run_playbook(pb_file)

        summary = parse_ansible_output(stdout)
        status = "success" if rc == 0 else "failed"
        if rc != 0:
            overall_status = "failed"

        results.append({
            "playbook": pb_key,
            "file": pb_file,
            "returncode": rc,
            "status": status,
            "summary": summary,
        })

    # Зібрати дані топології та надіслати до Flask
    topology = {}
    if gns3_status["online"]:
        topology = collect_gns3_topology()

    flask_payload = {
        "timestamp": datetime.now().isoformat(),
        "overall_status": overall_status,
        "gns3_online": gns3_status["online"],
        "gns3_version": gns3_status.get("version"),
        "playbooks_run": results,
        "topology": topology,
        "deployment": {
            "nodes": topology.get("nodes", []),
            "links": topology.get("links", []),
            "project_id": topology.get("project_id"),
            "project_name": topology.get("project_name"),
        },
    }

    send_to_flask(flask_payload)

    # Підсумок
    log_ua(f"\n{'='*60}")
    log_ua(f"📊 Підсумок виконання:")
    for r in results:
        icon = "✅" if r["status"] == "success" else "❌"
        s = r["summary"]
        log_ua(
            f"  {icon} {r['playbook']}: ok={s['ok']} changed={s['changed']} "
            f"failed={s['failed']} skipped={s['skipped']}"
        )
    log_ua(f"{'='*60}")
    log_ua(f"Загальний статус: {'✅ УСПІХ' if overall_status == 'success' else '❌ ПОМИЛКА'}")

    return 0 if overall_status == "success" else 1


# ── Головна функція ───────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="GNS3 Ansible Manager — автоматизація розгортання мережевої топології",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Приклади використання:
  python3 gns3_ansible_manager.py --playbook all        # Повне розгортання
  python3 gns3_ansible_manager.py --playbook setup      # Тільки setup
  python3 gns3_ansible_manager.py --playbook validate   # Тільки валідація
  python3 gns3_ansible_manager.py --playbook configure  # OSPF + ACL
  python3 gns3_ansible_manager.py --playbook start      # Запуск вузлів
        """,
    )
    parser.add_argument(
        "--playbook",
        choices=list(PLAYBOOK_MAP.keys()) + ["all"],
        default="all",
        help="Який playbook запустити (default: all)",
    )
    parser.add_argument(
        "--gns3-url",
        default=GNS3_URL,
        help=f"URL GNS3 API (default: {GNS3_URL})",
    )
    parser.add_argument(
        "--flask-url",
        default=FLASK_URL,
        help=f"URL Flask застосунку (default: {FLASK_URL})",
    )
    parser.add_argument(
        "--log",
        default=LOG_FILE,
        help=f"Шлях до лог-файлу (default: {LOG_FILE})",
    )

    args = parser.parse_args()

    # Перевизначити глобальні константи якщо передані аргументи
    global GNS3_URL, FLASK_URL, LOG_FILE
    GNS3_URL = args.gns3_url
    FLASK_URL = args.flask_url
    LOG_FILE = args.log

    # Переналаштувати логування якщо змінено log-файл
    for handler in logger.handlers:
        if isinstance(handler, logging.FileHandler):
            handler.baseFilename = LOG_FILE

    log_ua(f"📁 Лог-файл: {LOG_FILE}")
    log_ua(f"📂 Ansible директорія: {ANSIBLE_DIR}")

    if not ANSIBLE_DIR.exists():
        log_ua(f"❌ Ansible директорія не знайдена: {ANSIBLE_DIR}", "error")
        sys.exit(1)

    if not INVENTORY.exists():
        log_ua(f"❌ Inventory файл не знайдено: {INVENTORY}", "error")
        sys.exit(1)

    sys.exit(run_selected_playbooks(args.playbook))


if __name__ == "__main__":
    main()
