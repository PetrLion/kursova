# 🤖 Ansible Автоматизація GNS3 Мережевої Топології

Цей модуль забезпечує повну автоматизацію розгортання та налаштування мережевої топології в GNS3 за допомогою Ansible.

---

## 📋 Зміст

- [Вимоги](#вимоги)
- [Структура директорій](#структура-директорій)
- [Опис топології](#опис-топології)
- [Встановлення](#встановлення)
- [Використання](#використання)
- [Playbooks](#playbooks)
- [Ролі](#ролі)
- [Змінні](#змінні)
- [Інтеграція з Flask](#інтеграція-з-flask)

---

## ⚙️ Вимоги

- **Python** >= 3.10
- **Ansible Core** >= 2.15.0
- **GNS3 Server** >= 3.0.6 (запущений на `http://127.0.0.1:3080`)
- **Flask веб-застосунок** (запущений на `http://localhost:5050`)

Встановлення залежностей:
```bash
pip install -r network_topology/requirements.txt
# або окремо:
pip install ansible-core>=2.15.0 ansible-runner>=2.3.0 requests>=2.31.0
```

---

## 🗂️ Структура директорій

```
network_topology/ansible/
├── inventory.ini                    # Інвентар Ansible
├── group_vars/
│   └── gns3_servers.yml             # Глобальні змінні (вузли, OSPF, ACL)
├── host_vars/
│   └── localhost.yml                # Змінні для локального хосту
├── playbooks/
│   ├── gns3_setup.yml               # Головний orchestration playbook
│   ├── gns3_project.yml             # Створення проекту
│   ├── gns3_nodes.yml               # Розгортання вузлів
│   ├── gns3_links.yml               # Створення з'єднань
│   ├── gns3_configure.yml           # OSPF + ACL конфігурація
│   ├── gns3_start.yml               # Запуск вузлів
│   └── gns3_validate.yml            # Валідація топології
└── roles/
    ├── gns3_project/                # Управління проектом GNS3
    ├── gns3_nodes/                  # Створення вузлів топології
    ├── gns3_links/                  # Створення з'єднань між вузлами
    ├── gns3_ospf/                   # Налаштування OSPF протоколу
    ├── gns3_acl/                    # Застосування ACL правил
    └── gns3_start_nodes/            # Запуск вузлів GNS3
```

---

## 🌐 Опис топології

### Маршрутизатори

| Назва | Router ID  | Роль       | Адреса Loopback |
|-------|------------|------------|-----------------|
| R1    | 1.1.1.1    | Core       | 1.1.1.1/32      |
| R2    | 2.2.2.2    | Office     | 2.2.2.2/32      |
| R3    | 3.3.3.3    | Restricted | 3.3.3.3/32      |
| R4    | 4.4.4.4    | DMZ        | 4.4.4.4/32      |

### IP Адресація

| Мережа              | Призначення          | Пристрої                         |
|---------------------|----------------------|----------------------------------|
| 10.0.10.0/30        | Канал R1-R2          | R1: .1, R2: .2                   |
| 10.0.11.0/30        | Канал R1-R3          | R1: .1, R3: .2                   |
| 10.0.12.0/30        | Канал R1-R4          | R1: .1, R4: .2                   |
| 10.0.20.0/24        | LAN Office (R2)      | R2: .1, PC1: .10, PC2: .11, PC3: .12 |
| 10.0.30.0/24        | LAN Restricted (R3)  | R3: .1, PC4: .10, PC5: .11       |
| 10.0.40.0/24        | LAN DMZ (R4)         | R4: .1, SRV-WEB: .10, SRV-REDIS: .11, SRV-DB: .12 |

### OSPF

- **Area 0** для всіх маршрутизаторів
- Redistribution connected увімкнено на всіх роутерах

### ACL Правила безпеки

| Правило                      | Дія    | Опис                                      |
|------------------------------|--------|-------------------------------------------|
| ALLOW_OFFICE_TO_DMZ_HTTP     | permit | HTTP з офісу до DMZ                       |
| ALLOW_OFFICE_TO_DMZ_HTTPS    | permit | HTTPS з офісу до DMZ                      |
| DENY_RESTRICTED_TO_DMZ       | deny   | Блокування з restricted зони до DMZ       |
| ALLOW_ICMP_ALL               | permit | ICMP між всіма зонами                     |
| DENY_DMZ_TELNET_INTERNAL     | deny   | Блокування Telnet з DMZ до внутрішніх     |
| DENY_DMZ_SSH_INTERNAL        | deny   | Блокування SSH з DMZ до внутрішніх        |

---

## 🚀 Встановлення

1. Переконайтеся що GNS3 сервер запущено:
   ```bash
   curl http://127.0.0.1:3080/v3/version
   ```

2. Перевірте inventory:
   ```bash
   ansible -i network_topology/ansible/inventory.ini all --list-hosts
   ```

3. Перевірте синтаксис playbooks:
   ```bash
   ansible-playbook -i network_topology/ansible/inventory.ini \
     network_topology/ansible/playbooks/gns3_setup.yml --syntax-check
   ```

---

## 📖 Використання

### Через Python менеджер (рекомендовано)

```bash
# Повне розгортання (всі кроки)
python3 gns3_ansible_manager.py --playbook all

# Тільки створення проекту та вузлів
python3 gns3_ansible_manager.py --playbook setup

# Тільки OSPF + ACL конфігурація
python3 gns3_ansible_manager.py --playbook configure

# Запуск вузлів
python3 gns3_ansible_manager.py --playbook start

# Валідація топології
python3 gns3_ansible_manager.py --playbook validate
```

### Напряму через ansible-playbook

```bash
# З директорії network_topology/ansible/
cd network_topology/ansible

# Повне розгортання
ansible-playbook -i inventory.ini playbooks/gns3_setup.yml

# Окремі кроки
ansible-playbook -i inventory.ini playbooks/gns3_project.yml
ansible-playbook -i inventory.ini playbooks/gns3_nodes.yml
ansible-playbook -i inventory.ini playbooks/gns3_links.yml
ansible-playbook -i inventory.ini playbooks/gns3_start.yml
ansible-playbook -i inventory.ini playbooks/gns3_configure.yml
ansible-playbook -i inventory.ini playbooks/gns3_validate.yml
```

### Через start_all.sh з Ansible

```bash
# Запуск з Ansible автоматизацією
./start_all.sh --ansible

# Звичайний запуск (без Ansible)
./start_all.sh
```

---

## 📋 Playbooks

### `gns3_setup.yml` — Головний orchestration playbook
Послідовно викликає всі кроки розгортання:
1. Створення проекту
2. Розгортання вузлів
3. Створення з'єднань
4. Запуск вузлів
5. Налаштування OSPF + ACL
6. Валідація

### `gns3_project.yml` — Управління проектом
- Перевіряє чи існує проект з такою назвою
- Видаляє існуючий проект (якщо є)
- Створює новий проект
- Реєструє `gns3_project_id`

### `gns3_nodes.yml` — Розгортання вузлів
- Створює маршрутизатори (FRR/Quagga Docker контейнери)
- Створює VPCS клієнти
- Створює сервери DMZ (Docker)
- Зберігає node IDs у `/tmp/gns3_node_ids.json`

### `gns3_links.yml` — З'єднання між вузлами
- Отримує актуальні node IDs з API
- Створює всі з'єднання згідно топології

### `gns3_configure.yml` — Конфігурація протоколів
- Генерує OSPF конфіги через Jinja2 шаблони
- Завантажує конфіги у контейнери через GNS3 Files API
- Аналогічно для ACL правил

### `gns3_start.yml` — Запуск вузлів
- Виконує bulk start всіх вузлів проекту
- Чекає ініціалізацію та показує статус

### `gns3_validate.yml` — Валідація
- Перевіряє що проект існує
- Перевіряє кількість вузлів (мінімум 12)
- Перевіряє що маршрутизатори запущені
- Перевіряє кількість з'єднань (мінімум 11)

---

## 🔧 Ролі

### `gns3_project`
**Задачі**: перевірка/видалення/створення проекту GNS3  
**API**: `GET/DELETE/POST /v3/projects`

### `gns3_nodes`
**Задачі**: створення всіх вузлів топології  
**API**: `POST /v3/projects/{id}/nodes`

### `gns3_links`
**Задачі**: створення з'єднань між вузлами  
**API**: `POST /v3/projects/{id}/links`

### `gns3_ospf`
**Задачі**: генерація та завантаження OSPF конфігурацій  
**Шаблон**: `templates/ospf_config.j2` (FRR/Quagga формат)  
**API**: `POST /v3/projects/{id}/nodes/{node_id}/files/etc/frr/frr.conf`

### `gns3_acl`
**Задачі**: генерація та завантаження ACL правил  
**Шаблон**: `templates/acl_config.j2`  
**API**: `POST /v3/projects/{id}/nodes/{node_id}/files/etc/frr/acl.conf`

### `gns3_start_nodes`
**Задачі**: запуск всіх вузлів проекту  
**API**: `POST /v3/projects/{id}/nodes/start`

---

## 📊 Змінні

### Основні (`group_vars/gns3_servers.yml`)

| Змінна              | За замовчуванням                          | Опис                          |
|---------------------|-------------------------------------------|-------------------------------|
| `gns3_url`          | `http://127.0.0.1:3080/v3`                | URL GNS3 API                  |
| `gns3_project_name` | `network-security-topology`               | Назва проекту                 |
| `gns3_auth_enabled` | `false`                                   | Чи увімкнена авторизація      |
| `flask_url`         | `http://localhost:5050`                   | URL Flask застосунку          |
| `log_file`          | `/tmp/ansible_gns3.log`                   | Шлях до лог-файлу             |
| `gns3_routers`      | список                                    | Конфігурація маршрутизаторів  |
| `gns3_vpcs`         | список                                    | Конфігурація VPCS клієнтів    |
| `gns3_servers_list` | список                                    | Конфігурація DMZ серверів     |
| `gns3_links`        | список                                    | З'єднання між вузлами         |
| `gns3_ospf_config`  | словник                                   | OSPF конфігурація             |
| `gns3_acl_rules`    | список                                    | ACL правила безпеки           |

---

## 🔗 Інтеграція з Flask

Python менеджер `gns3_ansible_manager.py` після виконання playbooks:

1. Збирає дані топології з GNS3 API (`/v3/projects/{id}/nodes`, `/v3/projects/{id}/links`)
2. Надсилає JSON до Flask endpoint `POST /api/ansible_update`
3. Flask оновлює стан і сповіщає клієнтів через SocketIO подію `ansible_update`

### Формат payload до Flask:
```json
{
  "timestamp": "2024-01-01T12:00:00",
  "overall_status": "success",
  "gns3_online": true,
  "playbooks_run": [...],
  "deployment": {
    "nodes": [...],
    "links": [...],
    "project_id": "uuid",
    "project_name": "network-security-topology"
  }
}
```

---

## 📝 Логування

Всі операції логуються у файл `/tmp/ansible_gns3.log`:
```bash
# Переглянути лог в реальному часі
tail -f /tmp/ansible_gns3.log

# Переглянути весь лог
cat /tmp/ansible_gns3.log
```

---

## 🛠️ Усунення проблем

**GNS3 не відповідає:**
```bash
curl -v http://127.0.0.1:3080/v3/version
```

**Ansible не знайдено:**
```bash
pip install ansible-core>=2.15.0
which ansible-playbook
```

**Помилка авторизації GNS3 (HTTP 401):**
Встановіть у `group_vars/gns3_servers.yml`:
```yaml
gns3_auth_enabled: true
gns3_username: "ваш_логін"
gns3_password: "ваш_пароль"
```

**Перевірка синтаксису YAML:**
```bash
ansible-playbook --syntax-check -i inventory.ini playbooks/gns3_setup.yml
```
