#!/bin/bash
echo "🚀 Запускаємо все..."

# Прапор --ansible для опціонального запуску Ansible автоматизації
RUN_ANSIBLE=false
for arg in "$@"; do
    if [ "$arg" = "--ansible" ]; then
        RUN_ANSIBLE=true
    fi
done

# 1. GNS3 server
echo "📡 GNS3 server..."
gns3server --host 127.0.0.1 --port 3080 &
GNS3_PID=$!
sleep 3

# Перевірка
if curl -s http://localhost:3080/v2/version > /dev/null 2>&1; then
    echo "✅ GNS3 server запущено"
else
    echo "⚠️  GNS3 server не відповідає — спробуємо інакше"
    pkill -f gns3server 2>/dev/null
    python3 -m gns3server --host 127.0.0.1 --port 3080 &
    sleep 3
fi

# 2. Відкриваємо проект
echo "📂 Відкриваємо GNS3 проект..."
curl -s -X POST \
  "http://localhost:3080/v2/projects/9f113df3-4dd5-4203-bc25-7d05c3bb83cf/open" \
  -u "admin:QuEipKKmvKI6PS0ZizY00qOTHQj8ku32QWFvnlmtS0JTDQTrPmaOc7k8zfR4qbl1" \
  -H "Content-Type: application/json" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    print('✅ Проект:', d.get('name','?'), '| Status:', d.get('status','?'))
except:
    print('⚠️  Відповідь:', sys.stdin.read()[:200])
" 2>/dev/null || echo "⚠️  Не вдалось відкрити проект"

# 3. Стартуємо всі вузли
echo "▶️  Запускаємо вузли..."
curl -s -X POST \
  "http://localhost:3080/v2/projects/9f113df3-4dd5-4203-bc25-7d05c3bb83cf/nodes/start" \
  -u "admin:QuEipKKmvKI6PS0ZizY00qOTHQj8ku32QWFvnlmtS0JTDQTrPmaOc7k8zfR4qbl1" \
  -H "Content-Type: application/json" -d '{}' > /dev/null 2>&1
echo "✅ Вузли запущені"

sleep 2

# 4. Ansible автоматизація (опціонально, якщо передано --ansible)
if [ "$RUN_ANSIBLE" = true ]; then
    echo ""
    echo "🤖 Запускаємо Ansible автоматизацію GNS3 топології..."
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    if [ -f "$SCRIPT_DIR/gns3_ansible_manager.py" ]; then
        python3 "$SCRIPT_DIR/gns3_ansible_manager.py" --playbook all
        ANSIBLE_RC=$?
        if [ $ANSIBLE_RC -eq 0 ]; then
            echo "✅ Ansible автоматизація завершена успішно"
        else
            echo "⚠️  Ansible завершився з помилкою (код $ANSIBLE_RC) — продовжуємо"
        fi
    else
        echo "⚠️  gns3_ansible_manager.py не знайдено — пропускаємо Ansible"
    fi
fi

# 5. Веб-інтерфейс
echo "🌐 Запускаємо веб-інтерфейс..."
sudo fuser -k 5050/tcp 2>/dev/null
sleep 1
cd ~/kursovichy/security_validator
source ../network_topology/venv/bin/activate
python3 app.py &
WEB_PID=$!

sleep 2
echo ""
echo "════════════════════════════════════"
echo "✅ Все запущено!"
echo "   GNS3 API:  http://localhost:3080"
echo "   Web UI:    http://localhost:5050"
if [ "$RUN_ANSIBLE" = true ]; then
    echo "   Ansible:   завершено (лог: /tmp/ansible_gns3.log)"
fi
echo "════════════════════════════════════"
echo ""
echo "Натисни Ctrl+C щоб зупинити все"
echo "Підказка: ./start_all.sh --ansible   щоб запустити з Ansible автоматизацією"

# Чекаємо
wait $WEB_PID
