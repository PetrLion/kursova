#!/bin/bash
echo "🚀 Запускаємо все..."

# 1. GNS3 server
echo "📡 GNS3 server..."
gns3server --host 127.0.0.1 --port 3080 &
GNS3_PID=$!
sleep 3

# Перевірка (v3 API)
if curl -s http://localhost:3080/v3/version > /dev/null 2>&1; then
    echo "✅ GNS3 server запущено (v3 API)"
else
    echo "⚠️  GNS3 server не відповідає на /v3/version — спробуємо інакше"
    kill $GNS3_PID 2>/dev/null
    python3 -m gns3server --host 127.0.0.1 --port 3080 &
    GNS3_PID=$!
    sleep 3
fi

# 2. Веб-інтерфейс — звільняємо порт 5050 якщо зайнятий
echo "🌐 Запускаємо веб-інтерфейс..."
OLD_PID=$(lsof -ti:5050 2>/dev/null | head -1)
if [ -n "$OLD_PID" ]; then
    kill "$OLD_PID" 2>/dev/null || fuser -k 5050/tcp 2>/dev/null || true
fi
sleep 1
cd ~/kursovichy/security_validator
source ../network_topology/venv/bin/activate 2>/dev/null || true
python3 app.py &
WEB_PID=$!
sleep 2

# 3. Топологія GNS3 v3
echo "🏗  Створюємо топологію через GNS3 v3 API..."
python3 ~/kursovichy/gns3_topology_creator_v3.py \
    --host 127.0.0.1 --port 3080 \
    --flask-url http://localhost:5050 || \
    echo "⚠️  Топологія не створена (GNS3 може бути недоступний)"

echo ""
echo "════════════════════════════════════"
echo "✅ Все запущено!"
echo "   GNS3 API:  http://localhost:3080/v3"
echo "   Web UI:    http://localhost:5050"
echo "════════════════════════════════════"
echo ""
echo "Натисни Ctrl+C щоб зупинити все"

# Чекаємо
wait $WEB_PID
