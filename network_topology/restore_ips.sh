#!/bin/bash
echo "Відновлення IP адрес..."

# PC1
PC1=$(docker ps --format '{{.ID}} {{.Names}}' | grep 'PC1' | awk '{print $1}')
docker exec $PC1 ip addr add 10.0.20.10/24 dev eth0 2>/dev/null; true
docker exec $PC1 ip route add default via 10.0.20.1 2>/dev/null; true

# PC2
PC2=$(docker ps --format '{{.ID}} {{.Names}}' | grep 'PC2' | awk '{print $1}')
docker exec $PC2 ip addr add 10.0.21.10/24 dev eth0 2>/dev/null; true
docker exec $PC2 ip route add default via 10.0.21.1 2>/dev/null; true

# PC3
PC3=$(docker ps --format '{{.ID}} {{.Names}}' | grep 'PC3' | awk '{print $1}')
docker exec $PC3 ip addr add 10.0.30.10/24 dev eth0 2>/dev/null; true
docker exec $PC3 ip route add default via 10.0.30.1 2>/dev/null; true

# SRV-WEB
WEB_PID=$(docker inspect --format '{{.State.Pid}}' \
  $(docker ps --format '{{.ID}} {{.Names}}' | grep 'SRV-WEB' | awk '{print $1}'))
sudo nsenter -t $WEB_PID -n -- ip addr add 10.0.40.10/24 dev eth0 2>/dev/null; true
sudo nsenter -t $WEB_PID -n -- ip route add default via 10.0.40.1 2>/dev/null; true

# SRV-REDIS
REDIS_PID=$(docker inspect --format '{{.State.Pid}}' \
  $(docker ps --format '{{.ID}} {{.Names}}' | grep 'SRV-REDIS' | awk '{print $1}'))
sudo nsenter -t $REDIS_PID -n -- ip addr add 10.0.41.10/24 dev eth0 2>/dev/null; true
sudo nsenter -t $REDIS_PID -n -- ip route add default via 10.0.41.1 2>/dev/null; true

# SRV-DB
DB_PID=$(docker inspect --format '{{.State.Pid}}' \
  $(docker ps --format '{{.ID}} {{.Names}}' | grep 'SRV-DB' | awk '{print $1}'))
sudo nsenter -t $DB_PID -n -- ip addr add 10.0.42.10/24 dev eth0 2>/dev/null; true
sudo nsenter -t $DB_PID -n -- ip route add default via 10.0.42.1 2>/dev/null; true

echo "✅ IP відновлено!"
