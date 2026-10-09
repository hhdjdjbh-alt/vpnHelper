
echo '=== Службы ==='
for service in vpsvpn-awg awg-quick@awg0 awg-quick@wg0; do
    printf '%s: ' "$service"
    systemctl is-active "$service" || true
done
echo '=== UDP-порты ==='
ss -H -lun || true
echo '=== Пересылка IPv4 ==='
sysctl net.ipv4.ip_forward
echo '=== Правила FORWARD и NAT, счётчики ==='
if command -v iptables >/dev/null; then
    iptables -L FORWARD -n -v || true
    iptables -t nat -L POSTROUTING -n -v || true
fi
echo '=== AmneziaWG: рукопожатия и трафик (без ключей) ==='
if command -v awg >/dev/null; then
    for interface in $(awg show interfaces); do
        printf 'Интерфейс: %s, UDP-порт: ' "$interface"
        awg show "$interface" listen-port
        awg show "$interface" latest-handshakes | awk -v now="$(date +%s)" '{if ($2 == 0) print "Peer " NR ": успешного handshake ещё не было"; else print "Peer " NR ": handshake " now-$2 " секунд назад"}'
        awg show "$interface" transfer | awk '{print "Peer " NR ": принято " $2 " байт, отправлено " $3 " байт"}'
    done
fi
if command -v docker >/dev/null && docker info >/dev/null 2>&1; then
    echo '=== Контейнеры Amnezia ==='
    docker ps --format '{{.Names}} {{.Ports}}' | awk 'tolower($0) ~ /amnezia|awg/'
    for id in $(docker ps --filter name=amnezia --format '{{.ID}}'); do
        docker exec "$id" sh -c '
            if command -v awg >/dev/null; then
                for interface in $(awg show interfaces); do
                    echo "Интерфейс контейнера: $interface"
                    awg show "$interface" latest-handshakes | awk -v now="$(date +%s)" '\''{if ($2 == 0) print "Peer " NR ": успешного handshake ещё не было"; else print "Peer " NR ": handshake " now-$2 " секунд назад"}'\''
                    awg show "$interface" transfer | awk '\''{print "Peer " NR ": принято " $2 " байт, отправлено " $3 " байт"}'\''
                done
            fi
        ' || true
    done
fi
echo 'Диагностика завершена. PrivateKey и PresharedKey не выводились.'
