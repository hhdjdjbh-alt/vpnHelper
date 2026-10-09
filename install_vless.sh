apt-get update </dev/null >&2
apt-get install -y python3 curl ca-certificates unzip iproute2 iptables openssl </dev/null >&2
export VPN_PORT
VPN_PORT=$(python3 - @PORT@ <<'PORTPY'
@PORT_SELECTOR@
PORTPY
)
echo "Добавляем VLESS на TCP $VPN_PORT. AmneziaWG продолжает работать отдельно." >&2
python3 - <<'PREFLIGHTPY'
import base64, json, socket, ssl, sys
p = json.loads(base64.b64decode('@PARAMETERS@'))
try:
    socket.getaddrinfo(p['endpoint'], p['port'], socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(['h2'])
    with socket.create_connection((p['sni'], 443), timeout=15) as raw:
        with context.wrap_socket(raw, server_hostname=p['sni']) as tls:
            if tls.selected_alpn_protocol() != 'h2':
                raise ValueError('HTTP/2 не поддерживается')
except (OSError, ValueError):
    raise SystemExit('Ошибка: проверьте IPv4-адрес VPS и домен Reality (доступность, сертификат, TLS 1.3 и HTTP/2).') from None
print('Домен Reality: TLS 1.3 и HTTP/2 доступны.', file=sys.stderr)
PREFLIGHTPY
export XRAY_BIN XRAY_DIR XRAY_CONFIG XRAY_CLIENT XRAY_GROUP
XRAY_BIN=$(python3 - <<'BINARYPY'
@XRAY_BINARY@
BINARYPY
)
XRAY_DIR="/etc/vpsvpn-xray/$VPN_PORT"
XRAY_CONFIG="$XRAY_DIR/config.json"
XRAY_CLIENT="$XRAY_DIR/client.txt"
service="vpsvpn-xray-$VPN_PORT"
firewall="$service-firewall"
for file in "$XRAY_DIR" "/etc/systemd/system/$service.service" "/etc/systemd/system/$firewall.service"; do
    [ ! -e "$file" ] && [ ! -L "$file" ] || { echo "Уже существует $file; выберите другой порт." >&2; exit 1; }
done
[ ! -L /etc/vpsvpn-xray ] || { echo 'Каталог vpsvpn-xray не должен быть ссылкой.' >&2; exit 1; }
getent passwd vpsvpn-xray >/dev/null || useradd --system --user-group --no-create-home --shell /usr/sbin/nologin vpsvpn-xray
[ "$(id -u vpsvpn-xray)" != 0 ] || { echo 'Служебный пользователь не должен иметь UID 0.' >&2; exit 1; }
XRAY_GROUP=$(id -gn vpsvpn-xray)
install -d -m 750 -o root -g "$XRAY_GROUP" /etc/vpsvpn-xray
created_slot=0
committed=0
cleanup() {
    result=$?
    if [ "$result" != 0 ] && [ "$created_slot" = 1 ] && [ "$committed" = 0 ]; then
        echo "Ошибка: отменяю добавление $service. Другие службы Xray не изменялись." >&2
        systemctl disable --now "$service" "$firewall" >&2 2>/dev/null || true
        rm -f -- "/etc/systemd/system/$service.service" "/etc/systemd/system/$firewall.service"
        rm -rf -- "$XRAY_DIR"
        systemctl daemon-reload || true
    fi
}
trap cleanup EXIT
mkdir -m 750 "$XRAY_DIR"
created_slot=1
chown root:"$XRAY_GROUP" "$XRAY_DIR"
python3 - <<'PY'
import base64, grp, json, os, pathlib, re, secrets, subprocess, uuid
from urllib.parse import quote, urlencode
p = json.loads(base64.b64decode('@PARAMETERS@'))
p['port'] = int(os.environ['VPN_PORT'])
keys = subprocess.check_output([os.environ['XRAY_BIN'], 'x25519'], text=True)
def extract(names):
    for name in names:
        match = re.search(r'^' + re.escape(name) + r':\s*([A-Za-z0-9_-]{43})\s*$', keys, re.M)
        if match:
            return match.group(1)
    raise SystemExit('Неизвестный формат вывода xray x25519.')
private = extract(['PrivateKey', 'Private key'])
public = extract(['Password (PublicKey)', 'Password', 'PublicKey', 'Public key'])
identifier, short = str(uuid.uuid4()), secrets.token_hex(8)
config = {'log': {'loglevel': 'warning'}, 'inbounds': [{
    'listen': '0.0.0.0', 'port': p['port'], 'protocol': 'vless',
    'settings': {'clients': [{'id': identifier, 'email': p['client_name'], 'flow': 'xtls-rprx-vision'}], 'decryption': 'none'},
    'streamSettings': {'network': 'tcp', 'security': 'reality', 'realitySettings': {
        'show': False, 'target': p['sni'] + ':443', 'dest': p['sni'] + ':443', 'xver': 0,
        'serverNames': [p['sni']], 'privateKey': private, 'shortIds': [short]}}
}], 'outbounds': [{'protocol': 'freedom', 'tag': 'direct'}]}
path = pathlib.Path(os.environ['XRAY_CONFIG'])
path.write_text(json.dumps(config, indent=2) + '\n', encoding='utf-8')
os.chown(path, 0, grp.getgrnam(os.environ['XRAY_GROUP']).gr_gid)
os.chmod(path, 0o640)
os.chown(path.parent, 0, grp.getgrnam(os.environ['XRAY_GROUP']).gr_gid)
os.chmod(path.parent, 0o750)
query = urlencode({'encryption': 'none', 'security': 'reality', 'sni': p['sni'],
    'fp': 'chrome', 'pbk': public, 'sid': short, 'type': 'tcp', 'flow': 'xtls-rprx-vision', 'spx': '/'})
endpoint = '[' + p['endpoint'] + ']' if ':' in p['endpoint'] else p['endpoint']
label = quote(p['client_name'], safe='')
pathlib.Path(os.environ['XRAY_CLIENT']).write_text(f'vless://{identifier}@{endpoint}:{p["port"]}?{query}#{label}\n', encoding='utf-8')
PY
"$XRAY_BIN" run -test -config "$XRAY_CONFIG" >&2
runuser -u vpsvpn-xray -- "$XRAY_BIN" run -test -config "$XRAY_CONFIG" >&2
cat > "/etc/systemd/system/$firewall.service" <<UNIT
[Unit]
Description=Allow VLESS TCP port (vpsvpn)
Before=$service.service
After=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/iptables -w 10 -I INPUT -p tcp --dport $VPN_PORT -m comment --comment $service -j ACCEPT
ExecStop=/usr/sbin/iptables -w 10 -D INPUT -p tcp --dport $VPN_PORT -m comment --comment $service -j ACCEPT

[Install]
WantedBy=multi-user.target
UNIT
cat > "/etc/systemd/system/$service.service" <<UNIT
[Unit]
Description=VLESS TCP Reality (vpsvpn, port $VPN_PORT)
Wants=network-online.target
Requires=$firewall.service
After=network-online.target $firewall.service

[Service]
User=vpsvpn-xray
Group=$XRAY_GROUP
ExecStart="$XRAY_BIN" run -config $XRAY_CONFIG
Restart=on-failure
RestartSec=3
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT
chmod 644 "/etc/systemd/system/$service.service" "/etc/systemd/system/$firewall.service"
systemctl daemon-reload
systemctl enable --now "$firewall" >&2
systemctl enable --now "$service" >&2
sleep 2
systemctl is-active --quiet "$service"
ss -H -ltn "sport = :$VPN_PORT" | grep -q . || { echo 'Xray не открыл TCP-порт.' >&2; exit 1; }
iptables -w 10 -C INPUT -p tcp --dport "$VPN_PORT" -m comment --comment "$service" -j ACCEPT
python3 - <<'CHECKPY'
@CONFIG_CHECKS@
import json, os, pathlib, subprocess, sys
text = pathlib.Path(os.environ['XRAY_CLIENT']).read_text()
_, port_number = validate_profile('vless', text)
inbound = json.loads(pathlib.Path(os.environ['XRAY_CONFIG']).read_text())['inbounds'][0]
link = urlsplit(text.strip())
q = parse_qs(link.query)
reality = inbound['streamSettings']['realitySettings']
if port_number != inbound['port'] or link.username != inbound['settings']['clients'][0]['id'] or q['sid'][0] not in reality['shortIds'] or q['sni'][0] not in reality['serverNames']:
    raise SystemExit('Ошибка проверки: параметры ссылки VLESS не совпадают с сервером')
private_der = bytes.fromhex('302e020100300506032b656e04220420') + base64.urlsafe_b64decode(reality['privateKey'] + '=')
derived = subprocess.run(['openssl', 'pkey', '-inform', 'DER', '-pubout', '-outform', 'DER'], input=private_der, capture_output=True)
prefix = bytes.fromhex('302a300506032b656e032100')
if derived.returncode or not derived.stdout.startswith(prefix) or len(derived.stdout) != len(prefix) + 32:
    raise SystemExit('Ошибка проверки: не удалось получить открытый ключ Reality')
public = base64.urlsafe_b64encode(derived.stdout[len(prefix):]).decode().rstrip('=')
if q['pbk'][0] != public:
    raise SystemExit('Ошибка проверки: ключ Reality не соответствует ключу сервера')
print('Проверка VLESS: формат, ключ Reality и параметры совпадают.', file=sys.stderr)
CHECKPY
committed=1
echo "VLESS готов: служба $service, TCP $VPN_PORT, копия ссылки $XRAY_CLIENT." >&2
cat "$XRAY_CLIENT"
