[ -c /dev/net/tun ] || { echo 'VPS должен поддерживать /dev/net/tun.' >&2; exit 1; }
for file in /etc/amnezia/amneziawg/awg0.conf /etc/amnezia/amneziawg/client.conf /etc/sysctl.d/90-vpsvpn.conf /etc/systemd/system/vpsvpn-awg.service /usr/local/bin/awg /usr/local/bin/awg-quick /usr/local/bin/amneziawg-go; do
    [ ! -e "$file" ] && [ ! -L "$file" ] || { echo "Уже существует $file; установка остановлена." >&2; exit 1; }
done
apt-get update </dev/null >&2
apt-get install -y python3 ca-certificates git build-essential pkg-config iptables iproute2 </dev/null >&2
if ip link show awg0 >/dev/null 2>&1; then
    echo 'Интерфейс awg0 уже существует.' >&2; exit 1
fi
python3 - @PORT@ udp <<'PORTPY' >&2
@PORT_SELECTOR@
PORTPY
iface=$(ip -4 route show default | awk '/default/ {print $5; exit}')
case "$iface" in ''|*[!a-zA-Z0-9_.:-]*) echo 'Не удалось определить сетевой интерфейс.' >&2; exit 1;; esac
python3 - <<'PY'
import ipaddress, json, subprocess
network = ipaddress.ip_network('10.77.77.0/24')
routes = json.loads(subprocess.check_output(['ip', '-j', '-4', 'route', 'show', 'table', 'all']))
for route in routes:
    destination = route.get('dst', 'default')
    if destination != 'default' and ipaddress.ip_network(destination, strict=False).overlaps(network):
        raise SystemExit('Подсеть 10.77.77.0/24 пересекается с существующим маршрутом.')
PY
build_dir=$(mktemp -d)
trap 'rm -rf -- "$build_dir"' EXIT
python3 - "$build_dir" <<'PY'
import hashlib, json, pathlib, platform, urllib.request
directory = pathlib.Path(__import__('sys').argv[1])
arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
if not arch:
    raise SystemExit('Поддерживаются VPS x86_64 и arm64.')
with urllib.request.urlopen('https://go.dev/dl/?mode=json', timeout=60) as response:
    releases = json.load(response)
release = next(r for r in releases if r['stable'])
asset = next(f for f in release['files'] if f['os'] == 'linux' and f['arch'] == arch and f['kind'] == 'archive')
with urllib.request.urlopen('https://go.dev/dl/' + asset['filename'], timeout=120) as response:
    data = response.read()
if hashlib.sha256(data).hexdigest() != asset['sha256']:
    raise SystemExit('Контрольная сумма Go не совпала.')
(directory / 'go.tar.gz').write_bytes(data)
PY
tar -xzf "$build_dir/go.tar.gz" -C "$build_dir"
export PATH="$build_dir/go/bin:$PATH"
export GOPATH="$build_dir/gopath" GOCACHE="$build_dir/gocache"
git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-go.git "$build_dir/go-source" >&2
git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-tools.git "$build_dir/tools" >&2
mkdir -p /var/lib/vpsvpn
{ git -C "$build_dir/go-source" rev-parse HEAD; git -C "$build_dir/tools" rev-parse HEAD; } > /var/lib/vpsvpn/amnezia-build.txt
(cd "$build_dir/go-source"; go build -o "$build_dir/amneziawg-go" .) >&2
make -C "$build_dir/tools/src" >&2
install -m 755 "$build_dir/amneziawg-go" /usr/local/bin/amneziawg-go
install -m 755 "$build_dir/tools/src/wg" /usr/local/bin/awg
install -m 755 "$build_dir/tools/src/wg-quick/linux.bash" /usr/local/bin/awg-quick
install -d -m 700 /etc/amnezia/amneziawg
python3 - "$iface" <<'PY'
import base64, json, pathlib, secrets, subprocess, sys
p = json.loads(base64.b64decode('@PARAMETERS@'))
def key():
    return subprocess.check_output(['awg', 'genkey'], text=True).strip()
def public(private):
    return subprocess.check_output(['awg', 'pubkey'], input=private + '\n', text=True).strip()
server, client = key(), key()
psk = subprocess.check_output(['awg', 'genpsk'], text=True).strip()
headers = set()
while len(headers) < 4:
    headers.add(5 + secrets.randbelow(2147483642))
params = 'Jc = 5\nJmin = 8\nJmax = 80\nS1 = 64\nS2 = 67\n' + ''.join(f'H{i} = {h}\n' for i, h in enumerate(headers, 1))
iface, port = sys.argv[1], p['port']
tag = '-m comment --comment vpsvpn-awg'
rules = [f'INPUT -p udp --dport {port} {tag} -j ACCEPT',
         f'FORWARD -i %i {tag} -j ACCEPT',
         f'FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED {tag} -j ACCEPT']
up = ' && '.join(f'(iptables -w 10 -C {rule} 2>/dev/null || iptables -w 10 -I {rule})' for rule in rules)
down = '; '.join(f'iptables -w 10 -D {rule} 2>/dev/null || true' for rule in rules)
nat = f'POSTROUTING -s 10.77.77.0/24 -o {iface} {tag} -j MASQUERADE'
ipv6_path = pathlib.Path('/proc/sys/net/ipv6/conf/all/disable_ipv6')
ipv6_enabled = ipv6_path.exists() and ipv6_path.read_text().strip() == '0'
if ':' in p['endpoint'] and not ipv6_enabled:
    raise SystemExit('Ошибка: выбран IPv6 Endpoint, но IPv6 на VPS отключён')
ipv6_rule = f'INPUT -p udp --dport {port} {tag} -j ACCEPT'
ipv6_up = f'\nPostUp = ip6tables -w 10 -C {ipv6_rule} 2>/dev/null || ip6tables -w 10 -I {ipv6_rule}' if ipv6_enabled else ''
ipv6_down = f'\nPostDown = ip6tables -w 10 -D {ipv6_rule} 2>/dev/null || true' if ipv6_enabled else ''
server_config = f'''[Interface]
Address = 10.77.77.1/24
MTU = 1280
ListenPort = {port}
PrivateKey = {server}
{params}PostUp = {up} && (iptables -w 10 -t nat -C {nat} 2>/dev/null || iptables -w 10 -t nat -A {nat}){ipv6_up}
PostDown = {down}; iptables -w 10 -t nat -D {nat} 2>/dev/null || true{ipv6_down}

[Peer]
# Client: {p['client_name']}
PublicKey = {public(client)}
PresharedKey = {psk}
AllowedIPs = 10.77.77.2/32
'''
pathlib.Path('/etc/amnezia/amneziawg/awg0.conf').write_text(server_config, encoding='utf-8')
endpoint = '[' + p['endpoint'] + ']' if ':' in p['endpoint'] else p['endpoint']
client_config = f'''[Interface]
# Client: {p['client_name']}
PrivateKey = {client}
Address = 10.77.77.2/32
MTU = 1280
DNS = 1.1.1.1, 1.0.0.1
{params}
[Peer]
PublicKey = {public(server)}
PresharedKey = {psk}
Endpoint = {endpoint}:{port}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
'''
pathlib.Path('/etc/amnezia/amneziawg/client.conf').write_text(client_config, encoding='utf-8')
PY
printf 'net.ipv4.ip_forward=1\n' > /etc/sysctl.d/90-vpsvpn.conf
sysctl -p /etc/sysctl.d/90-vpsvpn.conf >&2
cat > /etc/systemd/system/vpsvpn-awg.service <<'UNIT'
[Unit]
Description=AmneziaWG VPN (vpsvpn)
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
Environment=PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=/usr/local/bin/awg-quick up awg0
ExecStop=/usr/local/bin/awg-quick down awg0

[Install]
WantedBy=multi-user.target
UNIT
chmod 644 /etc/systemd/system/vpsvpn-awg.service
systemctl daemon-reload
systemctl enable --now vpsvpn-awg >&2
systemctl is-active --quiet vpsvpn-awg
awg show awg0 >/dev/null
python3 - <<'CHECKPY'
@CONFIG_CHECKS@
import pathlib, subprocess, sys
client = pathlib.Path('/etc/amnezia/amneziawg/client.conf').read_text()
validate_profile('amnezia', client)
server = configparser.ConfigParser(interpolation=None, strict=False)
server.read('/etc/amnezia/amneziawg/awg0.conf')
profile = configparser.ConfigParser(interpolation=None)
profile.read_string(client)
for field in ['S1', 'S2', 'H1', 'H2', 'H3', 'H4']:
    if server['Interface'][field] != profile['Interface'][field]:
        raise SystemExit('Ошибка проверки: параметры AWG сервера и клиента различаются')
for private, expected in [(profile['Interface']['PrivateKey'], server['Peer']['PublicKey']), (server['Interface']['PrivateKey'], profile['Peer']['PublicKey'])]:
    actual = subprocess.check_output(['awg', 'pubkey'], input=private + '\n', text=True).strip()
    if actual != expected:
        raise SystemExit('Ошибка проверки: ключи сервера и клиента не соответствуют друг другу')
if server['Peer']['PresharedKey'] != profile['Peer']['PresharedKey']:
    raise SystemExit('Ошибка проверки: PresharedKey сервера и клиента различаются')
print('Проверка AmneziaWG: формат, ключи и параметры совпадают.', file=sys.stderr)
CHECKPY
[ "$(sysctl -n net.ipv4.ip_forward)" = 1 ] || { echo 'Ошибка: пересылка IPv4 отключена.' >&2; exit 1; }
iptables -w 10 -C INPUT -p udp --dport @PORT@ -m comment --comment vpsvpn-awg -j ACCEPT
iptables -w 10 -C FORWARD -i awg0 -m comment --comment vpsvpn-awg -j ACCEPT
iptables -w 10 -C FORWARD -o awg0 -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment vpsvpn-awg -j ACCEPT
iptables -w 10 -t nat -C POSTROUTING -s 10.77.77.0/24 -o "$iface" -m comment --comment vpsvpn-awg -j MASQUERADE
cat /etc/amnezia/amneziawg/client.conf
