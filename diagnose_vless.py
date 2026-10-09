import base64
import json
from pathlib import Path
import socket
import ssl
import subprocess
from config_checks import check_key, endpoint


def command(args, **kwargs):
    return subprocess.run(args, capture_output=True, timeout=15, **kwargs)


def matching_inbound(config, parameters):
    matches = [item for item in config.get("inbounds", [])
               if str(item.get("port")) == str(parameters["port"])
               and item.get("protocol") == "vless"]
    if len(matches) != 1:
        raise ValueError()
    return matches[0]


def matching_parameters(inbound, parameters):
    stream = inbound["streamSettings"]
    reality = stream["realitySettings"]
    clients = inbound["settings"]["clients"]
    return (stream.get("security") == "reality" and stream.get("network") in ("tcp", "raw")
            and any(client.get("id", "").lower() == parameters["uuid"].lower()
                    and client.get("flow") == parameters["flow"] for client in clients)
            and parameters["sni"] in reality.get("serverNames", [])
            and parameters["sid"].lower().ljust(16, "0") in [sid.lower().ljust(16, "0") for sid in reality.get("shortIds", [])])


def matching_public_key(reality, public):
    private = reality["privateKey"]
    check_key(private, "Reality", True)
    private_der = bytes.fromhex("302e020100300506032b656e04220420") + base64.urlsafe_b64decode(private + "=")
    result = command(["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"], input=private_der)
    prefix = bytes.fromhex("302a300506032b656e032100")
    if result.returncode or not result.stdout.startswith(prefix) or len(result.stdout) != len(prefix) + 32:
        raise ValueError()
    return base64.urlsafe_b64encode(result.stdout[len(prefix):]).decode().rstrip("=") == public


def tls_probe(address, number, sni, reality=False):
    context = ssl.create_default_context()
    if reality:
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(["h2"])
    with socket.create_connection((address, number), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname=sni) as connection:
            return not reality or connection.selected_alpn_protocol() == "h2"


def diagnose_vless(parameters, root=Path("/")):
    failures = []

    def check(label, action):
        try:
            passed = bool(action())
        except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError) as error:
            print(f"ОШИБКА: {label} ({type(error).__name__}; подробности скрыты, чтобы не вывести ключи).", flush=True)
            failures.append(label)
            return False
        print(f"{'OK' if passed else 'ОШИБКА'}: {label}.", flush=True)
        if not passed:
            failures.append(label)
        return passed

    number = int(parameters["port"])
    if not 1 <= number <= 65535:
        raise ValueError("Неверный порт")
    print(f"=== VPS: VLESS TCP {number} ===", flush=True)
    print("Сравнивается сохранённый файл; изменения профиля внутри Happ здесь не видны.")
    candidate = root / f"etc/vpsvpn-xray/{number}/config.json"
    service = f"vpsvpn-xray-{number}"
    if not candidate.exists():
        candidate = next((root / name for name in ("usr/local/etc/xray/config.json", "etc/xray/config.json")
                          if (root / name).is_file()), candidate)
        service = "xray"
    check("служба Xray активна", lambda: command(["systemctl", "is-active", "--quiet", service]).returncode == 0)

    def listening():
        result = command(["ss", "-H", "-ltn", f"sport = :{number}"])
        return result.returncode == 0 and bool(result.stdout.strip())

    check("TCP-порт прослушивается на VPS", listening)
    config = {}

    def read_config():
        config.update(json.loads(candidate.read_text(encoding="utf-8")))
        matching_inbound(config, parameters)
        return True

    if check("найден конфиг VLESS для указанного порта", read_config):
        inbound = matching_inbound(config, parameters)
        check("UUID, flow, SNI и shortId совпадают с серверным файлом",
              lambda: matching_parameters(inbound, parameters))
        check("публичный ключ Reality соответствует приватному ключу сервера",
              lambda: matching_public_key(inbound["streamSettings"]["realitySettings"], parameters["pbk"]))

        def target_probe():
            reality = inbound["streamSettings"]["realitySettings"]
            target = reality.get("target", reality.get("dest", ""))
            address, port_number = endpoint(target)
            return tls_probe(address, port_number, parameters["sni"], reality=True)

        check("сайт Reality доступен с VPS по TLS 1.3 / HTTP2", target_probe)
    check("контрольное TLS-соединение с VPS к example.com:443",
          lambda: tls_probe("example.com", 443, "example.com"))
    print("Проверки TLS выполняются от root, вне туннеля; они не подтверждают работу VLESS.")
    print("Конфиги на диске могут отличаться от загруженных службой. Чужие/Docker-установки автоматически не определяются.")
    print("Ключи, UUID и полная ссылка не выводились. Настройки и службы не изменялись.")
    return 1 if failures else 0
