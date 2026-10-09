#!/usr/bin/env python3
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import base64
import json
import tempfile
import socket
import argparse
from urllib.parse import parse_qs, urlsplit
from config_checks import normalize_host, validate_profile


def ask(prompt, default=""):
    value = input(f"{prompt}" + (f" [{default}]" if default else "") + ": ").strip()
    return value or default


def host(value):
    return normalize_host(value)


def port(value):
    try:
        number = int(value)
    except (ValueError, TypeError):
        raise ValueError("Порт должен быть целым числом от 1 до 65535") from None
    if not 1 <= number <= 65535:
        raise ValueError("Порт должен быть от 1 до 65535")
    return number


COMMON = r'''set -Eeuo pipefail
trap 'echo "Ошибка на VPS: шаг установки/проверки, строка $LINENO (код $?)." >&2' ERR
umask 077
export PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin
[ "$(id -u)" = 0 ] || { echo 'Нужен вход по SSH как root.' >&2; exit 1; }
. /etc/os-release
case "$ID" in ubuntu|debian) ;; *) echo 'Поддерживаются только Debian и Ubuntu.' >&2; exit 1;; esac
command -v systemctl >/dev/null
systemctl list-units >/dev/null
export DEBIAN_FRONTEND=noninteractive
export LC_ALL=C.UTF-8
export NEEDRESTART_MODE=l
'''


def client_name(value):
    if not 1 <= len(value) <= 64 or not re.fullmatch(r"[\w .-]+", value) or not value.strip(" .-_"):
        raise ValueError("Имя клиента: 1–64 символа, буквы, цифры, пробелы, точки, дефисы или подчёркивания")
    return value


def make_script(protocol, vpn_port, endpoint, sni="", name="client"):
    if protocol not in ("amnezia", "vless"):
        raise ValueError("Неизвестный протокол")
    vpn_port, endpoint = port(vpn_port), host(endpoint)
    if protocol == "vless":
        sni = host(sni)
    template = Path(__file__).with_name(f"install_{protocol}.sh").read_text(encoding="utf-8")
    parameters = base64.b64encode(json.dumps({
        "port": vpn_port, "endpoint": endpoint, "sni": sni, "client_name": client_name(name),
    }).encode()).decode()
    template = template.replace("@PORT_SELECTOR@", Path(__file__).with_name("server_port.py").read_text(encoding="utf-8"))
    template = template.replace("@CONFIG_CHECKS@", Path(__file__).with_name("config_checks.py").read_text(encoding="utf-8"))
    if protocol == "vless":
        template = template.replace("@XRAY_BINARY@", Path(__file__).with_name("xray_binary.py").read_text(encoding="utf-8"))
    lock = '\nexec 9>/run/lock/vpsvpn-install.lock\nflock -n 9 || { echo "Другая установка VPN уже выполняется." >&2; exit 1; }\n'
    return COMMON + lock + template.replace("@PARAMETERS@", parameters).replace("@PORT@", str(vpn_port))


def host_key_options(address, ssh_port):
    store = Path(__file__).resolve().parent / ".ssh-known-hosts"
    options = ["-o", f'UserKnownHostsFile="{store}"', "-o", "StrictHostKeyChecking=yes", "-o", "GlobalKnownHostsFile=/dev/null", "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "UpdateHostKeys=no"]
    if store.is_symlink():
        raise RuntimeError("Хранилище SSH-ключей не должно быть символической ссылкой")
    if store.exists():
        lookup = address if ssh_port == 22 else f"[{address}]:{ssh_port}"
        found = subprocess.run(["ssh-keygen", "-F", lookup, "-f", str(store)], capture_output=True, text=True)
        if found.returncode == 0:
            selected = options
        else:
            selected = []
    else:
        selected = []
    probe = subprocess.run(["ssh", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10", "-o", "ControlPath=none", *selected, "-p", str(ssh_port), f"root@{address}", "true"], capture_output=True, text=True, timeout=30)
    if "REMOTE HOST IDENTIFICATION HAS CHANGED" not in probe.stderr:
        return selected
    if not shutil.which("ssh-keyscan") or not shutil.which("ssh-keygen"):
        raise RuntimeError("Для обновления ключа нужны ssh-keyscan и ssh-keygen")
    scan = subprocess.run(["ssh-keyscan", "-T", "10", "-p", str(ssh_port), "-t", "ed25519", address], capture_output=True, text=True, timeout=30)
    keys = [line for line in scan.stdout.splitlines() if line and not line.startswith("#") and len(line.split()) == 3 and line.split()[1] == "ssh-ed25519"]
    if not keys or len({line.split()[2] for line in keys}) != 1:
        raise RuntimeError("Не удалось получить новый ED25519-ключ сервера")
    with tempfile.NamedTemporaryFile(mode="w", suffix=".pub") as public:
        public.write(keys[0] + "\n")
        public.flush()
        fingerprint = subprocess.run(["ssh-keygen", "-lf", public.name], capture_output=True, text=True, check=True).stdout.split()[1]
    print(f"\nSSH-ключ сервера {address}:{ssh_port} изменился. Новый отпечаток:\n{fingerprint}")
    print("Сверьте его через веб-консоль VPS: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub")
    if ask("Для подтверждения вставьте совпавший отпечаток SHA256 (Enter — отмена)") != fingerprint:
        raise RuntimeError("Новый SSH-ключ не подтверждён. Подключение остановлено до установки")
    lookup = address if ssh_port == 22 else f"[{address}]:{ssh_port}"
    with tempfile.TemporaryDirectory(dir=store.parent) as directory:
        staged = Path(directory) / "known_hosts"
        staged.write_text(store.read_text(encoding="utf-8") if store.exists() else "", encoding="utf-8")
        os.chmod(staged, 0o600)
        subprocess.run(["ssh-keygen", "-R", lookup, "-f", str(staged)], capture_output=True, text=True, check=True)
        with staged.open("a", encoding="utf-8") as file:
            file.write('\n' + lookup + ' ssh-ed25519 ' + keys[0].split()[2] + '\n')
        os.replace(staged, store)
    print("Новый ключ сохранён. Продолжаю подключение.")
    return options


def ssh_args(address, ssh_port, key):
    args = ["ssh", "-T", "-o", "StrictHostKeyChecking=ask", "-o", "ConnectTimeout=20", "-o", "ControlPath=none", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3", "-p", str(ssh_port)]
    if key:
        key_path = Path(key).expanduser()
        if not key_path.is_file():
            raise ValueError("SSH-ключ не найден")
        args.extend(["-i", str(key_path)])
    options = host_key_options(address, ssh_port)
    if options:
        args = [arg.replace("StrictHostKeyChecking=ask", "StrictHostKeyChecking=yes") for arg in args]
    return args + options + [f"root@{address}", "bash -s"]


def diagnose():
    if not shutil.which("ssh"):
        raise ValueError("Установите клиент OpenSSH (команда ssh).")
    print("Диагностика AmneziaWG: чтение состояния сервера без изменения настроек.")
    address = host(ask("IP или домен VPS"))
    ssh_port = port(ask("SSH-порт", "22"))
    key = ask("Путь к SSH-ключу (Enter — агент SSH или пароль)")
    script = COMMON + Path(__file__).with_name("diagnose_amnezia.sh").read_text(encoding="utf-8")
    result = subprocess.run(ssh_args(address, ssh_port, key), input=script, text=True, encoding="utf-8")
    if result.returncode:
        raise RuntimeError("Диагностика завершилась ошибкой; см. сообщения выше")


def make_vless_diagnostic(profile):
    endpoint, number = validate_profile("vless", profile)
    link = urlsplit(profile.strip())
    query = parse_qs(link.query, keep_blank_values=True)
    parameters = {"endpoint": endpoint, "port": number, "uuid": link.username,
                  **{key: query[key][0] for key in ("sni", "sid", "pbk", "flow")}}
    encoded = base64.b64encode(json.dumps(parameters).encode()).decode()
    checks = Path(__file__).with_name("config_checks.py").read_text(encoding="utf-8")
    diagnostic = Path(__file__).with_name("diagnose_vless.py").read_text(encoding="utf-8")
    diagnostic = diagnostic.replace("from config_checks import check_key, endpoint\n", "")
    return (COMMON + "\npython3 - <<'VLESSDIAGPY'\n" + checks + "\n" + diagnostic
            + "\nraise SystemExit(diagnose_vless(json.loads(base64.b64decode('" + encoded
            + "'))))\nVLESSDIAGPY\n")


def diagnose_vless_client():
    if not shutil.which("ssh"):
        raise ValueError("Установите клиент OpenSSH (команда ssh).")
    print("Диагностика VLESS: настройки и службы VPS не изменяются.")
    print("Для проверки прямого доступа отключите VPN. Если SSH доступен только через другой VPN, оставьте его включённым.")
    print("TCP-проверка относится к текущему маршруту этого компьютера и не доказывает доступность из другой сети.")
    path = Path(ask("Путь к сохранённому файлу VLESS (.txt)")).expanduser()
    profile = path.read_text(encoding="utf-8")
    endpoint, number = validate_profile("vless", profile)
    script = make_vless_diagnostic(profile)
    address = host(ask("IP или домен VPS для SSH", endpoint))
    ssh_port = port(ask("SSH-порт", "22"))
    key = ask("Путь к SSH-ключу (Enter — агент SSH или пароль)")
    print(f"=== TCP {number} из сети этого компьютера ===", flush=True)
    tcp_ok = False
    try:
        ipv4 = socket.gethostbyname(endpoint)
        with socket.create_connection((ipv4, number), timeout=10):
            pass
        tcp_ok = True
        print("OK: порт доступен. Авторизация Reality этим не проверяется.", flush=True)
    except OSError as error:
        print(f"ОШИБКА: TCP-подключение не установлено ({type(error).__name__}).", flush=True)
    result = subprocess.run(ssh_args(address, ssh_port, key), input=script, text=True, encoding="utf-8")
    if result.returncode == 255:
        raise RuntimeError("SSH недоступен или соединение прервано; серверная диагностика не завершена")
    if result.returncode or not tcp_ok:
        raise RuntimeError("Диагностика выявила ошибки; см. результаты выше. Это не доказывает блокировку сети")
    print("Базовые проверки пройдены. Работа туннеля в Happ ещё не подтверждена.")
    print("Если трафика нет, нужен текст ошибки Happ при подключении. Проверка TCP относится только к сети этого компьютера.")


def main():
    if not shutil.which("ssh"):
        raise ValueError("Установите клиент OpenSSH (команда ssh).")
    print("Установка VPN на Debian/Ubuntu VPS. Требуется SSH-доступ root.")
    print("1 — AmneziaWG\n2 — VLESS + TCP + Reality")
    choice = ask("Выберите протокол", "1")
    if choice not in ("1", "2"):
        raise ValueError("Выберите 1 или 2")
    protocol = "amnezia" if choice == "1" else "vless"
    if choice == "2":
        print("VLESS можно добавить на сервер с AmneziaWG. Занятый TCP-порт будет заменён свободным.")
    address = host(ask("IP или домен VPS"))
    ssh_port = port(ask("SSH-порт", "22"))
    transport = "UDP" if choice == "1" else "TCP"
    vpn_port = port(ask(f"{transport}-порт VPN", "51820" if choice == "1" else "443"))
    if choice == "2" and vpn_port == ssh_port:
        raise ValueError("Выберите VPN-порт, отличный от SSH-порта")
    endpoint = host(ask("Публичный IP/домен для подключения VPN", address))
    if choice == "2" and ":" in endpoint:
        raise ValueError("Для VLESS в этой версии укажите публичный IPv4 или домен с IPv4")
    sni = ""
    if choice == "2":
        sni = host(ask("Домен маскировки Reality (TLS 1.3 / HTTP/2)", "www.microsoft.com"))
        if ":" in sni or re.fullmatch(r"[0-9.]+", sni):
            raise ValueError("Для Reality нужен домен, а не IP")
    name = client_name(ask("Имя клиента", "client"))
    key = ask("Путь к SSH-ключу (Enter — агент SSH или пароль)")
    default_folder = Path(__file__).resolve().parent / "configs"
    folder = Path(ask("Папка для сохранения конфигурации", str(default_folder))).expanduser().resolve()
    file_stem = re.sub(r"\s+", "_", name).strip(" .")
    filename = ask("Имя файла", file_stem + (".conf" if choice == "1" else ".txt"))
    if filename in (".", "..") or "/" in filename or "\\" in filename or any(ord(c) < 32 for c in filename) or len(filename.encode('utf-8')) > 255:
        raise ValueError("Введите имя файла без пути; папка задаётся отдельно")
    output = folder / filename
    if output.exists():
        raise ValueError(f"Файл уже существует: {output}. Выберите другое имя.")
    output.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    saved = False
    try:
        print("SSH спросит пароль и при первом подключении покажет отпечаток сервера.")
        print("Установка пакетов и изменение маршрутизации займут несколько минут.")
        args = ssh_args(address, ssh_port, key)
        script = make_script(protocol, vpn_port, endpoint, sni, name)
        result = subprocess.run(args, input=script, text=True, encoding="utf-8", stdout=subprocess.PIPE)
        if result.returncode:
            if result.returncode == 255:
                raise RuntimeError("Ошибка SSH: подключение не установлено или прервано. Проверьте сообщение SSH выше и состояние VPS перед повторным запуском.")
            raise RuntimeError("Установка не завершена. См. сообщения выше; сервер мог быть частично настроен.")
        try:
            checked_host, checked_port = validate_profile(protocol, result.stdout)
        except ValueError as error:
            raise RuntimeError(f"Проверка конфига не пройдена: {error}") from None
        if checked_host != endpoint:
            raise RuntimeError("Проверка конфига: Endpoint отличается от указанного адреса VPS")
        print("Проверка формата конфига: OK. Проверки службы на VPS: OK.")
        if choice == "1" and checked_port != vpn_port:
            raise RuntimeError("Проверка конфига: UDP-порт отличается от выбранного")
        vpn_port = checked_port
        print("\nГотовая конфигурация:" if choice == "1" else "\nГотовая ссылка подключения:")
        print(result.stdout, end="" if result.stdout.endswith("\n") else "\n", flush=True)
        with os.fdopen(os.dup(fd), "w", encoding="utf-8") as file:
            file.write(result.stdout)
            file.flush()
            os.fsync(file.fileno())
        saved = True
    finally:
        os.close(fd)
        if not saved:
            output.unlink(missing_ok=True)
    print(f"\nСохранено в: {output}")
    if choice == "2":
        try:
            ipv4 = socket.gethostbyname(checked_host)
            with socket.create_connection((ipv4, checked_port), timeout=10):
                pass
            print("Проверка TCP-порта с этого компьютера: OK. Авторизация Reality ещё не проверена.")
        except OSError:
            print(f"Ошибка: TCP {checked_port} недоступен с этого компьютера. Проверьте firewall провайдера и доступность VPS из вашей сети.", file=sys.stderr)
            raise RuntimeError(f"Конфиг сохранён в {output}, но проверка доступности TCP-порта не пройдена") from None
    else:
        print("Доступность UDP и handshake ещё не подтверждены. Импортируйте конфиг и включите VPN, затем запустите --diagnose.")
    print("Импортируйте файл в AmneziaWG." if choice == "1" else "Импортируйте ссылку из файла в клиент с поддержкой VLESS/Reality.")
    print(f"В панели провайдера разрешите входящий {transport} {vpn_port}, если включён внешний firewall.")
    if choice == "1":
        print("IPv6 направлен в туннель и блокируется; интернет через VPN работает по IPv4.")


def cli(argv=None):
    parser = argparse.ArgumentParser(description="Установка VPN и проверка конфигов. Без параметров — установка на VPS.")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--diagnose", action="store_true", help="диагностика AmneziaWG на VPS через SSH")
    modes.add_argument("--diagnose-vless", action="store_true", help="диагностика VLESS на VPS через SSH")
    modes.add_argument("--check", nargs="*", metavar="ПУТЬ", help="офлайн-проверка файлов или папок; без пути — спросить")
    parser.add_argument("--report", metavar="ФАЙЛ", help="сохранить отчёт --check: .json или текст; существующий файл не заменяется")
    args = parser.parse_args(argv)
    if args.report and args.check is None:
        parser.error("--report используется только вместе с --check")
    if args.check is not None:
        from offline_check import check_files
        paths = args.check or [ask("Файл конфига или папка", str(Path(__file__).resolve().parent / "configs"))]
        return check_files(paths, args.report)
    if args.diagnose:
        diagnose()
    elif args.diagnose_vless:
        diagnose_vless_client()
    else:
        main()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(cli())
    except subprocess.SubprocessError as error:
        print(f"Ошибка внешней команды ({type(error).__name__}). Проверьте вывод выше.", file=sys.stderr)
        sys.exit(1)
    except (ValueError, RuntimeError, OSError) as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print("\nОтменено.", file=sys.stderr)
        sys.exit(130)
