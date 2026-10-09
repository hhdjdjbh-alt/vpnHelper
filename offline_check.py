import configparser
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import uuid
from urllib.parse import parse_qs, urlsplit

from config_checks import check_key, endpoint, normalize_host, validate_profile

MAX_BYTES = 256 * 1024
LIMITATION = "Офлайн: сеть, блокировки, служба VPS, соответствие ключей серверу и работа туннеля не проверялись."


def issue(level, code, message, hint):
    return {"level": level, "code": code, "message": message, "hint": hint}


def inspect_profile(text):
    findings = []
    protocol = "unknown"

    def add(code, message, hint, level="error"):
        findings.append(issue(level, code, message, hint))

    def test(code, label, action, hint):
        try:
            if action() is False:
                raise ValueError()
        except (ValueError, KeyError, TypeError, configparser.Error):
            add(code, label, hint)

    def address_warning(address):
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            return
        if not parsed.is_global or parsed.is_multicast:
            add("endpoint.nonpublic", "Endpoint не является обычным публичным IP.",
                "Для подключения через интернет проверьте публичный адрес VPS; локальный адрес допустим в частной сети.", "warning")

    text = text.lstrip("\ufeff").strip()
    if not text:
        add("file.empty", "Файл пуст.", "Выберите сохранённую ссылку VLESS или клиентский .conf AmneziaWG.")
    elif text.lower().startswith("vless:"):
        protocol = "vless"
        if any(c.isspace() or ord(c) < 32 for c in text):
            add("vless.whitespace", "В ссылке есть пробелы или переносы строк.", "Экспортируйте одну полную ссылку в одну строку; пробелы в имени должны быть URL-кодированы.")
        if re.search(r"%(?![0-9a-fA-F]{2})", text):
            add("vless.encoding", "Повреждено URL-кодирование ссылки.", "Скопируйте исходную ссылку целиком, без ручной замены символов.")
        try:
            link = urlsplit(text)
            query = parse_qs(link.query, strict_parsing=True, keep_blank_values=True, max_num_fields=100)
        except ValueError:
            add("vless.parse", "Не удалось разобрать адрес или параметры VLESS.", "Повторно экспортируйте ссылку; ожидается vless://UUID@адрес:порт?параметры.")
        else:
            test("vless.structure", "Неверная структура ссылки VLESS.",
                 lambda: link.scheme == "vless" and bool(link.username) and link.password is None and not link.path and link.netloc.count("@") == 1,
                 "Выберите одну клиентскую ссылку vless:// без пароля или пути после порта.")
            if any(len(values) != 1 for values in query.values()):
                add("vless.duplicates", "В ссылке повторяются параметры.", "Используйте исходную ссылку без склеивания нескольких наборов параметров.")

            def check_uuid():
                value = uuid.UUID(link.username or "")
                return value.int != 0 and str(value) == (link.username or "").lower()

            test("vless.uuid", "UUID клиента отсутствует или повреждён.", check_uuid,
                 "Возьмите UUID из действующего профиля сервера. Новый случайный UUID не подойдёт.")

            def check_endpoint():
                address, _ = endpoint(link.netloc.rsplit("@", 1)[-1])
                address_warning(address)

            test("vless.endpoint", "Неверный адрес или порт VPS.", check_endpoint,
                 "Проверьте адрес и порт 1–65535; IPv6 должен быть заключён в квадратные скобки.")
            for field, expected in (("security", "reality"), ("type", "tcp"), ("encryption", "none"), ("flow", "xtls-rprx-vision")):
                test("vless." + field, "Отсутствует или не подходит параметр " + field + ".",
                     lambda field=field, expected=expected: query.get(field) == [expected],
                     f"Для профилей этого установщика ожидается {field}={expected}. Если это другой вариант VLESS, данная проверка к нему не относится.")
            test("vless.pbk", "Ключ Reality pbk отсутствует или имеет неверный формат.",
                 lambda: check_key(query.get("pbk", [""])[0], "Reality", True),
                 "Повторно экспортируйте публичный ключ из серверного профиля. Не подставляйте приватный ключ.")
            test("vless.sid", "shortId отсутствует или имеет неверный формат.",
                 lambda: "sid" in query and bool(re.fullmatch(r"(?:[0-9a-fA-F]{2}){0,8}", query["sid"][0])),
                 "Нужен sid из серверного профиля: 0–16 шестнадцатеричных символов, чётная длина; пустой допустим только при такой настройке сервера.")

            def check_sni():
                value = normalize_host(query.get("sni", [""])[0])
                try:
                    ipaddress.ip_address(value)
                except ValueError:
                    return True
                return False

            test("vless.sni", "Домен SNI отсутствует или повреждён.", check_sni,
                 "Для профиля этого установщика sni должен совпадать с доменом serverNames в конфиге VPS.")
            fingerprint = query.get("fp", [""])[0]
            test("vless.fp", "Fingerprint отсутствует или непригоден для Reality.",
                 lambda: bool(fingerprint) and fingerprint != "unsafe" and not any(c.isspace() or ord(c) < 32 for c in fingerprint),
                 "Установщик использует fp=chrome; проверьте, что импорт сохранил этот параметр.")
            if fingerprint and fingerprint not in {"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized", "unsafe"}:
                add("vless.fp.unknown", "Fingerprint не входит в список известных этой проверке.", "Проверьте поддержку выбранного fingerprint в версии клиента.", "warning")
            if set(query) - {"security", "type", "encryption", "flow", "pbk", "sid", "sni", "fp", "spx"}:
                add("vless.extra", "Есть дополнительные параметры, которые здесь не проверяются.", "Для расширенных профилей нужна проверка их документации и клиента.", "warning")
    elif "[Interface]" in text or "[Peer]" in text:
        protocol = "amnezia"
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        try:
            parser.read_string(text)
        except configparser.Error:
            add("awg.parse", "Неверный INI-формат или повторяющиеся поля/секции.", "Выберите клиентский .conf с одной секцией Interface и одной Peer, без дубликатов.")
        else:
            test("awg.sections", "Нужны ровно секции Interface и Peer, без DEFAULT.",
                 lambda: not parser.defaults() and set(parser.sections()) == {"Interface", "Peer"},
                 "Выберите клиентский профиль этого установщика; серверные и многопользовательские конфиги не поддерживаются.")
            interface = dict(parser["Interface"]) if parser.has_section("Interface") else {}
            peer = dict(parser["Peer"]) if parser.has_section("Peer") else {}
            for section, field in ((interface, "PrivateKey"), (peer, "PublicKey"), (peer, "PresharedKey")):
                test("awg." + field.lower(), "Поле " + field + " отсутствует или имеет неверный формат.",
                     lambda section=section, field=field: check_key(section.get(field.lower(), ""), field),
                     "Восстановите поле из клиентского профиля сервера; новые случайные ключи не восстановят подключение.")
            test("awg.address", "Неверный Address интерфейса.",
                 lambda: ipaddress.ip_interface(interface.get("address", "")),
                 "Укажите адрес клиента с префиксом, как в выданном .conf.")

            def check_networks():
                networks = [ipaddress.ip_network(value.strip(), strict=False) for value in peer.get("allowedips", "").split(",")]
                if ipaddress.ip_network("0.0.0.0/0") not in networks:
                    add("awg.routes", "Нет маршрута для всего IPv4-трафика.", "Это может быть намеренная раздельная маршрутизация; для всего интернета обычно нужен 0.0.0.0/0.", "warning")

            test("awg.allowedips", "Неверные сети в AllowedIPs.", check_networks,
                 "Проверьте список сетей через запятую, например 0.0.0.0/0, ::/0.")

            def check_endpoint():
                address, _ = endpoint(peer.get("endpoint", ""))
                address_warning(address)

            test("awg.endpoint", "Неверный Endpoint сервера.", check_endpoint, "Укажите публичный адрес VPS и UDP-порт из серверного профиля.")
            if any(field in interface for field in ("preup", "postup", "predown", "postdown")):
                add("awg.hooks", "В клиентском профиле обнаружены команды запуска.", "Используйте выданный клиентский .conf; команды при этой проверке не выполняются.")
            ranges = {"jc": (1, 128), "jmin": (0, 1280), "jmax": (0, 1280), "s1": (0, 1132), "s2": (0, 1188),
                      **{f"h{i}": (5, 4294967295) for i in range(1, 5)}}
            values = {}
            for field, (minimum, maximum) in ranges.items():
                def numeric(field=field, minimum=minimum, maximum=maximum):
                    value = int(interface.get(field, ""))
                    if not minimum <= value <= maximum:
                        return False
                    values[field] = value
                test("awg." + field, "Неверный или отсутствующий параметр " + field.upper() + ".", numeric,
                     f"Для классического профиля этого установщика ожидается целое число {minimum}–{maximum}; значение должно соответствовать серверу.")
            if {"jmin", "jmax"} <= values.keys() and values["jmin"] >= values["jmax"]:
                add("awg.jrange", "Jmin должен быть меньше Jmax.", "Восстановите параметры из исходного клиентского профиля.")
            if {"s1", "s2"} <= values.keys() and values["s1"] + 56 == values["s2"]:
                add("awg.sizes", "Размеры пакетов S1/S2 конфликтуют.", "Проверьте параметры одновременно на сервере и в клиенте.")
            headers = [values[field] for field in ("h1", "h2", "h3", "h4") if field in values]
            if len(headers) != len(set(headers)):
                add("awg.headers", "Значения H1–H4 повторяются.", "Четыре заголовка должны различаться и соответствовать серверным.")
            for section, field, default, minimum, maximum in ((interface, "mtu", "1280", 576, 1500), (peer, "persistentkeepalive", "25", 0, 65535)):
                test("awg." + field, "Неверный числовой параметр " + field + ".",
                     lambda section=section, field=field, default=default, minimum=minimum, maximum=maximum: minimum <= int(section.get(field, default)) <= maximum,
                     f"Для профилей этого установщика допустимо {minimum}–{maximum}.")
            if not interface.get("dns"):
                add("awg.dns.missing", "В профиле не указан DNS.", "Клиент может использовать системный DNS. При неработающих доменах проверьте DNS отдельно.", "warning")
            else:
                test("awg.dns", "Неверный формат DNS.", lambda: [normalize_host(value.strip()) for value in interface["dns"].split(",")],
                     "Проверьте IP-адреса DNS и поисковые домены, разделённые запятыми; URL здесь не подходит.")
            known = set(ranges) | {"privatekey", "address", "mtu", "dns", "preup", "postup", "predown", "postdown"}
            if set(interface) - known or set(peer) - {"publickey", "presharedkey", "endpoint", "allowedips", "persistentkeepalive"}:
                add("awg.extra", "Есть дополнительные поля вне проверяемого классического профиля AWG.", "Возможности AWG 2/3 и расширенные настройки этим режимом не проверяются.", "warning")
    else:
        add("file.unsupported", "Формат не поддерживается этой проверкой.", "Поддерживаются одна ссылка VLESS + TCP + Reality и классический клиентский AmneziaWG .conf; JSON, vpn:// и подписки не поддерживаются.")

    if protocol != "unknown" and not any(item["level"] == "error" for item in findings):
        test("profile.compatibility", "Профиль не прошёл заключительную проверку формата.",
             lambda: validate_profile(protocol, text), "Повторно экспортируйте профиль этого установщика.")
    return {"protocol": protocol, "status": "error" if any(item["level"] == "error" for item in findings) else "warning" if findings else "ok", "findings": findings}


def inspect_file(path):
    try:
        if not stat.S_ISREG(path.stat().st_mode):
            raise ValueError()
        with path.open("rb") as source:
            data = source.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            return file_error("file.large", "Файл больше 256 КиБ.", "Выберите отдельный клиентский профиль, а не архив или подписку.")
        result = inspect_profile(data.decode("utf-8-sig"))
    except UnicodeError:
        return file_error("file.encoding", "Файл не является текстом UTF-8.", "Экспортируйте конфиг как текстовый .txt или .conf в UTF-8.")
    except (OSError, ValueError):
        return file_error("file.read", "Не удалось прочитать обычный файл.", "Проверьте путь, существование файла и права доступа.")
    return result


def file_error(code, message, hint):
    return {"protocol": "unknown", "status": "error", "findings": [issue("error", code, message, hint)]}


def render_report(report):
    lines = ["Офлайн-проверка конфигов VPN", LIMITATION]
    for index, result in enumerate(report["files"], 1):
        lines.append(f"\nФайл {index}: {json.dumps(result['file'], ensure_ascii=True)} — {result['protocol']}")
        if result["status"] == "ok":
            lines.append("OK: ошибок формата не найдено.")
        for item in result["findings"]:
            label = "ОШИБКА" if item["level"] == "error" else "ВНИМАНИЕ"
            lines.extend([f"{label} [{item['code']}]: {item['message']}", "  Что сделать: " + item["hint"]])
    lines.append(f"\nПроверено файлов: {len(report['files'])}. Файлов с ошибками: {sum(item['status'] == 'error' for item in report['files'])}.")
    return "\n".join(lines) + "\n"


def save_report(path, report):
    path = Path(path).expanduser()
    content = json.dumps(report, ensure_ascii=False, indent=2) + "\n" if path.suffix.lower() == ".json" else render_report(report)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise ValueError("Файл отчёта уже существует. Выберите другое имя; существующие файлы не заменяются.") from None
    complete = False
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as target:
            target.write(content)
            target.flush()
            os.fsync(target.fileno())
        complete = True
    finally:
        if not complete:
            path.unlink(missing_ok=True)


def check_files(paths, output=None):
    results, seen = [], set()
    for value in paths:
        path = Path(value).expanduser()
        try:
            files = sorted((item for item in path.iterdir() if not item.name.startswith(".") and item.suffix.lower() in (".conf", ".txt")), key=lambda item: item.name) if path.is_dir() else [path]
        except OSError:
            files = []
        if not files:
            results.append({"file": path.name, **file_error("folder.empty", "Папка недоступна или в ней нет .conf/.txt файлов.", "Укажите отдельный файл или папку с клиентскими профилями; вложенные папки не обходятся.")})
        for item in files:
            identity = os.path.abspath(item)
            if identity not in seen:
                seen.add(identity)
                results.append({"file": item.name, **inspect_file(item)})
    report = {"schema_version": 1, "created_at": datetime.now(timezone.utc).isoformat(), "mode": "offline", "limitation": LIMITATION, "files": results}
    print(render_report(report), end="")
    if output:
        save_report(output, report)
        print("Отчёт сохранён. Он содержит имена файлов, но не значения полей конфигов.")
    return 1 if not results or any(item["status"] == "error" for item in results) else 0
