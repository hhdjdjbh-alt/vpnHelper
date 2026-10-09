import base64
import configparser
import ipaddress
import re
import uuid
from urllib.parse import parse_qs, urlsplit


def normalize_host(value):
    if not isinstance(value, str) or not value or '%' in value or any(c.isspace() or ord(c) < 32 for c in value):
        raise ValueError('Некорректный IP или домен')
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        domain = (value[:-1] if value.endswith('.') else value).lower()
        labels = domain.split('.')
        if len(domain) > 253 or re.fullmatch(r'[0-9.]+', domain) or any(
            not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
            for label in labels
        ):
            raise ValueError('Некорректный IP или домен') from None
        return domain


def check_key(value, label, urlsafe=False):
    try:
        if urlsafe:
            if not re.fullmatch(r'[A-Za-z0-9_-]{43}', value):
                raise ValueError()
            decoded = base64.b64decode(value + '=', altchars=b'-_', validate=True)
        else:
            decoded = base64.b64decode(value, validate=True)
        if len(decoded) != 32 or decoded == bytes(32):
            raise ValueError()
    except (ValueError, TypeError):
        raise ValueError(f'{label}: ключ должен кодировать 32 байта') from None


def endpoint(value):
    try:
        if any(c.isspace() or ord(c) < 32 for c in value):
            raise ValueError()
        parsed = urlsplit('//' + value)
        if parsed.username is not None or parsed.path or parsed.query or parsed.fragment or not parsed.hostname or parsed.port is None or not 1 <= parsed.port <= 65535:
            raise ValueError()
        return normalize_host(parsed.hostname), parsed.port
    except ValueError:
        raise ValueError('Endpoint: неверный адрес или порт') from None


def validate_profile(protocol, text):
    try:
        if protocol not in ('vless', 'amnezia'):
            raise ValueError('Неизвестный протокол')
        if protocol == 'vless':
            if any(ord(c) < 32 for c in text.strip()):
                raise ValueError('Неверный формат ссылки VLESS')
            url = urlsplit(text.strip())
            if url.scheme != 'vless' or not url.username or url.password is not None or url.path or url.netloc.count('@') != 1:
                raise ValueError('Неверный формат ссылки VLESS')
            try:
                identifier = uuid.UUID(url.username)
                if identifier.int == 0 or str(identifier) != url.username.lower():
                    raise ValueError()
            except ValueError:
                raise ValueError('VLESS: неверный UUID клиента') from None
            server, number = endpoint(url.netloc.split('@', 1)[1])
            try:
                query = parse_qs(url.query, strict_parsing=True, keep_blank_values=True)
            except ValueError:
                raise ValueError('VLESS: повреждена строка параметров') from None
            if any(len(values) != 1 for values in query.values()):
                raise ValueError('VLESS: параметры не должны повторяться')
            for field, expected in {'security': 'reality', 'type': 'tcp', 'encryption': 'none', 'flow': 'xtls-rprx-vision'}.items():
                if query.get(field) != [expected]:
                    raise ValueError(f'VLESS: неверный параметр {field}')
            check_key(query.get('pbk', [''])[0], 'Reality pbk', True)
            if 'sid' not in query or not re.fullmatch(r'(?:[0-9a-fA-F]{2}){0,8}', query['sid'][0]):
                raise ValueError('Reality: неверный shortId')
            if not query.get('sni', [''])[0] or not query.get('fp', [''])[0]:
                raise ValueError('Reality: отсутствует SNI или fingerprint')
            if query['fp'][0] == 'unsafe' or any(c.isspace() or ord(c) < 32 for c in query['fp'][0]):
                raise ValueError('Reality: неверный fingerprint')
            sni = normalize_host(query['sni'][0])
            try:
                ipaddress.ip_address(sni)
            except ValueError:
                pass
            else:
                raise ValueError('Reality: SNI должен быть доменом')
            return server, number
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        parser.read_string(text)
        if parser.defaults() or set(parser.sections()) != {'Interface', 'Peer'}:
            raise ValueError('AmneziaWG: нужны секции Interface и Peer')
        interface, peer = parser['Interface'], parser['Peer']
        for section, field in [(interface, 'PrivateKey'), (peer, 'PublicKey'), (peer, 'PresharedKey')]:
            check_key(section.get(field, ''), 'AmneziaWG ' + field)
        try:
            ipaddress.ip_interface(interface['Address'])
            for network in peer['AllowedIPs'].split(','):
                ipaddress.ip_network(network.strip(), strict=False)
        except ValueError:
            raise ValueError('AmneziaWG: неверные Address/AllowedIPs') from None
        if any(key in interface for key in ['preup', 'postup', 'predown', 'postdown']):
            raise ValueError('Клиентский профиль не должен содержать команды запуска')
        try:
            values = {key: int(interface[key]) for key in ['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'H1', 'H2', 'H3', 'H4']}
            if not 576 <= int(interface.get('MTU', '1280')) <= 1500 or not 0 <= int(peer.get('PersistentKeepalive', '25')) <= 65535:
                raise ValueError()
        except ValueError:
            raise ValueError('AmneziaWG: неверные числовые параметры') from None
        if not 1 <= values['Jc'] <= 128 or not 0 <= values['Jmin'] < values['Jmax'] <= 1280:
            raise ValueError('AmneziaWG: неверные Jc/Jmin/Jmax')
        if not 0 <= values['S1'] <= 1132 or not 0 <= values['S2'] <= 1188 or values['S1'] + 56 == values['S2']:
            raise ValueError('AmneziaWG: неверные S1/S2')
        headers = [values[key] for key in ['H1', 'H2', 'H3', 'H4']]
        if len(set(headers)) != 4 or any(not 5 <= h <= 4294967295 for h in headers):
            raise ValueError('AmneziaWG: неверные или повторяющиеся H1–H4')
        return endpoint(peer['Endpoint'])
    except (configparser.Error, KeyError):
        raise ValueError('Конфиг повреждён: отсутствуют обязательные поля или есть дубликаты') from None
