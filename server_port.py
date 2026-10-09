import json
import shutil
import socket
import subprocess
import sys
from pathlib import Path


def docker_ports(transport='tcp'):
    if not shutil.which('docker'):
        return set()
    ids = subprocess.check_output(['docker', 'ps', '-q'], text=True, timeout=20).split()
    if not ids:
        return set()
    containers = json.loads(subprocess.check_output(['docker', 'inspect', *ids], text=True, timeout=20))
    ports = set()
    for container in containers:
        for mapping in [container.get('HostConfig', {}).get('PortBindings'), container.get('NetworkSettings', {}).get('Ports')]:
            for key, bindings in (mapping or {}).items():
                if key.endswith('/' + transport):
                    for binding in bindings or []:
                        if binding.get('HostPort'):
                            ports.add(int(binding['HostPort']))
    return ports


def docker_tcp_ports():
    return docker_ports('tcp')


def available(number, transport='tcp'):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM if transport == 'tcp' else socket.SOCK_DGRAM) as sock:
            sock.bind(('0.0.0.0', number))
        return True
    except OSError:
        return False


def select_port(requested, reserved, check=available):
    for number in dict.fromkeys([requested, 443, 8443, 2053, 2083, 2087, 2096]):
        if number not in reserved and check(number):
            return number
    raise RuntimeError('Нет свободного TCP-порта среди предложенных. Укажите другой порт.')


def configured_xray_ports():
    directory = Path('/etc/vpsvpn-xray')
    if not directory.is_dir():
        return set()
    return {int(path.name) for path in directory.iterdir() if path.name.isdigit() and 1 <= int(path.name) <= 65535}


if __name__ == '__main__':
    requested = int(sys.argv[1])
    transport = sys.argv[2] if len(sys.argv) > 2 else 'tcp'
    try:
        reserved = docker_ports(transport)
        if transport == 'tcp':
            reserved.update(configured_xray_ports())
        if transport == 'udp':
            if requested in reserved or not available(requested, 'udp'):
                raise RuntimeError('UDP-порт занят службой или контейнером')
            chosen = requested
        else:
            chosen = select_port(requested, reserved)
    except (RuntimeError, subprocess.SubprocessError, ValueError) as error:
        raise SystemExit(f'Не удалось проверить свободные порты ({type(error).__name__}). Проверьте Docker и выбранный порт.')
    if chosen != requested:
        print(f'TCP {requested} занят. Для VLESS выбран TCP {chosen}; существующая служба сохранена.', file=sys.stderr)
    print(chosen)
