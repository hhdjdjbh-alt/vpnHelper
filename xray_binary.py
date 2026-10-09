import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import urllib.request
import zipfile


def fetch(url):
    request = urllib.request.Request(url, headers={'User-Agent': 'vpsvpn-installer'})
    with urllib.request.urlopen(request, timeout=90) as response:
        return response.read()


def ensure_binary():
    existing = shutil.which('xray')
    destination = Path('/usr/local/bin/xray')
    if existing:
        result = subprocess.run([existing, 'version'], capture_output=True, text=True, timeout=15)
        if result.returncode:
            raise RuntimeError('Установленный Xray не запускается; проверьте его бинарник')
        print('Используется уже установленный Xray.', file=sys.stderr)
        return existing
    if destination.exists() or destination.is_symlink():
        raise RuntimeError('Файл Xray существует, но не исполняется. Исправьте его права/установку')
    arch = {'x86_64': '64', 'aarch64': 'arm64-v8a'}.get(platform.machine())
    if not arch:
        raise RuntimeError('Автоматическая установка Xray поддерживает x86_64 и arm64')
    release = json.loads(fetch('https://api.github.com/repos/XTLS/Xray-core/releases/latest'))
    name = f'Xray-linux-{arch}.zip'
    asset = next((item for item in release['assets'] if item['name'] == name), None)
    if asset is None:
        raise RuntimeError('В официальном релизе отсутствует бинарник для этой архитектуры')
    url = asset['browser_download_url']
    if not url.startswith('https://github.com/XTLS/Xray-core/releases/download/'):
        raise RuntimeError('Неожиданный адрес загрузки Xray')
    print('Загружается официальный Xray, проверяется SHA256.', file=sys.stderr)
    data = fetch(url)
    checksum = fetch(url + '.dgst').decode('ascii')
    match = re.search(r'(?mi)^\s*SHA(?:2-|-)?256\s*=\s*([0-9a-f]{64})\s*$', checksum)
    if not match or hashlib.sha256(data).hexdigest() != match.group(1).lower():
        raise RuntimeError('Контрольная сумма Xray не совпала')
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        binary = archive.read('xray')
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
    complete = False
    try:
        with os.fdopen(os.dup(fd), 'wb') as file:
            file.write(binary)
            file.flush()
            os.fsync(file.fileno())
        result = subprocess.run([str(destination), 'version'], capture_output=True, timeout=15)
        if result.returncode:
            raise RuntimeError('Загруженный Xray не запускается на этом VPS')
        os.fchmod(fd, 0o755)
        complete = True
    finally:
        os.close(fd)
        if not complete:
            destination.unlink(missing_ok=True)
    return str(destination)


if __name__ == '__main__':
    try:
        print(ensure_binary())
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        print(f'Ошибка подготовки Xray: {error}', file=sys.stderr)
        sys.exit(1)
