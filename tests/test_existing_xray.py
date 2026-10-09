import contextlib
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import server_port
import xray_binary


class ExistingXrayTests(unittest.TestCase):
    def test_installed_binary_reused_without_download(self):
        with patch('xray_binary.shutil.which', return_value='/usr/local/bin/xray'), patch('xray_binary.subprocess.run', return_value=subprocess.CompletedProcess([], 0, 'Xray 25.1', '')) as run, patch('xray_binary.fetch') as fetch, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(xray_binary.ensure_binary(), '/usr/local/bin/xray')
            run.assert_called_once()
            fetch.assert_not_called()

    def test_broken_existing_binary_is_not_overwritten(self):
        with patch('xray_binary.shutil.which', return_value='/usr/local/bin/xray'), patch('xray_binary.subprocess.run', return_value=subprocess.CompletedProcess([], 1, '', 'error')), patch('xray_binary.fetch') as fetch:
            with self.assertRaises(RuntimeError):
                xray_binary.ensure_binary()
            fetch.assert_not_called()

    def download(self, checksum_ok=True, version_ok=True):
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w') as archive:
            archive.writestr('xray', b'test binary')
            archive.writestr('../untrusted', b'never extracted')
        digest = hashlib.sha256(data.getvalue()).hexdigest() if checksum_ok else '0' * 64
        release = {'assets': [{'name': 'Xray-linux-64.zip', 'browser_download_url': 'https://github.com/XTLS/Xray-core/releases/download/vTEST/Xray-linux-64.zip'}]}
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / 'xray'
            with patch('xray_binary.Path', return_value=destination), patch('xray_binary.shutil.which', return_value=None), patch('xray_binary.platform.machine', return_value='x86_64'), patch('xray_binary.fetch', side_effect=[json.dumps(release).encode(), data.getvalue(), f'SHA256= {digest}\n'.encode()]), patch('xray_binary.subprocess.run', return_value=subprocess.CompletedProcess([], 0 if version_ok else 1)), contextlib.redirect_stderr(io.StringIO()):
                if not checksum_ok or not version_ok:
                    with self.assertRaises(RuntimeError):
                        xray_binary.ensure_binary()
                    self.assertFalse(destination.exists())
                else:
                    self.assertEqual(xray_binary.ensure_binary(), str(destination))
                    self.assertEqual(destination.read_bytes(), b'test binary')
                    self.assertEqual(destination.stat().st_mode & 0o777, 0o755)
                self.assertFalse((Path(directory) / 'untrusted').exists())

    def test_download_verifies_checksum(self):
        self.download()
        self.download(checksum_ok=False)

    def test_failed_binary_check_removes_only_new_binary(self):
        self.download(version_ok=False)

    def test_stopped_instance_port_remains_reserved(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / '8443').mkdir()
            (Path(directory) / 'notes').mkdir()
            with patch('server_port.Path', return_value=Path(directory)):
                self.assertEqual(server_port.configured_xray_ports(), {8443})

    def test_failure_cleanup_preserves_previous_instance(self):
        template = Path('install_vless.sh').read_text()
        function = re.search(r'cleanup\(\) \{.*?^\}', template, re.S | re.M).group()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            units = root / 'units'
            units.mkdir()
            previous = units / 'xray.service'
            previous.write_text('existing service')
            new = units / 'vpsvpn-xray-8443.service'
            new.write_text('new service')
            firewall = units / 'vpsvpn-xray-8443-firewall.service'
            firewall.write_text('new firewall')
            config = root / '8443'
            config.mkdir()
            (config / 'config.json').write_text('new config')
            function = function.replace('/etc/systemd/system', str(units))
            script = 'set -e\nservice=vpsvpn-xray-8443\nfirewall=$service-firewall\ncreated_slot=1\ncommitted=0\nXRAY_DIR="$1"\nsystemctl() { return 0; }\n' + function + '\ntrap cleanup EXIT\nfalse\n'
            result = subprocess.run(['bash', '-s', '--', str(config)], input=script, text=True, capture_output=True)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(previous.read_text(), 'existing service')
            self.assertFalse(new.exists())
            self.assertFalse(firewall.exists())
            self.assertFalse(config.exists())
