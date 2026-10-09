import contextlib
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
import base64
from unittest.mock import patch
import vpn_setup
import server_port
from config_checks import validate_profile

KEY = base64.b64encode(bytes(range(32))).decode()
AWG = f'''[Interface]
PrivateKey = {KEY}
Address = 10.77.77.2/32
Jc = 5
Jmin = 8
Jmax = 80
S1 = 64
S2 = 67
H1 = 100
H2 = 200
H3 = 300
H4 = 400
[Peer]
PublicKey = {KEY}
PresharedKey = {KEY}
Endpoint = 203.0.113.10:51820
AllowedIPs = 0.0.0.0/0, ::/0
'''
VLESS = 'vless://00000000-0000-4000-8000-000000000001@203.0.113.10:8443?security=reality&type=tcp&encryption=none&flow=xtls-rprx-vision&pbk=' + KEY.rstrip('=') + '&sid=0123456789abcdef&sni=www.microsoft.com&fp=chrome#phone\n'


class SetupTests(unittest.TestCase):
    def run_setup(self, directory, choice, result, socket_error=None):
        output = str((Path(directory) / 'profile').resolve())
        answers = [choice, '203.0.113.10', '', '', '']
        if choice == '2':
            answers.append('www.microsoft.com')
        answers += ['Мой телефон', '', directory, 'profile']
        terminal = io.StringIO()
        with patch('builtins.input', side_effect=answers), patch('vpn_setup.socket.create_connection', side_effect=socket_error), patch('vpn_setup.host_key_options', return_value=[]), patch('vpn_setup.shutil.which', return_value='/usr/bin/ssh'), patch('vpn_setup.subprocess.run', return_value=result) as run, contextlib.redirect_stdout(terminal):
            vpn_setup.main()
        self.assertIn(result.stdout, terminal.getvalue())
        self.assertIn(f'Сохранено в: {output}', terminal.getvalue())
        return Path(output), run.call_args

    def test_amnezia_output_and_permissions(self):
        config = AWG
        with tempfile.TemporaryDirectory() as directory:
            output, call = self.run_setup(directory, '1', subprocess.CompletedProcess([], 0, config))
            self.assertEqual(output.read_text(), config)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertIn('awg-quick up awg0', call.kwargs['input'])
            self.assertNotIn('@PARAMETERS@', call.kwargs['input'])

    def test_vless_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output, call = self.run_setup(directory, '2', subprocess.CompletedProcess([], 0, VLESS))
            self.assertEqual(output.read_text(), VLESS)
            self.assertIn('xtls-rprx-vision', call.kwargs['input'])
            self.assertIn('--dport $VPN_PORT', call.kwargs['input'])

    def test_vless_port_coexists_with_amnezia_udp(self):
        self.assertEqual(server_port.select_port(443, set(), lambda p: True), 443)

    def test_profile_validation_rejects_bad_keys(self):
        for protocol, text in [('amnezia', AWG.replace(KEY, 'broken-secret')), ('vless', VLESS.replace(KEY.rstrip('='), 'broken-secret'))]:
            with self.assertRaises(ValueError) as caught:
                validate_profile(protocol, text)
            self.assertNotIn('broken-secret', str(caught.exception))

    def test_profile_validation_rejects_parameters(self):
        for protocol, text in [('amnezia', AWG.replace('H4 = 400', 'H4 = 100')), ('vless', VLESS.replace('type=tcp', 'type=udp'))]:
            with self.assertRaises(ValueError):
                validate_profile(protocol, text)

    def test_valid_profiles(self):
        self.assertEqual(validate_profile('amnezia', AWG), ('203.0.113.10', 51820))
        self.assertEqual(validate_profile('vless', VLESS), ('203.0.113.10', 8443))

    def test_unreachable_tcp_reports_error_and_retains_profile(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stderr(io.StringIO()) as errors:
            with self.assertRaisesRegex(RuntimeError, 'проверка доступности TCP-порта'):
                self.run_setup(directory, '2', subprocess.CompletedProcess([], 0, VLESS), OSError('timeout'))
            self.assertEqual((Path(directory) / 'profile').read_text(), VLESS)
            self.assertIn('TCP 8443 недоступен', errors.getvalue())

    def test_vless_port_skips_docker_and_host_tcp(self):
        self.assertEqual(server_port.select_port(443, {443}, lambda p: p != 8443), 2053)

    def test_vless_no_free_port(self):
        with self.assertRaises(RuntimeError):
            server_port.select_port(443, set(), lambda p: False)

    def test_docker_tcp_reservations(self):
        containers = [{'HostConfig': {'PortBindings': {
            '443/udp': [{'HostPort': '443'}],
            '443/tcp': [{'HostPort': '8443'}],
        }}}]
        with patch('server_port.shutil.which', return_value='/usr/bin/docker'), patch('server_port.subprocess.check_output', side_effect=['container\n', __import__('json').dumps(containers)]):
            self.assertEqual(server_port.docker_tcp_ports(), {8443})

    def test_failure_removes_empty_output(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(RuntimeError):
                self.run_setup(directory, '1', subprocess.CompletedProcess([], 1, ''))
            self.assertFalse((Path(directory) / 'profile').exists())

    def test_invalid_reply_is_not_saved(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(RuntimeError):
                self.run_setup(directory, '2', subprocess.CompletedProcess([], 0, 'installer log'))
            self.assertFalse((Path(directory) / 'profile').exists())

    def test_existing_output_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'profile'
            path.write_text('existing secret')
            with self.assertRaises(ValueError):
                self.run_setup(directory, '1', subprocess.CompletedProcess([], 0, ''))
            self.assertEqual(path.read_text(), 'existing secret')

    def test_rejects_shell_injection(self):
        for value in ['host;id', '$(id)', '-oProxyCommand=id', 'a\nb', 'a/b']:
            with self.assertRaises(ValueError):
                vpn_setup.host(value)

    def test_client_name(self):
        self.assertEqual(vpn_setup.client_name('Мой телефон-1'), 'Мой телефон-1')
        for name in ['', '../phone', 'phone\n[Peer]', 'phone#tag', 'x' * 65, '..']:
            with self.assertRaises(ValueError):
                vpn_setup.client_name(name)

    def test_changed_host_key_is_pinned_after_verification(self):
        fingerprint = 'SHA256:verified'
        replies = [subprocess.CompletedProcess([], 255, '', 'REMOTE HOST IDENTIFICATION HAS CHANGED'),
                   subprocess.CompletedProcess([], 0, '203.0.113.10 ssh-ed25519 KEY\n', ''),
                   subprocess.CompletedProcess([], 0, f'256 {fingerprint} host (ED25519)\n', ''),
                   subprocess.CompletedProcess([], 0, '', '')]
        with tempfile.TemporaryDirectory() as directory, patch('vpn_setup.__file__', str(Path(directory) / 'vpn_setup.py')), patch('vpn_setup.subprocess.run', side_effect=replies), patch('vpn_setup.shutil.which', return_value='/usr/bin/tool'), patch('builtins.input', return_value=fingerprint), contextlib.redirect_stdout(io.StringIO()):
            options = vpn_setup.host_key_options('203.0.113.10', 22)
            store = Path(directory) / '.ssh-known-hosts'
            self.assertIn('StrictHostKeyChecking=yes', options)
            self.assertEqual(store.read_text().strip(), '203.0.113.10 ssh-ed25519 KEY')
            self.assertEqual(store.stat().st_mode & 0o777, 0o600)

    def test_unverified_changed_key_is_not_saved(self):
        replies = [subprocess.CompletedProcess([], 255, '', 'REMOTE HOST IDENTIFICATION HAS CHANGED'),
                   subprocess.CompletedProcess([], 0, '203.0.113.10 ssh-ed25519 KEY\n', ''),
                   subprocess.CompletedProcess([], 0, '256 SHA256:verified host (ED25519)\n', '')]
        with tempfile.TemporaryDirectory() as directory, patch('vpn_setup.__file__', str(Path(directory) / 'vpn_setup.py')), patch('vpn_setup.subprocess.run', side_effect=replies), patch('vpn_setup.shutil.which', return_value='/usr/bin/tool'), patch('builtins.input', return_value=''), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(RuntimeError):
                vpn_setup.host_key_options('203.0.113.10', 22)
            self.assertFalse((Path(directory) / '.ssh-known-hosts').exists())

    def test_remote_shell_and_embedded_python_syntax(self):
        for protocol in ['amnezia', 'vless']:
            script = vpn_setup.make_script(protocol, 51820, '203.0.113.1', 'www.microsoft.com')
            subprocess.run(['bash', '-n'], input=script, text=True, check=True)
            snippets, current = [], None
            for line in script.splitlines():
                if line.startswith('python3 ') and ("<<'PY'" in line or "<<'CHECKPY'" in line):
                    current = []
                elif current is not None:
                    if line in ('PY', 'CHECKPY'):
                        snippets.append('\n'.join(current))
                        current = None
                    else:
                        current.append(line)
            self.assertGreater(len(snippets), 0)
            for snippet in snippets:
                compile(snippet, protocol, 'exec')
        diagnostic = vpn_setup.COMMON + Path('diagnose_amnezia.sh').read_text()
        subprocess.run(['bash', '-n'], input=diagnostic, text=True, check=True)


if __name__ == '__main__':
    unittest.main()
