import base64
import contextlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import config_checks
import server_port
import vpn_setup
import test_setup
from test_setup import AWG, KEY, VLESS


def blocks(script):
    return re.findall(r"<<'([A-Z]+)'[^\n]*\n(.*?)\n\1(?:\n|$)", script, re.S)


class Regressions(unittest.TestCase):
    def test_normalizes_hosts(self):
        self.assertEqual(vpn_setup.host('VPN.Example.COM.'), 'vpn.example.com')
        self.assertEqual(vpn_setup.host('2001:0DB8::0001'), '2001:db8::1')
        for value in ['bad..host', 'bad-.host', '999.1.2.3', 'fe80::1%eth0', 'a' * 64 + '.com', 'example.com\n']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                vpn_setup.host(value)

    def test_endpoint_rejects_userinfo_paths_and_controls(self):
        for value in ['user@host:123', 'host:123/path', 'host:123?x=1', 'ho\nst:123', 'host:0']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                config_checks.endpoint(value)

    def test_duplicate_or_bad_vless_params_rejected(self):
        for text in [VLESS.strip() + '&pbk=duplicate', VLESS.replace('&sid=', '&pbk=other&sid='), VLESS.replace('www.microsoft.com', '1.1.1.1'), VLESS.replace('sni=', 'sni=&other='), VLESS.replace('security=reality', 'broken-secret')]:
            if text.endswith('&pbk=duplicate'):
                text = VLESS.replace('#phone', '&pbk=duplicate#phone')
            with self.subTest(text=text[-40:]), self.assertRaises(ValueError):
                config_checks.validate_profile('vless', text)

    def test_bad_awg_fields_do_not_leak_values(self):
        for text in [AWG.replace('Jc = 5', 'Jc = hidden-secret'), AWG.replace('Address = 10.77.77.2/32', 'Address = hidden-secret')]:
            with self.assertRaises(ValueError) as caught:
                config_checks.validate_profile('amnezia', text)
            self.assertNotIn('hidden-secret', str(caught.exception))
        with self.assertRaises(ValueError):
            config_checks.validate_profile('amnezia', AWG.replace('[Interface]', '[Interface]\nPostUp = malicious'))

    def test_zero_keys_rejected(self):
        with self.assertRaises(ValueError):
            config_checks.check_key(base64.b64encode(bytes(32)).decode(), 'key')

    def test_disk_failure_removes_partial_profile(self):
        helper = test_setup.SetupTests()
        with tempfile.TemporaryDirectory() as directory, patch('vpn_setup.os.fsync', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                helper.run_setup(directory, '1', subprocess.CompletedProcess([], 0, AWG))
            self.assertFalse((Path(directory) / 'profile').exists())

    def test_docker_dynamic_and_udp_ports(self):
        data = [{'HostConfig': {'PortBindings': {'51820/udp': [{'HostPort': ''}]}},
                 'NetworkSettings': {'Ports': {'51820/udp': [{'HostPort': '51821'}], '443/tcp': [{'HostPort': '8443'}]}}}]
        with patch('server_port.shutil.which', return_value='docker'), patch('server_port.subprocess.check_output', side_effect=['id', json.dumps(data)]):
            self.assertEqual(server_port.docker_ports('udp'), {51821})

    def test_all_embedded_programs_compile(self):
        for protocol in ['amnezia', 'vless']:
            script = vpn_setup.make_script(protocol, 443, 'EXAMPLE.com', 'www.microsoft.com')
            self.assertNotRegex(script, r'@(PARAMETERS|PORT_SELECTOR|CONFIG_CHECKS|PORT)@')
            subprocess.run(['bash', '-n'], input=script, text=True, check=True)
            for tag, code in blocks(script):
                if tag in ['PY', 'PORTPY', 'PREFLIGHTPY', 'CHECKPY', 'BINARYPY']:
                    compile(code, protocol + '-' + tag, 'exec')

    def test_ssh_store_update_preserves_other_hosts_and_nonstandard_port(self):
        real_run = subprocess.run
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory) / 'testkey'
            real_run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(private)], check=True)
            public = private.with_suffix('.pub').read_text().split()[1]
            fingerprint = real_run(['ssh-keygen', '-lf', str(private) + '.pub'], capture_output=True, text=True, check=True).stdout.split()[1]
            store = Path(directory) / '.ssh-known-hosts'
            other = f'other.example ssh-ed25519 {public}\n'
            store.write_text(other + f'[203.0.113.10]:2222 ssh-ed25519 {public}\n')

            def run(args, **kwargs):
                if args[0] == 'ssh':
                    return subprocess.CompletedProcess(args, 255, '', 'REMOTE HOST IDENTIFICATION HAS CHANGED')
                if args[0] == 'ssh-keyscan':
                    return subprocess.CompletedProcess(args, 0, f'untrusted-label ssh-ed25519 {public}\n', '')
                return real_run(args, **kwargs)

            with patch('vpn_setup.__file__', str(Path(directory) / 'vpn_setup.py')), patch('vpn_setup.subprocess.run', side_effect=run), patch('builtins.input', return_value=fingerprint), contextlib.redirect_stdout(io.StringIO()):
                options = vpn_setup.host_key_options('203.0.113.10', 2222)
            self.assertIn(other, store.read_text())
            self.assertNotIn('untrusted-label', store.read_text())
            self.assertEqual(store.read_text().count('[203.0.113.10]:2222'), 1)
            self.assertIn('HostKeyAlgorithms=ssh-ed25519', options)


class RemoteGeneration(unittest.TestCase):
    def run_generator(self, protocol, corrupt=False):
        script = vpn_setup.make_script(protocol, 443 if protocol == 'vless' else 51820, '203.0.113.10', 'www.microsoft.com', 'Мой телефон')
        snippets = blocks(script)
        generator = next(code for tag, code in snippets if tag == 'PY' and 'client_name' in code and 'write_text' in code)
        checker = next(code for tag, code in snippets if tag == 'CHECKPY')
        path_type, real_open, real_run = Path, open, subprocess.run
        with tempfile.TemporaryDirectory() as directory:
            root = path_type(directory)

            def path(value):
                value = str(value)
                return root / value.lstrip('/') if value.startswith(('/etc/', '/usr/local/etc/', '/proc/')) else path_type(value)

            def open_file(value, *args, **kwargs):
                return real_open(path(value), *args, **kwargs)

            for name in ['/etc/amnezia/amneziawg', '/usr/local/etc/xray', '/etc/vpsvpn-xray/8443']:
                path(name).mkdir(parents=True)
            ipv6 = path('/proc/sys/net/ipv6/conf/all/disable_ipv6')
            ipv6.parent.mkdir(parents=True)
            ipv6.write_text('0\n')
            private = bytes.fromhex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
            public = bytes.fromhex('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a')

            def output(args, **kwargs):
                if args[0] == 'awg':
                    return KEY + '\n'
                if args[:2] == ['/usr/local/bin/xray', 'x25519']:
                    return 'PrivateKey: ' + base64.urlsafe_b64encode(private).decode().rstrip('=') + '\nPassword (PublicKey): ' + base64.urlsafe_b64encode(public).decode().rstrip('=') + '\n'
                raise AssertionError(args)

            def run(args, **kwargs):
                self.assertEqual(args, ['openssl', 'pkey', '-inform', 'DER', '-pubout', '-outform', 'DER'])
                self.assertEqual(kwargs['input'], bytes.fromhex('302e020100300506032b656e04220420') + private)
                return subprocess.CompletedProcess(args, 0, bytes.fromhex('302a300506032b656e032100') + public, b'')

            old = path('/usr/local/etc/xray/config.json')
            old.write_text('existing unrelated config')
            env = {'VPN_PORT': '8443', 'XRAY_BIN': '/usr/local/bin/xray', 'XRAY_CONFIG': '/etc/vpsvpn-xray/8443/config.json', 'XRAY_CLIENT': '/etc/vpsvpn-xray/8443/client.txt', 'XRAY_GROUP': 'vpsvpn-xray'}
            with patch('pathlib.Path', side_effect=path), patch('builtins.open', side_effect=open_file), patch('subprocess.check_output', side_effect=output), patch('subprocess.run', side_effect=run), patch('grp.getgrnam', return_value=SimpleNamespace(gr_gid=os.getgid())), patch('os.chown'), patch.dict(os.environ, env), patch('sys.argv', ['-', 'ens3']), contextlib.redirect_stderr(io.StringIO()):
                exec(compile(generator, 'generator', 'exec'), {})
                if corrupt:
                    if protocol == 'amnezia':
                        file = path('/etc/amnezia/amneziawg/awg0.conf')
                        file.write_text(file.read_text().replace('S1 = 64', 'S1 = 65'))
                    else:
                        file = path('/etc/vpsvpn-xray/8443/config.json')
                        config = json.loads(file.read_text())
                        config['inbounds'][0]['port'] = 1234
                        file.write_text(json.dumps(config))
                    with self.assertRaises(SystemExit):
                        exec(compile(checker, 'checker', 'exec'), {})
                else:
                    exec(compile(checker, 'checker', 'exec'), {})
            if protocol == 'amnezia':
                config = path('/etc/amnezia/amneziawg/awg0.conf').read_text()
                for line in config.splitlines():
                    if line.startswith(('PostUp =', 'PostDown =')):
                        real_run(['bash', '-n'], input=line.split('=', 1)[1], text=True, check=True)
            self.assertEqual(old.read_text(), 'existing unrelated config')
            file = path('/etc/amnezia/amneziawg/client.conf' if protocol == 'amnezia' else '/etc/vpsvpn-xray/8443/client.txt')
            return file.read_text()

    def test_amnezia_generator_and_checker(self):
        text = self.run_generator('amnezia')
        self.assertIn('Мой телефон', text)
        self.assertEqual(config_checks.validate_profile('amnezia', text), ('203.0.113.10', 51820))

    def test_vless_generator_and_checker(self):
        text = self.run_generator('vless')
        self.assertIn('%D0%9C', text)
        self.assertEqual(config_checks.validate_profile('vless', text), ('203.0.113.10', 8443))

    def test_mismatched_server_rejected(self):
        for protocol in ['amnezia', 'vless']:
            self.run_generator(protocol, corrupt=True)
