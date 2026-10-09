import base64
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import diagnose_vless as diagnostic
import vpn_setup
from test_setup import VLESS, KEY


PARAMETERS = {"port": 8443, "uuid": "00000000-0000-4000-8000-000000000001",
              "sni": "www.microsoft.com", "sid": "0123456789abcdef",
              "flow": "xtls-rprx-vision", "pbk": KEY.rstrip("=")}


class VlessDiagnosticTests(unittest.TestCase):
    def config(self):
        return {"inbounds": [{"protocol": "vless", "port": 8443,
                "settings": {"clients": [{"id": PARAMETERS["uuid"], "flow": PARAMETERS["flow"]}]},
                "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
                    "privateKey": KEY.rstrip("="), "shortIds": [PARAMETERS["sid"]],
                    "serverNames": [PARAMETERS["sni"]], "target": "www.microsoft.com:443"}}}]}

    def run_diagnostic(self, data, service_ok=True, probe_error=None):
        output = io.StringIO()
        def command(args, **kwargs):
            if args[0] == "openssl":
                self.assertNotIn(KEY.rstrip("="), " ".join(args))
                return subprocess.CompletedProcess(args, 0, bytes.fromhex("302a300506032b656e032100") + bytes(range(32)))
            if args[0] == "systemctl":
                self.assertEqual(args, ["systemctl", "is-active", "--quiet", "vpsvpn-xray-8443"])
                return subprocess.CompletedProcess(args, 0 if service_ok else 3, b"")
            self.assertEqual(args, ["ss", "-H", "-ltn", "sport = :8443"])
            return subprocess.CompletedProcess(args, 0, b"LISTEN")

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "etc/vpsvpn-xray/8443/config.json"
            path.parent.mkdir(parents=True)
            path.write_text(data)
            before = path.read_bytes()
            with contextlib.redirect_stdout(output), patch.object(diagnostic, "command", side_effect=command), patch.object(diagnostic, "tls_probe", return_value=True, side_effect=probe_error):
                result = diagnostic.diagnose_vless(PARAMETERS, Path(directory))
            self.assertEqual(path.read_bytes(), before)
        report = output.getvalue()
        for secret in (KEY.rstrip("="), PARAMETERS["uuid"], PARAMETERS["sid"]):
            self.assertNotIn(secret, report)
        return result, report

    def test_matching_configuration(self):
        result, report = self.run_diagnostic(json.dumps(self.config()))
        self.assertEqual(result, 0)
        self.assertIn("не подтверждают работу VLESS", report)

    def test_inactive_service_and_stale_client_report_errors(self):
        config = self.config()
        config["inbounds"][0]["settings"]["clients"][0]["id"] = "stale-client"
        result, report = self.run_diagnostic(json.dumps(config), service_ok=False)
        self.assertEqual(result, 1)
        self.assertIn("ОШИБКА: служба Xray активна", report)
        self.assertIn("ОШИБКА: UUID", report)
        self.assertIn("OK: контрольное TLS", report)

    def test_malformed_json_and_network_errors_are_redacted(self):
        result, report = self.run_diagnostic('{"privateKey": "secret-not-to-print"', probe_error=OSError("secret-not-to-print"))
        self.assertEqual(result, 1)
        self.assertNotIn("secret-not-to-print", report)
        self.assertIn("JSONDecodeError", report)
        self.assertIn("OSError", report)

    def test_public_key_mismatch_and_openssl_errors(self):
        output = bytes.fromhex("302a300506032b656e032100") + bytes(reversed(range(32)))
        with patch.object(diagnostic, "command", return_value=subprocess.CompletedProcess([], 0, output)):
            self.assertFalse(diagnostic.matching_public_key({"privateKey": KEY.rstrip("=")}, KEY.rstrip("=")))
        with patch.object(diagnostic, "command", return_value=subprocess.CompletedProcess([], 1, b"")):
            with self.assertRaises(ValueError):
                diagnostic.matching_public_key({"privateKey": KEY.rstrip("=")}, KEY.rstrip("="))

    def test_embedded_script_runs_without_local_modules(self):
        script = vpn_setup.make_vless_diagnostic(VLESS)
        subprocess.run(["bash", "-n"], input=script, text=True, check=True)
        source = script.split("<<'VLESSDIAGPY'\n", 1)[1].rsplit("\nVLESSDIAGPY", 1)[0]
        self.assertNotIn("from config_checks", source)
        namespace = {}
        exec(compile(source.rsplit("\nraise SystemExit", 1)[0], "remote-diagnostic", "exec"), namespace)
        self.assertTrue(namespace["matching_parameters"](self.config()["inbounds"][0], PARAMETERS))

    def test_client_tcp_failure_still_runs_remote_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.txt"
            path.write_text(VLESS)
            with patch("vpn_setup.ask", side_effect=[str(path), "203.0.113.10", "22", ""]), patch("vpn_setup.shutil.which", return_value="ssh"), patch("vpn_setup.ssh_args", return_value=["ssh"]), patch("vpn_setup.socket.gethostbyname", return_value="203.0.113.10"), patch("vpn_setup.socket.create_connection", side_effect=TimeoutError()), patch("vpn_setup.subprocess.run", return_value=subprocess.CompletedProcess([], 0)) as run, contextlib.redirect_stdout(io.StringIO()) as output:
                with self.assertRaisesRegex(RuntimeError, "Диагностика выявила ошибки"):
                    vpn_setup.diagnose_vless_client()
                run.assert_called_once()
                self.assertNotIn(PARAMETERS["uuid"], output.getvalue())
                self.assertEqual(path.read_text(), VLESS)


if __name__ == "__main__":
    unittest.main()
