import contextlib
import io
import json
import os
from pathlib import Path
import random
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import config_checks
import diagnose_vless
import offline_check
import vpn_setup
from test_setup import AWG, KEY, VLESS
import test_vless_diagnostic
from test_vless_diagnostic import PARAMETERS


class OfflineTests(unittest.TestCase):
    def codes(self, text):
        return {item["code"] for item in offline_check.inspect_profile(text)["findings"]}

    def test_generated_profiles_pass_without_network_or_commands(self):
        with patch("socket.getaddrinfo", side_effect=AssertionError("network")), patch("socket.socket", side_effect=AssertionError("network")), patch("subprocess.run", side_effect=AssertionError("command")):
            for profile, protocol in ((VLESS, "vless"), (AWG, "amnezia")):
                result = offline_check.inspect_profile(profile)
                self.assertEqual(result["protocol"], protocol)
                self.assertNotEqual(result["status"], "error")
                self.assertNotIn(KEY.rstrip("="), json.dumps(result))
                self.assertNotIn(PARAMETERS["uuid"], json.dumps(result))

    def test_multiple_errors_and_hints_are_reported_without_values(self):
        broken = VLESS.replace(PARAMETERS["uuid"], "TOPSECRET").replace("fp=chrome", "fp=").replace("sni=www.microsoft.com", "sni=TOPSECRET/invalid").replace(KEY.rstrip("="), "TOPSECRET").replace("8443", "99999")
        result = offline_check.inspect_profile(broken)
        self.assertEqual(result["status"], "error")
        self.assertTrue({"vless.uuid", "vless.endpoint", "vless.pbk", "vless.sni", "vless.fp"} <= {item["code"] for item in result["findings"]})
        self.assertNotIn("TOPSECRET", json.dumps(result))
        self.assertTrue(all(item["hint"] for item in result["findings"]))

    def test_amnezia_reports_several_independent_errors(self):
        profile = AWG.replace("Jc = 5", "Jc = TOPSECRET").replace("H4 = 400", "H4 = 100").replace("Jmin = 8", "Jmin = 81").replace("10.77.77.2/32", "TOPSECRET").replace("[Interface]", "[Interface]\nPostUp = echo TOPSECRET\nDNS = https://TOPSECRET")
        result = offline_check.inspect_profile(profile)
        self.assertTrue({"awg.jc", "awg.headers", "awg.jrange", "awg.address", "awg.hooks", "awg.dns"} <= self.codes(profile))
        self.assertNotIn("TOPSECRET", json.dumps(result))

    def test_duplicates_invalid_encoding_unknown_types(self):
        cases = [(AWG.replace("[Peer]", "[Peer]\nPublicKey = TOPSECRET"), "awg.parse"),
                 (VLESS.replace("fp=chrome", "fp=chrome&fp=firefox"), "vless.duplicates"),
                 (VLESS.replace("#phone", "#%GG"), "vless.encoding"),
                 (VLESS + VLESS, "vless.whitespace"),
                 ('{"privateKey": "TOPSECRET"}', "file.unsupported"), ("", "file.empty")]
        for text, code in cases:
            with self.subTest(code=code):
                self.assertIn(code, self.codes(text))
                self.assertNotIn("TOPSECRET", json.dumps(offline_check.inspect_profile(text)))

    def test_unknown_fields_are_warnings_without_echoing_their_names(self):
        for text in (VLESS.replace("#phone", "&TOPSECRET=TOPSECRET#phone"), AWG.replace("[Peer]", "TOPSECRET = TOPSECRET\n[Peer]")):
            result = offline_check.inspect_profile(text)
            self.assertEqual(result["status"], "warning")
            self.assertNotIn("TOPSECRET", json.dumps(result))

    def test_supported_empty_and_short_reality_ids(self):
        for sid in ("", "ab", "ABCDEF", "0123456789abcdef"):
            with self.subTest(sid=sid):
                text = VLESS.replace(PARAMETERS["sid"], sid)
                self.assertNotIn("vless.sid", self.codes(text))
                config_checks.validate_profile("vless", text)
                vpn_setup.make_vless_diagnostic(text)
                config = test_vless_diagnostic.VlessDiagnosticTests().config()["inbounds"][0]
                config["streamSettings"]["realitySettings"]["shortIds"] = [sid.lower().ljust(16, "0")]
                self.assertTrue(diagnose_vless.matching_parameters(config, {**PARAMETERS, "sid": sid}))
        for sid in ("a", "abc", "gg", "ab" * 9):
            text = VLESS.replace(PARAMETERS["sid"], sid)
            self.assertIn("vless.sid", self.codes(text))
            with self.assertRaises(ValueError):
                config_checks.validate_profile("vless", text)

    def test_core_validation_regressions(self):
        for value in ("example.com..", "example.com...", "."):
            with self.assertRaises(ValueError):
                config_checks.normalize_host(value)
        self.assertEqual(config_checks.normalize_host("Example.com."), "example.com")
        for fingerprint in ("unsafe", "chrome%0Asecret"):
            with self.assertRaises(ValueError):
                config_checks.validate_profile("vless", VLESS.replace("fp=chrome", "fp=" + fingerprint))
        with self.assertRaises(ValueError) as caught:
            vpn_setup.port("TOPSECRET")
        self.assertNotIn("TOPSECRET", str(caught.exception))

    def test_folder_report_and_input_files_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            folder = root / "profiles"
            folder.mkdir()
            (folder / "one.txt").write_text(VLESS)
            (folder / "two.conf").write_text(AWG)
            (folder / "notes.md").write_text("ignore me")
            (folder / ".hidden.txt").write_text("ignore me")
            before = {path.name: path.read_bytes() for path in folder.iterdir()}
            output = root / "reports" / "check.json"
            with patch("socket.getaddrinfo", side_effect=AssertionError("network")), patch("subprocess.run", side_effect=AssertionError("command")), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(vpn_setup.cli(["--check", str(folder), str(folder / "one.txt"), "--report", str(output)]), 0)
            report = json.loads(output.read_text())
            self.assertEqual(len(report["files"]), 2)
            self.assertEqual(report["mode"], "offline")
            self.assertNotIn(KEY.rstrip("="), output.read_text())
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(before, {path.name: path.read_bytes() for path in folder.iterdir()})

    def test_bad_file_does_not_skip_next_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bad.txt").write_bytes(b"\xff\x00")
            (root / "good.txt").write_text("\ufeff" + VLESS)
            output = root / "report.json"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(offline_check.check_files([root / "bad.txt", root / "missing", root / "good.txt"], output), 1)
            results = json.loads(output.read_text())["files"]
            self.assertEqual([item["status"] for item in results], ["error", "error", "warning"])
            self.assertEqual(results[0]["findings"][0]["code"], "file.encoding")

    def test_large_file_fifo_empty_folder(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            empty = root / "empty"
            empty.mkdir()
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(offline_check.check_files([empty]), 1)
                self.assertIn("folder.empty", output.getvalue())
            large = root / "large.txt"
            large.write_bytes(b"x" * (offline_check.MAX_BYTES + 1))
            self.assertEqual(offline_check.inspect_file(large)["findings"][0]["code"], "file.large")
            fifo = root / "pipe"
            os.mkfifo(fifo)
            self.assertEqual(offline_check.inspect_file(fifo)["findings"][0]["code"], "file.read")

    def test_report_never_overwrites_source_or_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = root / "profile.txt"
            profile.write_text(VLESS)
            link = root / "link.txt"
            link.symlink_to(profile)
            report = {"files": [], "mode": "offline"}
            for target in (profile, link):
                with self.assertRaises(ValueError):
                    offline_check.save_report(target, report)
            self.assertEqual(profile.read_text(), VLESS)
            failed = root / "failed.txt"
            with patch("offline_check.os.fsync", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    offline_check.save_report(failed, report)
            self.assertFalse(failed.exists())

    def test_interactive_and_invalid_cli_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory) / "client.txt"
            profile.write_text(VLESS)
            with patch("vpn_setup.ask", return_value=str(profile)), patch("vpn_setup.shutil.which", return_value=None), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(vpn_setup.cli(["--check"]), 0)
        for args in (["--report", "report.json"], ["--check", "--diagnose"], ["--check", "--diagnose-vless"]):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                vpn_setup.cli(args)
            self.assertEqual(caught.exception.code, 2)

    def test_malformed_inputs_never_raise_or_leak_values(self):
        generator = random.Random(42)
        alphabet = "[]@:/?&#%\n\r\t=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        samples = ["".join(generator.choice(alphabet) for _ in range(generator.randrange(200))) for _ in range(300)]
        for prefix in ("", "vless://", "[Interface]\n"):
            for text in samples:
                result = offline_check.inspect_profile(prefix + text)
                self.assertIn(result["status"], ("ok", "warning", "error"))

    def test_real_cli_exit_codes_and_help(self):
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory) / "valid.txt"
            profile.write_text(VLESS)
            program = str(Path(vpn_setup.__file__).resolve())
            import sys
            for data, expected in ((VLESS, 0), ("vless://broken", 1)):
                profile.write_text(data)
                result = subprocess.run([sys.executable, "-B", program, "--check", str(profile)], capture_output=True, text=True)
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertIn("Офлайн", result.stdout)
            result = subprocess.run([sys.executable, "-B", program, "--help"], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0)
            self.assertIn("--check", result.stdout)


if __name__ == "__main__":
    unittest.main()
