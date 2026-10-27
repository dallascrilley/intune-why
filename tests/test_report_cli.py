import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from intune_why.analyze import analyze
from intune_why.classify import classify
from intune_why.cli import main
from intune_why.report import redact, to_csv, to_html

from helpers import FakeHTTP, device, failing, snapshot


def built(name="LT-1", user="a@example.test"):
    return classify(analyze(snapshot([device("a", name=name, user=user)], [failing("a", "W.BitLockerEnabled")])))


class ReportTests(unittest.TestCase):
    def test_html_cannot_be_broken_out_of_by_tenant_data(self):
        page = to_html(built(name="</script><script>alert(1)</script>"))
        self.assertNotIn("</script><script>alert", page)
        self.assertEqual(page.count("</script>"), 1)

    def test_redact_replaces_names_consistently(self):
        report = redact(built(), salt="s")
        d = report["devices"]["a"]
        self.assertTrue(d["name"].startswith("device-") and d["user"].startswith("user-"))
        self.assertNotIn("example.test", json.dumps(report))

    def test_csv_neutralizes_formulas(self):
        self.assertIn("'=cmd", to_csv(built(name="=cmd|calc")))


class CliTests(unittest.TestCase):
    def test_demo_writes_report_and_prints_plan(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch("webbrowser.open") as opened:
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main(["demo", "--no-open", "--html", str(Path(tmp) / "r.html")])
            self.assertEqual(code, 0)
            self.assertIn("3 fixes raise compliance from 62% to 86%", out.getvalue())
            self.assertIn('"source": "demo"', (Path(tmp) / "r.html").read_text())
            opened.assert_not_called()

    def test_analyze_reports_bad_input_with_exit_code(self):
        err = io.StringIO()
        with mock.patch("sys.stdin", io.StringIO('{"schema": "nope"}')), contextlib.redirect_stderr(err):
            self.assertEqual(main(["analyze", "-"]), 1)
        self.assertIn("schema", err.getvalue())

    def test_collect_with_token_on_stdin_writes_private_snapshot_and_plan(self):
        http = FakeHTTP([
            (200, {"value": [{"id": "d1", "deviceName": "LT-1", "operatingSystem": "Windows", "complianceState": "noncompliant",
                              "lastSyncDateTime": "2026-10-26T00:00:00Z"}]}, {}),
            (200, {"value": [{"id": "s1", "setting": "W.BitLockerEnabled", "nonCompliantDeviceCount": 1}]}, {}),
            (200, {"value": [{"deviceId": "d1", "setting": "W.BitLockerEnabled", "state": "nonCompliant"}]}, {}),
        ])
        with tempfile.TemporaryDirectory() as tmp, mock.patch("intune_why.graph._default_open", return_value=http), \
                mock.patch("sys.stdin", io.StringIO("secret-token-value\n")):
            out, err = io.StringIO(), io.StringIO()
            target = Path(tmp) / "snap.json"
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(main(["collect", "--token-stdin", "--out", str(target)]), 0)
            self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o600)
            self.assertIn("BitLocker not enabled", out.getvalue())
            everything = target.read_text() + out.getvalue() + err.getvalue()
            self.assertNotIn("secret-token-value", everything)
        self.assertEqual(http.requests[0].get_header("Authorization"), "Bearer secret-token-value")


if __name__ == "__main__":
    unittest.main()
