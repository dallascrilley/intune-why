import io
import datetime as dt
import unittest

from intune_why.analyze import analyze
from intune_why.graph import GRAPH, GraphClient, GraphError, collect, device_code_token

from helpers import FakeHTTP


class PagingTests(unittest.TestCase):
    def test_follows_graph_pages_and_refuses_other_origins(self):
        http = FakeHTTP([(200, {"value": [1], "@odata.nextLink": GRAPH + "/x?$skiptoken=2"}, {}),
                         (200, {"value": [2], "@odata.nextLink": "https://evil.example/steal"}, {})])
        with self.assertRaises(GraphError):
            GraphClient("token", opener=http).pages(GRAPH + "/x")
        self.assertEqual(len(http.requests), 2)
        self.assertTrue(all(r.full_url.startswith("https://graph.microsoft.com/") for r in http.requests))

    def test_honors_retry_after_on_throttling(self):
        waits = []
        http = FakeHTTP([(429, {}, {"Retry-After": "7"}), (200, {"value": [1]}, {})])
        self.assertEqual(GraphClient("token", opener=http, sleep=waits.append).pages(GRAPH + "/x"), [1])
        self.assertEqual(waits, [7.0])

    def test_explains_missing_permission_without_echoing_body(self):
        http = FakeHTTP([(403, {"error": {"message": "token=abc"}}, {})])
        with self.assertRaises(GraphError) as ctx:
            GraphClient("token", opener=http).pages(GRAPH + "/x")
        self.assertIn("permission", str(ctx.exception))
        self.assertNotIn("abc", str(ctx.exception))


class CollectTests(unittest.TestCase):
    def test_builds_an_analyzable_snapshot(self):
        http = FakeHTTP([
            (200, {"value": [{"id": "d1", "deviceName": "LT-1", "operatingSystem": "Windows", "lastSyncDateTime": "2026-10-26T00:00:00Z",
                              "complianceState": "noncompliant", "userPrincipalName": "a@example.test"}]}, {}),
            (200, {"value": [{"id": "s1", "setting": "W.BitLockerEnabled", "platformType": "windows10AndLater", "nonCompliantDeviceCount": 1},
                             {"id": "s2", "setting": "W.Firewall", "nonCompliantDeviceCount": 0}]}, {}),
            (200, {"value": [{"deviceId": "d1", "setting": "W.BitLockerEnabled", "settingName": "BitLockerEnabled", "state": "nonCompliant"},
                             {"deviceId": "d2", "setting": "W.BitLockerEnabled", "state": "compliant"}]}, {}),
        ])
        snap = collect(GraphClient("token", opener=http), dt.datetime(2026, 10, 27, tzinfo=dt.timezone.utc))
        self.assertEqual(len(http.requests), 3)
        self.assertIn("/deviceCompliancePolicySettingStateSummaries/s1/deviceComplianceSettingStates", http.requests[2].full_url)
        self.assertEqual(len(snap["setting_states"]), 1)
        self.assertEqual(analyze(snap)["plan"][0]["cause"], "W.BitLockerEnabled")


class DeviceCodeTests(unittest.TestCase):
    def test_polls_until_token_and_backs_off_on_slow_down(self):
        waits, printed = [], []
        http = FakeHTTP([
            (200, {"device_code": "dc", "user_code": "ABC", "verification_uri": "https://microsoft.com/devicelogin",
                   "message": "Go sign in", "interval": 5, "expires_in": 900}, {}),
            (400, {"error": "authorization_pending"}, {}),
            (400, {"error": "slow_down"}, {}),
            (200, {"access_token": "tok"}, {}),
        ])

        class Out:
            def write(self, s):
                printed.append(s)

        token = device_code_token("contoso.example", opener=http, out=Out(), sleep=waits.append, clock=lambda: 0)
        self.assertEqual(token, "tok")
        self.assertEqual(waits, [5, 5, 10])
        self.assertIn("Go sign in", "".join(printed))
        self.assertTrue(all(r.full_url.startswith("https://login.microsoftonline.com/contoso.example/") for r in http.requests))

    def test_declined_sign_in_raises(self):
        http = FakeHTTP([(200, {"device_code": "dc", "interval": 1, "expires_in": 60}, {}),
                         (400, {"error": "authorization_declined"}, {})])
        with self.assertRaises(GraphError):
            device_code_token(None, opener=http, out=io.StringIO(), sleep=lambda s: None, clock=lambda: 0)


if __name__ == "__main__":
    unittest.main()
