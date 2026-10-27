import unittest

from intune_why.analyze import analyze
from intune_why.classify import JevClient, classify, jev_state, rule_for

from helpers import FakeHTTP, device, failing, snapshot


def report_with(*settings):
    devices = [device("d%d" % i, name="SECRET-HOST-%d" % i, user="secret.user%d@corp.test" % i) for i in range(len(settings))]
    return analyze(snapshot(devices, [failing("d%d" % i, s) for i, s in enumerate(settings)]))


def jev_answer(choice, confidence):
    return (200, {"model": "jev-test", "answers": {"path": {"type": "choice", "choice": choice, "confidence": confidence,
                                                           "probabilities": {choice: confidence}}}}, {})


class RuleTests(unittest.TestCase):
    def test_standard_settings_match_and_custom_password_names_fall_through(self):
        self.assertEqual(rule_for({"setting": "Windows10CompliancePolicy.BitLockerEnabled"})[0], "device_configuration")
        self.assertEqual(rule_for({"setting": "IosCompliancePolicy.PasscodeRequired"})[0], "user_action")
        self.assertEqual(rule_for({"setting": "DefaultDeviceCompliancePolicy.RequireRemainContact"})[0], "stale_or_orphaned")
        self.assertIsNone(rule_for({"setting": "CustomCompliance.BiosPasswordSet"}))
        self.assertIsNone(rule_for({"setting": "CustomCompliance.LapsPasswordBackedUp"}))

    def test_rules_mode_marks_unknown_settings_for_review(self):
        report = classify(report_with("CustomCompliance.VpnInstalled"))
        self.assertEqual(report["causes"][0]["category"], "other")
        self.assertEqual(report["causes"][0]["decision"], {"decided_by": "unclassified"})


class JevTests(unittest.TestCase):
    def run_jev(self, *responses):
        http = FakeHTTP(responses)
        client = JevClient("key", opener=http, sleep=lambda s: None)
        warnings = []
        report = classify(report_with("CustomCompliance.VpnInstalled"), decider="jev", client=client, warn=warnings.append)
        return report["causes"][0], http, warnings

    def test_confident_answer_is_accepted_with_provenance(self):
        cause, http, _ = self.run_jev(jev_answer("device_configuration", 0.93))
        self.assertEqual(cause["category"], "device_configuration")
        self.assertEqual(cause["decision"]["model"], "jev-test")
        self.assertEqual(http.requests[0].full_url, "https://openrouter.ai/api/alpha/decisions")

    def test_low_confidence_answer_goes_to_review(self):
        cause, _, _ = self.run_jev(jev_answer("user_action", 0.41))
        self.assertEqual(cause["category"], "other")
        self.assertEqual((cause["decision"]["decided_by"], cause["decision"]["proposed"]), ("jev-low-confidence", "user_action"))

    def test_retries_rate_limit_then_degrades_without_crashing(self):
        cause, http, warnings = self.run_jev((429, {}, {"retry-after": "0"}), (500, {}, {}))
        self.assertEqual(len(http.requests), 2)
        self.assertEqual(cause["decision"], {"decided_by": "unclassified"})
        self.assertTrue(warnings)

    def test_unknown_option_is_rejected(self):
        cause, _, _ = self.run_jev(jev_answer("delete_everything", 0.99))
        self.assertEqual(cause["category"], "other")

    def test_state_sent_to_jev_contains_no_device_or_user_data(self):
        cause = report_with("CustomCompliance.VpnInstalled")["causes"][0]
        sent = repr(jev_state(cause))
        self.assertNotIn("SECRET", sent)
        self.assertNotIn("secret.user", sent)
        self.assertEqual(set(jev_state(cause)["cause"]),
                         {"setting", "setting_name", "platforms", "states", "share_not_recently_synced"})


if __name__ == "__main__":
    unittest.main()
