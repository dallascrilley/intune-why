#!/usr/bin/env python3
"""Shadow-run Jev against labeled compliance settings.

Labels are the maintainer's judgment of the usual remediation path. Every
setting gets the same neutral counts (share_not_recently_synced 0.1), so Jev
judges from the setting identifier alone. Writes one JSONL record per call and
prints a Markdown summary. Needs TYPESAFE_API_KEY.
"""

import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from intune_why.classify import CONFIDENCE_FLOOR, JEV_QUESTION, JevClient, jev_state, rule_for  # noqa: E402

LABELS = [
    ("Windows10CompliancePolicy.BitLockerEnabled", "device_configuration"),
    ("Windows10CompliancePolicy.SecureBootEnabled", "device_configuration"),
    ("Windows10CompliancePolicy.CodeIntegrityEnabled", "device_configuration"),
    ("Windows10CompliancePolicy.StorageRequireEncryption", "device_configuration"),
    ("Windows10CompliancePolicy.ActiveFirewallRequired", "device_configuration"),
    ("Windows10CompliancePolicy.DefenderEnabled", "device_configuration"),
    ("Windows10CompliancePolicy.AntivirusRequired", "device_configuration"),
    ("Windows10CompliancePolicy.TpmRequired", "device_configuration"),
    ("Windows10CompliancePolicy.OsMinimumVersion", "user_action"),
    ("Windows10CompliancePolicy.PasswordRequired", "user_action"),
    ("Windows10CompliancePolicy.DeviceThreatProtectionRequiredSecurityLevel", "security_investigation"),
    ("IosCompliancePolicy.OsMinimumVersion", "user_action"),
    ("IosCompliancePolicy.PasscodeRequired", "user_action"),
    ("IosCompliancePolicy.SecurityBlockJailbrokenDevices", "security_investigation"),
    ("AndroidWorkProfileCompliancePolicy.PasswordRequired", "user_action"),
    ("AndroidWorkProfileCompliancePolicy.MinAndroidSecurityPatchLevel", "user_action"),
    ("AndroidWorkProfileCompliancePolicy.SecurityBlockJailbrokenDevices", "security_investigation"),
    ("MacOSCompliancePolicy.StorageRequireEncryption", "device_configuration"),
    ("MacOSCompliancePolicy.FirewallEnabled", "device_configuration"),
    ("MacOSCompliancePolicy.OsMinimumVersion", "user_action"),
    ("DefaultDeviceCompliancePolicy.RequireRemainContact", "stale_or_orphaned"),
    ("DefaultDeviceCompliancePolicy.RequireDeviceCompliancePolicyAssigned", "policy_assignment"),
    ("DefaultDeviceCompliancePolicy.RequireUserExistence", "stale_or_orphaned"),
    ("CustomCompliance.ApprovedVpnClientInstalled", "device_configuration"),
    ("CustomCompliance.LocalAdministratorsWithinLimit", "security_investigation"),
    ("CustomCompliance.BiosPasswordSet", "device_configuration"),
    ("CustomCompliance.PendingRebootOver7Days", "user_action"),
    ("CustomCompliance.CrowdStrikeSensorRunning", "device_configuration"),
    ("CustomCompliance.EdrSensorReportsHighRisk", "security_investigation"),
    ("CustomCompliance.LastIntuneCheckInWithin30Days", "stale_or_orphaned"),
    ("CustomCompliance.PrimaryUserAccountDisabled", "stale_or_orphaned"),
    ("CustomCompliance.LapsPasswordBackedUp", "device_configuration"),
    ("CustomCompliance.UnapprovedRemoteAccessToolInstalled", "security_investigation"),
    ("CustomCompliance.WindowsUpdateRingAssigned", "policy_assignment"),
    ("CustomCompliance.ConflictingCompliancePolicies", "policy_assignment"),
    ("CustomCompliance.UserAcceptedTermsOfUse", "user_action"),
    ("CustomCompliance.UsbStorageBlocked", "device_configuration"),
    ("CustomCompliance.SuspiciousProcessDetected", "security_investigation"),
    ("CustomCompliance.OneDriveKnownFolderMoveEnabled", "device_configuration"),
    ("CustomCompliance.MfaRegisteredForPrimaryUser", "user_action"),
]


def platform(setting):
    for prefix, name in (("Windows10", "Windows"), ("Ios", "iOS"), ("Android", "Android"), ("MacOS", "macOS"), ("Custom", "Windows")):
        if setting.startswith(prefix):
            return [name]
    return ["Windows", "iOS", "Android", "macOS"]


def main():
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "shadow-run.jsonl")
    client = JevClient(os.environ.get("TYPESAFE_API_KEY", ""), model=os.environ.get("INTUNE_WHY_JEV_MODEL", "jev-1.14.0"))
    rows = []
    with out.open("w", encoding="utf-8") as log:
        for setting, label in LABELS:
            cause = {"setting": setting, "setting_name": setting.split(".", 1)[1], "platforms": dict.fromkeys(platform(setting), 10),
                     "states": {"nonCompliant": 10}, "affected": 10, "not_recently_synced": 1}
            t0 = time.monotonic()
            answer = client.ask(jev_state(cause), {"path": JEV_QUESTION})
            latency = round((time.monotonic() - t0) * 1000)
            result = answer["answers"]["path"]
            rule = rule_for(cause)
            row = {"setting": setting, "label": label, "custom": setting.startswith("Custom"),
                   "jev": result["choice"], "confidence": result["confidence"], "probabilities": result["probabilities"],
                   "rule": rule[0] if rule else None, "model": answer.get("model"), "latency_ms": latency,
                   "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
            rows.append(row)
            log.write(json.dumps(row) + "\n")

    def summarize(subset):
        n = len(subset)
        agree = sum(r["jev"] == r["label"] for r in subset)
        gated = [r for r in subset if r["confidence"] >= CONFIDENCE_FLOOR]
        gated_agree = sum(r["jev"] == r["label"] for r in gated)
        return n, agree, len(gated), gated_agree

    print("| Set | Settings | Jev agrees | At or above %.2f confidence | Agreement when accepted |" % CONFIDENCE_FLOOR)
    print("|---|---|---|---|---|")
    for name, subset in (("Standard settings", [r for r in rows if not r["custom"]]),
                         ("Custom settings", [r for r in rows if r["custom"]]), ("All", rows)):
        n, agree, g, ga = summarize(subset)
        print("| %s | %d | %d (%d%%) | %d | %d of %d |" % (name, n, agree, round(100 * agree / n), g, ga, g))
    covered = [r for r in rows if r["rule"]]
    print("\nBuilt-in rules cover %d of %d settings and agree with the label on %d." % (
        len(covered), len(rows), sum(r["rule"] == r["label"] for r in covered)))
    print("\nModel: %s. Median latency %d ms." % (rows[0]["model"], sorted(r["latency_ms"] for r in rows)[len(rows) // 2]))
    print("\nDisagreements:")
    for r in rows:
        if r["jev"] != r["label"]:
            print("- `%s`: labeled %s, Jev chose %s (%.2f)" % (r["setting"], r["label"], r["jev"], r["confidence"]))


if __name__ == "__main__":
    main()
