#!/usr/bin/env python3
"""Generate the fictional demo tenant used by `intune-why demo`.

Deterministic: the same seed always writes the same snapshot. Every name is
invented; the domain is reserved for documentation (northwind.example).
"""

import datetime as dt
import json
import random
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "src" / "intune_why" / "data" / "demo_snapshot.json"
NOW = dt.datetime(2026, 10, 27, 15, 0, tzinfo=dt.timezone.utc)
rng = random.Random(20261027)

FIRST = "Avery Blake Casey Devon Emery Finley Harper Jordan Kendall Logan Morgan Parker Quinn Reese Riley Rowan Sawyer Skyler Taylor Jamie Alex Drew Elliot Hayden Jesse".split()
LAST = "Adams Brooks Chen Diaz Ellis Foster Garcia Hughes Ito Jensen Kim Lopez Moreno Nguyen Okafor Patel Ramos Silva Torres Underwood Vance Walsh Young Zhang".split()

S = {
    "bitlocker": ("Windows10CompliancePolicy.BitLockerEnabled", "BitLockerEnabled", "Windows10"),
    "win_os": ("Windows10CompliancePolicy.OsMinimumVersion", "OsMinimumVersion", "Windows10"),
    "secureboot": ("Windows10CompliancePolicy.SecureBootEnabled", "SecureBootEnabled", "Windows10"),
    "antivirus": ("Windows10CompliancePolicy.AntivirusRequired", "AntivirusRequired", "Windows10"),
    "threat": ("Windows10CompliancePolicy.DeviceThreatProtectionRequiredSecurityLevel", "DeviceThreatProtectionRequiredSecurityLevel", "Windows10"),
    "vpn": ("CustomCompliance.ApprovedVpnClientInstalled", "ApprovedVpnClientInstalled", "Windows10"),
    "localadmin": ("CustomCompliance.LocalAdministratorsWithinLimit", "LocalAdministratorsWithinLimit", "Windows10"),
    "active": ("DefaultDeviceCompliancePolicy.RequireRemainContact", "RequireRemainContact", "All"),
    "assigned": ("DefaultDeviceCompliancePolicy.RequireDeviceCompliancePolicyAssigned", "RequireDeviceCompliancePolicyAssigned", "All"),
    "user": ("DefaultDeviceCompliancePolicy.RequireUserExistence", "RequireUserExistence", "All"),
    "ios_os": ("IosCompliancePolicy.OsMinimumVersion", "OsMinimumVersion", "iOS"),
    "ios_passcode": ("IosCompliancePolicy.PasscodeRequired", "PasscodeRequired", "iOS"),
    "android_passcode": ("AndroidWorkProfileCompliancePolicy.PasswordRequired", "PasswordRequired", "AndroidWorkProfile"),
    "android_patch": ("AndroidWorkProfileCompliancePolicy.MinAndroidSecurityPatchLevel", "MinAndroidSecurityPatchLevel", "AndroidWorkProfile"),
    "filevault": ("MacOSCompliancePolicy.StorageRequireEncryption", "StorageRequireEncryption", "macOS"),
    "mac_os": ("MacOSCompliancePolicy.OsMinimumVersion", "OsMinimumVersion", "macOS"),
}

# Platform -> list of (count, causes). Remaining devices are compliant.
PLAN = {
    "Windows": (186, [
        (32, ["bitlocker"]), (4, ["bitlocker", "secureboot"]), (6, ["bitlocker", "win_os"]),
        (2, ["bitlocker", "vpn"]), (22, ["win_os"]), (2, ["win_os", "antivirus"]), (2, ["antivirus"]),
        (3, ["vpn"]), (2, ["localadmin"]), (2, ["threat"]), (10, ["active"]), (3, ["assigned"]),
        (2, ["user"]), (2, []),
    ]),
    "iOS": (66, [(6, ["ios_os"]), (1, ["ios_os", "ios_passcode"]), (1, ["ios_passcode"]), (3, ["active"]), (2, ["assigned"])]),
    "Android": (42, [(3, ["android_passcode"]), (2, ["android_patch"]), (3, ["active"]), (1, ["assigned"])]),
    "macOS": (26, [(3, ["filevault"]), (1, ["filevault", "mac_os"]), (1, ["mac_os"]), (2, ["active"])]),
}
PREFIX = {"Windows": "NW-LT", "iOS": "NW-IPH", "Android": "NW-AND", "macOS": "NW-MAC"}
OS_VERSION = {"Windows": ["10.0.22631.4317", "10.0.26100.2033", "10.0.19045.5011"], "iOS": ["18.0.1", "17.6.1", "18.1"],
              "Android": ["14", "13", "15"], "macOS": ["15.0.1", "14.7", "15.1"]}
ERRORS = {"bitlocker": "Encryption is not enabled on the OS drive", "antivirus": "Real-time protection is off"}


def stamp(days_ago):
    return (NOW - dt.timedelta(days=days_ago, minutes=rng.randint(0, 1400))).strftime("%Y-%m-%dT%H:%M:%SZ")


def main():
    users = ["%s.%s@northwind.example" % (f.lower(), l.lower()) for f in FIRST for l in LAST]
    rng.shuffle(users)
    devices, states, serial = [], [], 1000
    for platform, (total, groups) in PLAN.items():
        assigned = [causes for count, causes in groups for _ in range(count)]
        assigned += [None] * (total - len(assigned))
        rng.shuffle(assigned)
        for causes in assigned:
            serial += rng.randint(1, 9)
            dev_id = "%08x-%04x-4%03x-a%03x-%012x" % tuple(rng.getrandbits(b) for b in (32, 16, 12, 12, 48))
            stale = causes is not None and ("active" in causes or "user" in causes)
            last = stamp(rng.randint(34, 160)) if stale else stamp(rng.choice([0, 0, 1, 1, 2, 3, 5, 8]))
            if causes and "assigned" in causes and rng.random() < 0.4:
                last = "0001-01-01T00:00:00Z"
            devices.append({
                "id": dev_id,
                "name": "%s-%04d" % (PREFIX[platform], serial),
                "platform": platform,
                "os_version": rng.choice(OS_VERSION[platform]),
                "user": users.pop(),
                "last_sync": last,
                "compliance_state": "compliant" if causes is None else "noncompliant",
            })
            for key in causes or []:
                setting, name, policy_platform = S[key]
                state = "error" if key == "android_passcode" and rng.random() < 0.3 else "nonCompliant"
                entry = {"device_id": dev_id, "setting": setting, "setting_name": name, "platform": policy_platform, "state": state}
                if key in ERRORS:
                    entry["error"] = ERRORS[key]
                states.append(entry)
    snapshot = {
        "schema": "intune-why/snapshot@1",
        "source": "demo",
        "collected_at": NOW.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tenant": "northwind.example",
        "devices": devices,
        "setting_states": states,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(snapshot, indent=1) + "\n", encoding="utf-8")
    print("wrote %s: %d devices, %d failing setting states" % (OUT, len(devices), len(states)))


if __name__ == "__main__":
    main()
