"""Decide the remediation path for each root cause.

Built-in rules cover the standard Intune compliance settings. Anything else,
such as custom compliance settings with arbitrary names, can go to Jev, a typed
decision model from TypeSafe. Jev receives only the setting identifier,
platforms, state counts and the share of devices that stopped syncing. It never
receives device names, user names or error text.
"""

import json
import os
import re
import time
import urllib.error
import urllib.request

CATEGORIES = {
    "device_configuration": {
        "label": "Configure devices",
        "next": "Deploy or repair the configuration profile or security feature this setting checks, then confirm on one affected device before rolling out.",
    },
    "user_action": {
        "label": "Ask users",
        "next": "Tell the affected users what to change, or enforce it with an update ring or policy, and set a deadline that matches the grace period.",
    },
    "policy_assignment": {
        "label": "Fix policy",
        "next": "Check which compliance policies target these devices and resolve missing assignments or conflicting settings.",
    },
    "stale_or_orphaned": {
        "label": "Clean up devices",
        "next": "Confirm the devices are no longer in use, then retire them or reconnect their owners. These devices will not report a fix until they check in.",
    },
    "security_investigation": {
        "label": "Investigate risk",
        "next": "Send these devices to whoever owns endpoint security; the setting reports a risk signal rather than a configuration gap.",
    },
    "other": {
        "label": "Review",
        "next": "Read the setting definition in the compliance policy and decide who owns the fix.",
    },
}

# (pattern over "setting settingName", category, title). First match wins.
RULES = [
    (r"requireremaincontact|isactive", "stale_or_orphaned", "Device stopped checking in"),
    (r"requireuserexistence|userexist", "stale_or_orphaned", "Enrolled user no longer exists"),
    (r"requiredevicecompliancepolicyassigned|policyassigned", "policy_assignment", "No compliance policy assigned"),
    (r"bitlocker", "device_configuration", "BitLocker not enabled"),
    (r"filevault", "device_configuration", "FileVault not enabled"),
    (r"storagerequireencryption|requireencryption", "device_configuration", "Disk encryption not enabled"),
    (r"secureboot", "device_configuration", "Secure Boot not enabled"),
    (r"codeintegrity", "device_configuration", "Code integrity not enabled"),
    (r"\btpm|tpmrequired", "device_configuration", "TPM not present or ready"),
    (r"firewall", "device_configuration", "Firewall not enabled"),
    (r"antivirus|antispyware|defender|signatureoutofdate|rtpenabled", "device_configuration", "Antivirus not healthy"),
    (r"threatprotection|threatlevel|securitylevel", "security_investigation", "Threat level above allowed"),
    (r"jailbr|rooted|securityblockjailbroken", "security_investigation", "Jailbroken or rooted device"),
    (r"securitypatch", "user_action", "Security patch level too old"),
    (r"osminimum|minimumbuild|minimumversion|minandroid|osversion", "user_action", "OS below minimum version"),
    (r"osmaximum|maximumversion", "user_action", "OS above maximum version"),
    # Anchored to standard password settings so custom names like BiosPasswordSet fall through.
    (r"(passcode|password)(required|minimum|expiration|minutes|previous|block|complex|type|length)",
     "user_action", "Passcode requirement not met"),
]


def rule_for(cause):
    text = (cause.get("setting", "") + " " + cause.get("setting_name", "")).lower()
    for pattern, category, title in RULES:
        if re.search(pattern, text):
            return category, title
    return None


JEV_URL = "https://api.typesafe.ai/v1/systemone"
# Pinned to the version measured in docs/decision-model.md; override to test another.
JEV_MODEL = os.environ.get("INTUNE_WHY_JEV_MODEL", "jev-1.14.0")
CONFIDENCE_FLOOR = 0.6

JEV_QUESTION = {
    "type": "choice",
    "instructions": (
        "`cause` describes one Microsoft Intune compliance setting that is failing on managed devices. "
        "`cause.setting` is the setting identifier; custom compliance settings can have any name. "
        "Which remediation path usually resolves this setting?"
    ),
    "criteria": {
        "device_configuration": {
            "what": "An admin deploys or repairs device configuration or a security feature",
            "examples": ["disk encryption off", "firewall disabled", "required VPN client missing", "Secure Boot off"],
        },
        "user_action": {
            "what": "The device user must act on the device",
            "examples": ["install an OS update", "set a passcode", "restart to finish an update"],
        },
        "policy_assignment": {
            "what": "The compliance policy itself is missing, mis-targeted or conflicting",
            "examples": ["no compliance policy assigned", "two policies conflict"],
        },
        "stale_or_orphaned": {
            "what": "The device stopped checking in or its user no longer exists",
            "not_for": "Devices that report in normally but fail a setting",
        },
        "security_investigation": {
            "what": "The setting reports a security risk signal that needs investigation",
            "examples": ["threat level too high", "jailbroken device", "unexpected local administrators"],
        },
        "other": None,
    },
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class JevClient:
    """Minimal client for TypeSafe's System One endpoint (stdlib only)."""

    def __init__(self, api_key, model=JEV_MODEL, timeout=8.0, opener=None, sleep=time.sleep):
        if not api_key:
            raise ValueError("TYPESAFE_API_KEY is not set")
        self._key = api_key
        self.model = model
        self.timeout = timeout
        self._open = opener or urllib.request.build_opener(_NoRedirect()).open
        self._sleep = sleep

    def ask(self, state, questions, attempts=3):
        body = json.dumps({"model": self.model, "state": state, "questions": questions}).encode()
        for attempt in range(attempts):
            req = urllib.request.Request(
                JEV_URL, data=body, method="POST",
                headers={"Authorization": "Bearer " + self._key, "Content-Type": "application/json"},
            )
            try:
                with self._open(req, timeout=self.timeout) as resp:
                    return json.load(resp)
            except urllib.error.HTTPError as exc:
                if exc.code in (429, 529) and attempt + 1 < attempts:
                    self._sleep(min(float(exc.headers.get("retry-after") or 2 ** attempt), 10.0))
                    continue
                raise RuntimeError("Jev request failed with HTTP %d" % exc.code) from None
            except (urllib.error.URLError, OSError) as exc:
                if attempt + 1 < attempts:
                    self._sleep(2 ** attempt)
                    continue
                raise RuntimeError("Jev request failed: " + type(exc).__name__) from None
        raise RuntimeError("Jev request failed")


def jev_state(cause):
    """The only data sent to Jev: no device, user or error text."""
    affected = max(cause["affected"], 1)
    return {"cause": {
        "setting": cause["setting"],
        "setting_name": cause["setting_name"],
        "platforms": sorted(cause["platforms"]),
        "states": cause["states"],
        "share_not_recently_synced": round(cause["not_recently_synced"] / affected, 2),
    }}


def decide_with_jev(cause, client):
    answer = client.ask(jev_state(cause), {"path": JEV_QUESTION})
    result = answer["answers"]["path"]
    choice, confidence = result.get("choice"), float(result.get("confidence") or 0.0)
    if choice not in CATEGORIES:
        raise RuntimeError("Jev returned an unknown option")
    return {
        "category": choice if confidence >= CONFIDENCE_FLOOR else "other",
        "proposed": choice,
        "confidence": round(confidence, 3),
        "model": answer.get("model", client.model),
        "decided_by": "jev" if confidence >= CONFIDENCE_FLOOR else "jev-low-confidence",
    }


def classify(report, decider="rules", client=None, warn=None):
    """Attach category, title and decision provenance to every cause."""
    if decider not in ("rules", "jev"):
        raise ValueError("decider must be rules or jev")
    if decider == "jev" and os.environ.get("INTUNE_WHY_DISABLE_JEV") == "1":
        decider = "rules"
    if decider == "jev" and client is None:
        client = JevClient(os.environ.get("TYPESAFE_API_KEY", ""))
    for cause in report["causes"]:
        rule = rule_for(cause)
        if rule:
            cause["category"], cause["title"] = rule
            cause["decision"] = {"decided_by": "rule"}
            continue
        if decider == "jev":
            try:
                decision = decide_with_jev(cause, client)
                cause["category"] = decision["category"]
                cause["decision"] = decision
                continue
            except (RuntimeError, KeyError, TypeError, ValueError) as exc:
                if warn:
                    warn("Jev could not classify %s (%s); marked for review" % (cause["setting"], exc))
        cause["category"] = "other"
        cause["decision"] = {"decided_by": "unclassified"}
    for cause in report["causes"]:
        cause["category_label"] = CATEGORIES[cause["category"]]["label"]
        cause["next_step"] = CATEGORIES[cause["category"]]["next"]
    _disambiguate_titles(report["causes"])
    report["decider"] = decider
    return report


def _disambiguate_titles(causes):
    """Add the platform when two causes would otherwise share a title."""
    counts = {}
    for cause in causes:
        counts[cause["title"]] = counts.get(cause["title"], 0) + 1
    for cause in causes:
        if counts[cause["title"]] > 1 and len(cause["platforms"]) == 1:
            cause["title"] += " (%s)" % next(iter(cause["platforms"]))
