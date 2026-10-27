"""Decide the remediation path for each root cause.

Built-in rules cover the standard Intune compliance settings. Anything else,
such as custom compliance settings with arbitrary names, can go to Jev, a typed
decision model from TypeSafe, through OpenRouter's Decisions API. Jev receives
only the setting identifier, platforms, state counts and the share of devices
that stopped syncing. It never receives device names, user names or error text.
"""

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

_RULES_FILE = Path(__file__).with_name("data") / "rules.json"
_SHARED = json.loads(_RULES_FILE.read_text(encoding="utf-8"))  # also used by the web demo
CATEGORIES = _SHARED["categories"]
# (pattern over "setting settingName", category, title). First match wins.
RULES = [(r["pattern"], r["category"], r["title"]) for r in _SHARED["rules"]]


def rule_for(cause):
    text = (cause.get("setting", "") + " " + cause.get("setting_name", "")).lower()
    for pattern, category, title in RULES:
        if re.search(pattern, text):
            return category, title
    return None


JEV_URL = "https://openrouter.ai/api/alpha/decisions"
# Pinned to the release measured in docs/decision-model.md; override to test another.
JEV_MODEL = os.environ.get("INTUNE_WHY_JEV_MODEL", "typesafe/jev-1.14")
CONFIDENCE_FLOOR = _SHARED["confidence_floor"]

JEV_QUESTION = _SHARED["jev_question"]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class JevClient:
    """Minimal client for OpenRouter's Decisions API (stdlib only)."""

    def __init__(self, api_key, model=JEV_MODEL, timeout=8.0, opener=None, sleep=time.sleep):
        if not api_key:
            raise ValueError("OPENROUTER_API_KEY is not set")
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
                headers={"Authorization": "Bearer " + self._key, "Content-Type": "application/json",
                         "HTTP-Referer": "https://github.com/dallascrilley/intune-why", "X-Title": "intune-why"},
            )
            try:
                with self._open(req, timeout=self.timeout) as resp:
                    return json.load(resp)
            except urllib.error.HTTPError as exc:
                if exc.code in (429, 502, 503, 529) and attempt + 1 < attempts:
                    self._sleep(min(float(exc.headers.get("retry-after") or 2 ** attempt), 10.0))
                    continue
                hint = {401: "check OPENROUTER_API_KEY", 402: "add OpenRouter credits",
                        404: "the model may be blocked by your OpenRouter guardrails"}.get(exc.code)
                raise RuntimeError("Jev request failed with HTTP %d%s" % (exc.code, "; " + hint if hint else "")) from None
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
        client = JevClient(os.environ.get("OPENROUTER_API_KEY", ""))
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
