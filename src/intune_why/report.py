"""Render an analyzed report as text, JSON, CSV or a self-contained HTML page."""

import csv
import hashlib
import io
import json
import secrets
from pathlib import Path

TEMPLATE = Path(__file__).with_name("templates") / "report.html"


def redact(report, salt=None):
    """Replace device and user names with stable per-run pseudonyms for sharing."""
    salt = salt or secrets.token_hex(8)

    def alias(prefix, value):
        if not value:
            return value
        return "%s-%s" % (prefix, hashlib.sha256((salt + value).encode()).hexdigest()[:6])

    for device in report["devices"].values():
        device["name"] = alias("device", device["name"])
        device["user"] = alias("user", device["user"])
    report["tenant"] = None
    report["redacted"] = True
    return report


def pct(part, whole):
    return 0 if not whole else round(100.0 * part / whole)


def headline(report, steps=3):
    totals, plan = report["totals"], report["plan"][:steps]
    if not totals["needs_attention"] or not plan:
        return "No noncompliant devices with setting detail in this snapshot."
    return "%d %s raise compliance from %d%% to %d%%." % (
        len(plan), "fix" if len(plan) == 1 else "fixes",
        pct(totals["compliant"], totals["devices"]), pct(plan[-1]["compliant_after"], totals["devices"]))


def to_text(report, limit=10):
    t = report["totals"]
    lines = [
        "intune-why  %d devices  %d%% compliant  %d need attention" % (
            t["devices"], pct(t["compliant"], t["devices"]), t["needs_attention"]),
        headline(report),
        "",
        "  #  Root cause                              Devices  Clears  Compliant after  Action",
    ]
    by_id = {c["id"]: c for c in report["causes"]}
    for i, step in enumerate(report["plan"][:limit], 1):
        c = by_id[step["cause"]]
        how = c["decision"]["decided_by"]
        if how.startswith("jev"):
            how = "jev %.2f" % c["decision"]["confidence"]
        lines.append("%3d  %-38s %8d %7d %15d%%  %s (%s)" % (
            i, c["title"][:38], c["affected"], step["newly_cleared"],
            pct(step["compliant_after"], t["devices"]), c["category_label"], how))
    if len(report["plan"]) > limit:
        lines.append("     ... %d more in the HTML or JSON report" % (len(report["plan"]) - limit))
    if t["unexplained"]:
        lines.append("")
        lines.append("%d noncompliant devices had no failing setting detail; check them in the Intune portal." % t["unexplained"])
    if t["unmatched_setting_states"]:
        lines.append("%d failing setting states referenced devices missing from the device list." % t["unmatched_setting_states"])
    lines.append("")
    lines.append("Clears: devices that become fully compliant at that step. Projections assume each fix resolves the setting.")
    return "\n".join(lines)


def to_csv(report):
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["plan_rank", "root_cause", "setting", "action", "device", "platform", "user", "last_sync", "other_failing_settings"])
    for cause in report["causes"]:
        for d_id in cause["devices"]:
            d = report["devices"][d_id]
            writer.writerow([cause["plan_rank"]] + [_cell(v) for v in (
                cause["title"], cause["setting"], cause["category_label"], d["name"], d["platform"], d["user"], d["last_sync"])]
                + [len(d["causes"]) - 1])
    return out.getvalue()


def _cell(value):
    """Keep spreadsheet apps from evaluating tenant-supplied text as a formula."""
    text = str(value or "")
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def to_html(report):
    template = TEMPLATE.read_text(encoding="utf-8")
    if template.count("__REPORT_DATA__") != 1:
        raise ValueError("Invalid report template")
    payload = json.dumps(report, ensure_ascii=True, sort_keys=True)
    payload = payload.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    payload = payload.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    return template.replace("__REPORT_DATA__", payload)
