"""Root-cause analysis for an Intune compliance snapshot.

A snapshot lists managed devices and the compliance setting states that are
failing on them. Analysis groups failures by setting, then builds a greedy fix
plan: each step picks the setting whose fix makes the most additional devices
fully compliant. A device counts as cleared only when every failing setting on
it has been fixed.
"""

import datetime as dt
from collections import Counter, defaultdict

SNAPSHOT_SCHEMA = "intune-why/snapshot@1"
REPORT_SCHEMA = "intune-why/report@1"
FAILING_STATES = ("nonCompliant", "error", "conflict")
NONCOMPLIANT_DEVICE_STATES = ("noncompliant", "error", "conflict")


class SnapshotError(ValueError):
    """The snapshot is missing required data or contradicts itself."""


def parse_time(value):
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    # Intune reports 0001-01-01 for devices that never synced.
    if parsed.year < 1990:
        return None
    return parsed.astimezone(dt.timezone.utc)


def validate_snapshot(snapshot):
    if not isinstance(snapshot, dict):
        raise SnapshotError("Snapshot must be a JSON object")
    if snapshot.get("schema") != SNAPSHOT_SCHEMA:
        raise SnapshotError("Unsupported snapshot schema; expected " + SNAPSHOT_SCHEMA)
    if parse_time(snapshot.get("collected_at")) is None:
        raise SnapshotError("collected_at must be an ISO timestamp with a timezone")
    devices = snapshot.get("devices")
    states = snapshot.get("setting_states")
    if not isinstance(devices, list) or not isinstance(states, list):
        raise SnapshotError("Snapshot needs devices and setting_states arrays")
    seen = set()
    for device in devices:
        if not isinstance(device, dict) or not isinstance(device.get("id"), str) or not device["id"]:
            raise SnapshotError("Every device needs a non-empty string id")
        if device["id"] in seen:
            raise SnapshotError("Duplicate device id: " + device["id"])
        seen.add(device["id"])
    for state in states:
        if not isinstance(state, dict):
            raise SnapshotError("Every setting state must be an object")
        for field in ("device_id", "setting", "state"):
            if not isinstance(state.get(field), str) or not state[field]:
                raise SnapshotError("Every setting state needs a string " + field)
    return snapshot


def fix_plan(device_causes):
    """Order causes so each step clears the most additional devices.

    When no single fix clears a device (every remaining device fails several
    settings), the step picks the cause that touches the most uncleared
    devices so later steps can clear them. Ties break by name for stable output.
    """
    remaining = {device: set(causes) for device, causes in device_causes.items() if causes}
    candidates = set()
    for causes in remaining.values():
        candidates |= causes
    fixed, plan, cleared = set(), [], 0
    while candidates - fixed:
        scored = []
        for cause in candidates - fixed:
            newly = affected = 0
            for causes in remaining.values():
                if cause in causes:
                    affected += 1
                    if causes <= fixed | {cause}:
                        newly += 1
            scored.append((-newly, -affected, cause))
        scored.sort()
        newly, _, cause = -scored[0][0], scored[0][1], scored[0][2]
        fixed.add(cause)
        cleared += newly
        plan.append({"cause": cause, "newly_cleared": newly, "cumulative_cleared": cleared})
    return plan


def _humanize(name):
    out = []
    for i, ch in enumerate(name):
        if i and ch.isupper() and (not name[i - 1].isupper() or (i + 1 < len(name) and name[i + 1].islower())):
            out.append(" ")
        out.append(ch)
    text = "".join(out).replace("_", " ").strip()
    return text[:1].upper() + text[1:] if text else name


def analyze(snapshot, stale_days=30):
    validate_snapshot(snapshot)
    if stale_days < 1:
        raise SnapshotError("stale_days must be at least 1")
    now = parse_time(snapshot["collected_at"])
    devices = {d["id"]: d for d in snapshot["devices"]}
    causes = {}
    device_causes = defaultdict(set)
    unmatched = 0
    for state in snapshot["setting_states"]:
        if state["state"] not in FAILING_STATES:
            continue
        device_id = state["device_id"]
        if device_id not in devices:
            unmatched += 1
            continue
        key = state["setting"]
        cause = causes.get(key)
        if cause is None:
            name = state.get("setting_name") or key.rsplit(".", 1)[-1]
            cause = causes[key] = {
                "id": key,
                "setting": key,
                "setting_name": name,
                "title": _humanize(name),
                "platforms": Counter(),
                "states": Counter(),
                "errors": Counter(),
                "devices": set(),
            }
        if device_id in cause["devices"]:
            continue
        cause["devices"].add(device_id)
        cause["states"][state["state"]] += 1
        cause["platforms"][devices[device_id].get("platform") or state.get("platform") or "Unknown"] += 1
        if state.get("error"):
            cause["errors"][str(state["error"])[:200]] += 1
        device_causes[device_id].add(key)

    def is_stale(device):
        last = parse_time(device.get("last_sync"))
        return last is None or (now - last) > dt.timedelta(days=stale_days)

    unexplained = sorted(
        d_id for d_id, d in devices.items()
        if str(d.get("compliance_state", "")).lower() in NONCOMPLIANT_DEVICE_STATES and d_id not in device_causes
    )
    needs = set(device_causes) | set(unexplained)
    total = len(devices)
    plan = fix_plan(device_causes)
    rank = {step["cause"]: i + 1 for i, step in enumerate(plan)}
    for step in plan:
        step["compliant_after"] = total - len(needs) + step["cumulative_cleared"]

    cause_list = []
    for key, cause in causes.items():
        affected = sorted(cause["devices"], key=lambda d: (devices[d].get("name") or d))
        cause_list.append({
            "id": key,
            "setting": cause["setting"],
            "setting_name": cause["setting_name"],
            "title": cause["title"],
            "affected": len(affected),
            "clears_alone": sum(1 for d in affected if device_causes[d] == {key}),
            "not_recently_synced": sum(1 for d in affected if is_stale(devices[d])),
            "users": len({devices[d].get("user") for d in affected if devices[d].get("user")}),
            "platforms": dict(cause["platforms"].most_common()),
            "states": dict(cause["states"].most_common()),
            "top_errors": [e for e, _ in cause["errors"].most_common(3)],
            "devices": affected,
            "plan_rank": rank[key],
        })
    cause_list.sort(key=lambda c: c["plan_rank"])

    index = {}
    for d_id in sorted(needs):
        d = devices[d_id]
        index[d_id] = {
            "name": d.get("name") or d_id,
            "platform": d.get("platform") or "Unknown",
            "os_version": d.get("os_version") or "",
            "user": d.get("user") or "",
            "last_sync": d.get("last_sync") or "",
            "stale": is_stale(d),
            "causes": sorted(device_causes.get(d_id, ())),
        }

    return {
        "schema": REPORT_SCHEMA,
        "collected_at": snapshot["collected_at"],
        "source": snapshot.get("source", "unknown"),
        "tenant": snapshot.get("tenant"),
        "stale_days": stale_days,
        "totals": {
            "devices": total,
            "needs_attention": len(needs),
            "compliant": total - len(needs),
            "explained": len(device_causes),
            "unexplained": len(unexplained),
            "unmatched_setting_states": unmatched,
        },
        "causes": cause_list,
        "plan": plan,
        "unexplained": unexplained,
        "devices": index,
    }
