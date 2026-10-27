// Browser port of intune_why.analyze and the rule step of intune_why.classify.
// Pure functions, no DOM: script/cibuild checks that it produces the same report
// as the Python package for the demo tenant.

export const SNAPSHOT_SCHEMA = "intune-why/snapshot@1";
export const REPORT_SCHEMA = "intune-why/report@1";
const FAILING_STATES = new Set(["nonCompliant", "error", "conflict"]);
const NONCOMPLIANT_DEVICE_STATES = new Set(["noncompliant", "error", "conflict"]);
const DAY_MS = 86400000;

export class SnapshotError extends Error {}

export function parseTime(value) {
  if (typeof value !== "string" || !value) return null;
  // Same contract as Python: ISO 8601 with an explicit offset; years before 1990 mean "never".
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:\d{2})$/.test(value)) return null;
  const ms = Date.parse(value);
  if (Number.isNaN(ms) || Number(value.slice(0, 4)) < 1990) return null;
  return ms;
}

export function validateSnapshot(snapshot) {
  if (!snapshot || typeof snapshot !== "object" || Array.isArray(snapshot)) throw new SnapshotError("Snapshot must be a JSON object");
  if (snapshot.schema !== SNAPSHOT_SCHEMA) throw new SnapshotError("Unsupported snapshot schema; expected " + SNAPSHOT_SCHEMA);
  if (parseTime(snapshot.collected_at) === null) throw new SnapshotError("collected_at must be an ISO timestamp with a timezone");
  const { devices, setting_states: states } = snapshot;
  if (!Array.isArray(devices) || !Array.isArray(states)) throw new SnapshotError("Snapshot needs devices and setting_states arrays");
  const seen = new Set();
  for (const d of devices) {
    if (!d || typeof d !== "object" || typeof d.id !== "string" || !d.id) throw new SnapshotError("Every device needs a non-empty string id");
    if (seen.has(d.id)) throw new SnapshotError("Duplicate device id: " + d.id);
    seen.add(d.id);
  }
  for (const s of states) {
    if (!s || typeof s !== "object") throw new SnapshotError("Every setting state must be an object");
    for (const f of ["device_id", "setting", "state"]) {
      if (typeof s[f] !== "string" || !s[f]) throw new SnapshotError("Every setting state needs a string " + f);
    }
  }
  return snapshot;
}

const isSubset = (a, b) => [...a].every((x) => b.has(x));
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

export function fixPlan(deviceCauses) {
  const remaining = [...deviceCauses.values()].filter((c) => c.size);
  const candidates = new Set();
  for (const c of remaining) for (const x of c) candidates.add(x);
  const fixed = new Set();
  const plan = [];
  let cleared = 0;
  while (fixed.size < candidates.size) {
    let best = null;
    for (const cause of candidates) {
      if (fixed.has(cause)) continue;
      const withCause = new Set([...fixed, cause]);
      let newly = 0, affected = 0;
      for (const c of remaining) {
        if (c.has(cause)) {
          affected++;
          if (isSubset(c, withCause)) newly++;
        }
      }
      // Same order as Python's sort on (-newly, -affected, cause).
      const key = [-newly, -affected, cause];
      if (!best || key[0] - best[0] < 0 || (key[0] === best[0] && (key[1] - best[1] < 0 || (key[1] === best[1] && cmp(key[2], best[2]) < 0)))) best = key;
    }
    fixed.add(best[2]);
    cleared += -best[0];
    plan.push({ cause: best[2], newly_cleared: -best[0], cumulative_cleared: cleared });
  }
  return plan;
}

function humanize(name) {
  let out = "";
  for (let i = 0; i < name.length; i++) {
    const ch = name[i];
    const up = (c) => c && c !== c.toLowerCase() && c === c.toUpperCase();
    const low = (c) => c && c !== c.toUpperCase() && c === c.toLowerCase();
    if (i && up(ch) && (!up(name[i - 1]) || (i + 1 < name.length && low(name[i + 1])))) out += " ";
    out += ch;
  }
  const text = out.replace(/_/g, " ").trim();
  return text ? text[0].toUpperCase() + text.slice(1) : name;
}

// Counter.most_common(): count descending, ties in first-seen order.
function mostCommon(counter) {
  return [...counter.entries()].map((e, i) => [e, i]).sort((a, b) => b[0][1] - a[0][1] || a[1] - b[1]).map((x) => x[0]);
}
const bump = (m, k) => m.set(k, (m.get(k) || 0) + 1);

export function analyze(snapshot, staleDays = 30) {
  validateSnapshot(snapshot);
  if (staleDays < 1) throw new SnapshotError("stale_days must be at least 1");
  const now = parseTime(snapshot.collected_at);
  const devices = new Map(snapshot.devices.map((d) => [d.id, d]));
  const causes = new Map();
  const deviceCauses = new Map();
  let unmatched = 0;
  for (const state of snapshot.setting_states) {
    if (!FAILING_STATES.has(state.state)) continue;
    const deviceId = state.device_id;
    if (!devices.has(deviceId)) { unmatched++; continue; }
    const key = state.setting;
    let cause = causes.get(key);
    if (!cause) {
      const name = state.setting_name || key.split(".").pop();
      cause = { id: key, setting: key, setting_name: name, title: humanize(name), platforms: new Map(), states: new Map(), errors: new Map(), devices: new Set() };
      causes.set(key, cause);
    }
    if (cause.devices.has(deviceId)) continue;
    cause.devices.add(deviceId);
    bump(cause.states, state.state);
    bump(cause.platforms, devices.get(deviceId).platform || state.platform || "Unknown");
    if (state.error) bump(cause.errors, String(state.error).slice(0, 200));
    if (!deviceCauses.has(deviceId)) deviceCauses.set(deviceId, new Set());
    deviceCauses.get(deviceId).add(key);
  }
  const isStale = (d) => {
    const last = parseTime(d.last_sync);
    return last === null || now - last > staleDays * DAY_MS;
  };
  const unexplained = [...devices.keys()].filter((id) => NONCOMPLIANT_DEVICE_STATES.has(String(devices.get(id).compliance_state || "").toLowerCase()) && !deviceCauses.has(id)).sort(cmp);
  const needs = new Set([...deviceCauses.keys(), ...unexplained]);
  const total = devices.size;
  const plan = fixPlan(deviceCauses);
  const rank = new Map(plan.map((s, i) => [s.cause, i + 1]));
  for (const step of plan) step.compliant_after = total - needs.size + step.cumulative_cleared;

  const causeList = [...causes.values()].map((c) => {
    const nameOf = (id) => devices.get(id).name || id;
    const affected = [...c.devices].sort((a, b) => cmp(nameOf(a), nameOf(b)));
    const only = (id) => deviceCauses.get(id).size === 1 && deviceCauses.get(id).has(c.id);
    return {
      id: c.id, setting: c.setting, setting_name: c.setting_name, title: c.title,
      affected: affected.length,
      clears_alone: affected.filter(only).length,
      not_recently_synced: affected.filter((id) => isStale(devices.get(id))).length,
      users: new Set(affected.map((id) => devices.get(id).user).filter(Boolean)).size,
      platforms: Object.fromEntries(mostCommon(c.platforms)),
      states: Object.fromEntries(mostCommon(c.states)),
      top_errors: mostCommon(c.errors).slice(0, 3).map((e) => e[0]),
      devices: affected,
      plan_rank: rank.get(c.id),
    };
  }).sort((a, b) => a.plan_rank - b.plan_rank);

  const index = {};
  for (const id of [...needs].sort(cmp)) {
    const d = devices.get(id);
    index[id] = {
      name: d.name || id, platform: d.platform || "Unknown", os_version: d.os_version || "", user: d.user || "",
      last_sync: d.last_sync || "", stale: isStale(d), causes: [...(deviceCauses.get(id) || [])].sort(cmp),
    };
  }
  return {
    schema: REPORT_SCHEMA, collected_at: snapshot.collected_at, source: snapshot.source ?? "unknown", tenant: snapshot.tenant ?? null,
    stale_days: staleDays,
    totals: { devices: total, needs_attention: needs.size, compliant: total - needs.size, explained: deviceCauses.size, unexplained: unexplained.length, unmatched_setting_states: unmatched },
    causes: causeList, plan, unexplained, devices: index,
  };
}

export function ruleFor(cause, rules) {
  const text = ((cause.setting || "") + " " + (cause.setting_name || "")).toLowerCase();
  for (const r of rules.rules) if (new RegExp(r.pattern).test(text)) return [r.category, r.title];
  return null;
}

// Rule step plus optional decisions supplied by the caller (for example from Jev).
export function classify(report, rules, decisions = {}) {
  for (const cause of report.causes) {
    const rule = ruleFor(cause, rules);
    if (rule) {
      [cause.category, cause.title] = rule;
      cause.decision = { decided_by: "rule" };
    } else if (decisions[cause.id]) {
      cause.decision = decisions[cause.id];
      cause.category = cause.decision.category;
    } else {
      cause.category = "other";
      cause.decision = { decided_by: "unclassified" };
    }
  }
  for (const cause of report.causes) {
    cause.category_label = rules.categories[cause.category].label;
    cause.next_step = rules.categories[cause.category].next;
  }
  const counts = new Map();
  for (const c of report.causes) bump(counts, c.title);
  for (const c of report.causes) {
    const platforms = Object.keys(c.platforms);
    if (counts.get(c.title) > 1 && platforms.length === 1) c.title += " (" + platforms[0] + ")";
  }
  report.decider = Object.keys(decisions).length ? "jev" : "rules";
  return report;
}

export function unclassified(report, rules) {
  return report.causes.filter((c) => !ruleFor(c, rules));
}

// The only data sent to Jev: no device, user or error text.
export function jevState(cause) {
  const affected = Math.max(cause.affected, 1);
  return { cause: {
    setting: cause.setting, setting_name: cause.setting_name, platforms: Object.keys(cause.platforms).sort(),
    states: cause.states, share_not_recently_synced: Math.round((cause.not_recently_synced / affected) * 100) / 100,
  } };
}

export function decisionFromAnswer(answer, rules, model) {
  const r = answer?.answers?.path;
  if (!r || !(r.choice in rules.categories)) throw new Error("Jev returned an unexpected answer");
  const confidence = Number(r.confidence || 0);
  const ok = confidence >= rules.confidence_floor;
  return { category: ok ? r.choice : "other", proposed: r.choice, confidence: Math.round(confidence * 1000) / 1000, model: answer.model || model, decided_by: ok ? "jev" : "jev-low-confidence" };
}

export function reportHtml(template, report) {
  const payload = JSON.stringify(report).replace(/</g, "\\u003c").replace(/>/g, "\\u003e").replace(/&/g, "\\u0026").replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029");
  if (template.split("__REPORT_DATA__").length !== 2) throw new Error("Invalid report template");
  return template.replace("__REPORT_DATA__", () => payload);
}
