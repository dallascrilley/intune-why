// The browser port must produce the same rule-mode report as the Python package.
// Run by script/cibuild with the installed package's JSON report on stdin.
import { readFileSync } from "node:fs";
import { test } from "node:test";
import assert from "node:assert/strict";
import { analyze, classify, fixPlan, parseTime, SnapshotError } from "./core.js";

const root = new URL("../src/intune_why/data/", import.meta.url);
const rules = JSON.parse(readFileSync(new URL("rules.json", root)));
const demo = JSON.parse(readFileSync(new URL("demo_snapshot.json", root)));

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((k) => [k, canonical(value[k])]));
  return value;
}

test("matches the Python report for the demo tenant", { skip: !process.env.PY_REPORT && "set PY_REPORT to a Python JSON report" }, () => {
  const expected = JSON.parse(readFileSync(process.env.PY_REPORT, "utf8"));
  const actual = classify(analyze(demo), rules);
  assert.deepEqual(canonical(actual), canonical(expected));
});

test("fix plan matches the Python greedy order", () => {
  const sets = (o) => new Map(Object.entries(o).map(([k, v]) => [k, new Set(v)]));
  assert.deepEqual(fixPlan(sets({ a: ["x"], b: ["x", "y"], c: ["y"], d: ["z"], e: ["y"] })).map((s) => [s.cause, s.newly_cleared, s.cumulative_cleared]),
    [["y", 2, 2], ["x", 2, 4], ["z", 1, 5]]);
  assert.deepEqual(fixPlan(sets({ a: ["x", "y"], b: ["x", "z"] }))[0], { cause: "x", newly_cleared: 0, cumulative_cleared: 0 });
});

test("never-synced sentinel and naive timestamps are unknown", () => {
  assert.equal(parseTime("0001-01-01T00:00:00Z"), null);
  assert.equal(parseTime("2026-10-01T00:00:00"), null);
  assert.equal(typeof parseTime("2026-10-01T00:00:00.1234567Z"), "number");
});

test("rejects snapshots the Python package rejects", () => {
  assert.throws(() => analyze({ schema: "other" }), SnapshotError);
  assert.throws(() => analyze({ ...demo, devices: [demo.devices[0], demo.devices[0]] }), SnapshotError);
});
