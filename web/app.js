import "./vendor/byo-kit.js";
import { countNetworkCalls } from "./vendor/byo-kit.js";
import { analyze, classify, unclassified, jevState, decisionFromAnswer, reportHtml, SnapshotError } from "./core.js";

const JEV_URL = "https://openrouter.ai/api/alpha/decisions";
const JEV_MODEL = "typesafe/jev-1.14";

export const openrouter = {
  id: "openrouter",
  label: "OpenRouter",
  keyPattern: "^sk-or-v1-[A-Za-z0-9]{32,}$",
  docsUrl: "https://openrouter.ai/settings/keys",
  mode: "direct",
  endpoint: "https://openrouter.ai",
  auth: { header: "authorization", prefix: "Bearer " },
  headers: {},
  testPath: "/api/v1/key",
  note: "Use a key with a small credit limit you can revoke.",
};

const $ = (id) => document.getElementById(id);
const [rules, template] = await Promise.all([
  fetch("rules.json").then((r) => r.json()),
  fetch("report.html").then((r) => r.text()),
]);

let snapshot = null;
let decisions = {};
let lastSource = "sample";

function show(report) {
  const frame = $("report");
  frame.srcdoc = reportHtml(template, report);
  frame.onload = () => {
    const doc = frame.contentDocument;
    if (!doc) return;
    const fit = () => { frame.style.height = doc.documentElement.scrollHeight + "px"; };
    fit();
    new ResizeObserver(fit).observe(doc.body);
  };
}

function build() {
  const report = analyze(structuredClone(snapshot));
  return classify(report, rules, decisions);
}

async function askJev(key, report) {
  const pending = unclassified(report, rules);
  if (!pending.length) return 0;
  let count = 0;
  await Promise.all(pending.map(async (cause) => {
    const res = await fetch(JEV_URL, {
      method: "POST",
      headers: { authorization: "Bearer " + key, "content-type": "application/json", "x-title": "intune-why" },
      body: JSON.stringify({ model: JEV_MODEL, state: jevState(cause), questions: { path: rules.jev_question } }),
    });
    if (!res.ok) {
      const hint = { 401: "the key was rejected", 402: "the key has no credits", 404: "Jev is blocked by this key's OpenRouter guardrails" }[res.status];
      throw new Error("OpenRouter returned " + res.status + (hint ? ": " + hint : ""));
    }
    decisions[cause.id] = decisionFromAnswer(await res.json(), rules, JEV_MODEL);
    count++;
  }));
  return count;
}

async function run(source = lastSource) {
  lastSource = source;
  $("error").textContent = "";
  const { result: report, count } = await countNetworkCalls(async () => build());
  show(report);
  const where = source === "sample" ? "Sample tenant" : "Your snapshot";
  $("status").textContent = where + " · analyzed in your browser · " + count + " network requests";
  const key = $("key").getKey();
  if (key && unclassified(report, rules).length) {
    $("status").textContent = where + " · asking Jev about " + unclassified(report, rules).length + " custom settings…";
    try {
      const n = await askJev(key, report);
      show(build());
      $("status").textContent = where + " · " + n + " custom settings classified by Jev";
    } catch (err) {
      $("error").textContent = err.message + ". The report shows rule results only.";
      $("status").textContent = where + " · analyzed in your browser";
    }
  }
}

const data = $("data");
data.validate = (value) => {
  try {
    analyze(structuredClone(value));
    return [];
  } catch (err) {
    return [err instanceof SnapshotError ? err.message : "This file is not an intune-why snapshot."];
  }
};
data.addEventListener("byo-data", (e) => {
  snapshot = e.detail.data;
  decisions = {};
  run(e.detail.source);
});

const key = $("key");
key.provider = openrouter;
key.addEventListener("byo-key", (e) => {
  if (e.detail.state === "set" && snapshot) run();
});

snapshot = await fetch("demo_snapshot.json").then((r) => r.json());
run("sample");
