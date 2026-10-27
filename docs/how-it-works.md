# How intune-why works

A short tour for contributors and for anyone who wants to check the numbers.

## 1. Collect: three read-only Graph calls

`graph.py` signs in with the OAuth 2.0 device code flow, then reads:

1. `managedDevices`: every Intune device, with its primary user, last sync time and compliance state.
2. `deviceCompliancePolicySettingStateSummaries`: one row per compliance setting, with counts of devices that pass or fail it.
3. For each setting with failures, its `deviceComplianceSettingStates`: which devices fail it.

The snapshot keeps only failing states (`nonCompliant`, `error`, `conflict`). The token stays in memory. The client follows `@odata.nextLink` only on graph.microsoft.com, refuses redirects, and waits out `Retry-After` when Graph throttles.

## 2. Analyze: who fails what

`analyze.py` groups failing states by setting. Each group becomes a root cause with its affected devices, platforms, and how many of those devices fail only this setting. Devices that report noncompliant but list no failing setting are kept aside as *unexplained*, and failing states for devices missing from the device list are counted as *unmatched*. Neither is guessed at.

A device counts as stale when it has not synced within `--stale-days` (30 by default). Intune reports `0001-01-01` for devices that never synced; that counts as unknown, so stale.

## 3. Plan: the fix that clears the most devices next

A device becomes compliant only when every failing setting on it is fixed. `fix_plan` is a greedy set cover: at each step it picks the setting whose fix makes the most additional devices fully compliant, given the fixes already chosen. When no single fix clears anything (every remaining device fails two or more settings), it picks the setting that touches the most uncleared devices, so a later step can clear them. Ties break by name, so output is stable.

Greedy is not guaranteed optimal for set cover, but on this shape of data it matches what an admin would do by hand, and every step is easy to explain.

## 4. Classify: who does the fix

`classify.py` maps each setting to one remediation path: configure devices, ask users, fix policy, clean up devices, investigate risk, or review. Rules in `data/rules.json` cover the standard settings; the web demo uses the same file. Custom settings can go to Jev, a typed decision model, which must pick one of those paths and returns a confidence. Answers under 0.60 go to review. See [decision-model.md](decision-model.md) for the measurement.

## 5. Report

`report.py` writes the terminal summary, JSON, CSV and the HTML page. The page embeds the report as escaped JSON and renders it with `textContent`, so tenant data cannot inject markup. The CSV prefixes cells that start with `=`, `+`, `-` or `@` so spreadsheet apps do not evaluate them.

## 6. The browser demo

`web/core.js` is a JavaScript port of steps 2 to 4. `web/parity.test.mjs` runs it on the demo tenant and requires the exact same report the Python package produces; CI fails on any difference. The page reads your snapshot with [byo-kit](https://github.com/dallascrilley/byo-kit), analyzes it in the tab, and, if you add an OpenRouter key, sends only setting names and counts to Jev.

## Try changing it

- Copy `src/intune_why/data/demo_snapshot.json`, assign one stale device's failing setting to a fresh device, and run `intune-why analyze copy.json`. Which plan step changes, and why?
- Add a rule to `data/rules.json` for a custom setting your tenant uses, then run `script/cibuild`. The parity test confirms the browser demo agrees.
