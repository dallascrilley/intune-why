# Decision model: how intune-why classifies settings

Measured 27 October 2026 against `jev-1.14.0` through TypeSafe's direct System One API. The tool now calls the same release, `typesafe/jev-1.14`, through OpenRouter's Decisions API so that users need only an OpenRouter key; rerun `scripts/shadow_jev.py` to measure that route on your account.

## What is decided

Each root cause gets one remediation path: configure devices, ask users, fix policy, clean up devices, investigate risk, or other. Built-in regular-expression rules handle the standard compliance settings. Settings no rule matches, mostly custom compliance settings, go to Jev as a single `choice` question with an `other` option. The full question is `JEV_QUESTION` in `src/intune_why/classify.py`.

Jev receives only the setting identifier, its short name, the platforms, state counts and the share of affected devices that have not synced recently. Answers with confidence below 0.60 are shown as *Review*, together with Jev's proposed path.

## Shadow run

`scripts/shadow_jev.py` sends 40 settings to Jev: 23 standard settings and 17 custom-style settings written to resemble real custom compliance checks. Each has a label giving the remediation path the maintainer would choose. Every setting gets the same neutral counts, so Jev judges from the setting identifier alone, which is harder than real use, where the share of stale devices is informative.

| Set | Settings | Jev agrees | At or above 0.60 confidence | Agreement when accepted |
|---|---|---|---|---|
| Standard settings | 23 | 21 (91%) | 21 | 21 of 21 |
| Custom settings | 17 | 14 (82%) | 12 | 12 of 12 |
| All | 40 | 35 (88%) | 33 | 33 of 33 |

Median latency was 201 ms per call. The built-in rules cover 23 of the 40 settings and agree with the label on all 23. Raw results, including every probability distribution, are in [evidence/shadow-run-2026-10-27.jsonl](evidence/shadow-run-2026-10-27.jsonl).

Disagreements, all below the 0.60 floor and therefore routed to review:

- `Windows10CompliancePolicy.DeviceThreatProtectionRequiredSecurityLevel`: labeled investigate risk, Jev chose configure devices (0.52). A rule covers this setting in normal use.
- `DefaultDeviceCompliancePolicy.RequireRemainContact`: labeled clean up devices, Jev chose ask users (0.44). A rule covers this setting, and in real data the stale-device share points the other way.
- `CustomCompliance.BiosPasswordSet`: labeled configure devices, Jev chose ask users (0.36).
- `CustomCompliance.PrimaryUserAccountDisabled`: labeled clean up devices, Jev chose ask users (0.22).
- `CustomCompliance.WindowsUpdateRingAssigned`: labeled fix policy, Jev chose configure devices (0.39).

An earlier run of the same set agreed on `BiosPasswordSet`, so low-confidence answers can change between runs. Accepted answers matched in both runs (33 of 33 each time).

The same run also exposed a rule bug: a broad `password` pattern classified custom settings such as `BiosPasswordSet` and `LapsPasswordBackedUp` as user actions. The rule is now anchored to the standard password settings, and a test covers it.

## Limits

Forty settings is a small sample, and the labels are one maintainer's judgment; several settings could reasonably take more than one path. Confidence is a property of Jev's probability distribution, not a calibrated probability of being right on your settings. The 0.60 floor comes from this run. Treat Jev's path as a starting suggestion, which is how the report presents it.
