| Set | Settings | Jev agrees | At or above 0.60 confidence | Agreement when accepted |
|---|---|---|---|---|
| Standard settings | 23 | 21 (91%) | 21 | 21 of 21 |
| Custom settings | 17 | 14 (82%) | 12 | 12 of 12 |
| All | 40 | 35 (88%) | 33 | 33 of 33 |

Built-in rules cover 23 of 40 settings and agree with the label on 23.

Model: jev-1.14.0. Median latency 201 ms.

Disagreements:
- `Windows10CompliancePolicy.DeviceThreatProtectionRequiredSecurityLevel`: labeled security_investigation, Jev chose device_configuration (0.52)
- `DefaultDeviceCompliancePolicy.RequireRemainContact`: labeled stale_or_orphaned, Jev chose user_action (0.44)
- `CustomCompliance.BiosPasswordSet`: labeled device_configuration, Jev chose user_action (0.36)
- `CustomCompliance.PrimaryUserAccountDisabled`: labeled stale_or_orphaned, Jev chose user_action (0.22)
- `CustomCompliance.WindowsUpdateRingAssigned`: labeled policy_assignment, Jev chose device_configuration (0.39)
