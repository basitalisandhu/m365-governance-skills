# conditional-access-gap-analysis

Resolves who each Conditional Access policy really covers and reports the gaps: users and admins without MFA, legacy authentication, device and risk policies, break-glass accounts and unexplained exclusions, report-only and self-cancelling policies, with a policy by persona coverage matrix.

How to run it, what to export and how to read the result: [SKILL.md](SKILL.md). Every option: `python3 scripts/ca_gaps.py --help`.

## Sample

Run from the repository root on the committed fixture (an example tenant with planted problems; every name, address and id in it is invented). Exit code 1 (findings at or above --fail-on).

```bash
python3 plugins/m365-governance/skills/conditional-access-gap-analysis/scripts/ca_gaps.py tests/fixtures/ca-gaps/gaps --config tests/fixtures/ca-gaps/config.yaml --as-of 2026-10-04
```

Output, as printed (first 40 lines):

````markdown
# Conditional Access gap analysis

Evaluated as of 2026-10-04.
Read: conditional-access-policies.json, group-members/, groups.json, named-locations.json, role-assignments.json, role-definitions.json, role-eligibility-schedule-instances.json, users.json.

| Severity | Findings |
|---|---|
| CRITICAL | 1 |
| HIGH | 4 |
| MEDIUM | 9 |
| LOW | 4 |
| INFO | 2 |

## Findings

| # | Severity | Check | Subject | Finding | Evidence |
|---|---|---|---|---|---|
| 1 | CRITICAL | CA-GAP-MFA-ADMINS | admins | Admins not covered by an enabled policy that requires MFA for all cloud apps | 1 of 2 not covered: admin.two@example.com; qualifying policies: Require MFA for all users, Require MFA for all users (copy) |
| 2 | HIGH | CA-BREAKGLASS-NOT-EXCLUDED | breakglass2@example.com | Break-glass account is covered by enabled policies | applies: Require MFA for all users, Require MFA for all users (copy) |
| 3 | HIGH | CA-EXCLUSION-HAS-ADMIN | CA Exclusion - Service Accounts (group) | Excluded group contains admins | admins in the group: admin.two@example.com; excluded from: Require MFA for all users, Require MFA for all users (copy) |
| 4 | HIGH | CA-GAP-LEGACY-AUTH | all users | Users not covered by an enabled policy that blocks legacy authentication | 6 of 6 not covered: admin.one@example.com, admin.two@example.com, partner_example.org#EXT#@example.com, staff.one@example.com, staff.two@example.com, svc.scanner@example.com; qualifying policies: no qualifying enabled policy |
| 5 | HIGH | CA-GAP-MFA-ALL | all users | Users not covered by an enabled policy that requires MFA for all cloud apps | 2 of 6 not covered: admin.two@example.com, svc.scanner@example.com; qualifying policies: Require MFA for all users, Require MFA for all users (copy) |
| 6 | MEDIUM | CA-EXCLUSION-UNEXPLAINED | CA Exclusion - Service Accounts (group) | Exclusion with no recorded reason | excluded from: Require MFA for all users, Require MFA for all users (copy) |
| 7 | MEDIUM | CA-EXCLUSION-UNEXPLAINED | Pilot Users (group) | Exclusion with no recorded reason | excluded from: Pilot - require compliant device |
| 8 | MEDIUM | CA-GAP-ADMIN-DEVICE | admins | Admins not covered by an enabled policy that requires a compliant or hybrid-joined device | 1 of 2 not covered: admin.two@example.com; qualifying policies: Pilot - require compliant device, Admins - require compliant device |
| 9 | MEDIUM | CA-GAP-SIGNIN-RISK | tenant | No enabled policy acts on sign-in risk | no enabled policy sets signInRiskLevels with a grant of MFA or block |
| 10 | MEDIUM | CA-GAP-UNMANAGED-SESSION | tenant | No session controls for unmanaged devices | no enabled policy combines a session control (app enforced restrictions, Defender for Cloud Apps, sign-in frequency or persistent browser) with a device filter or the browser client type |
| 11 | MEDIUM | CA-INCLUDE-EXCLUDE-CANCEL | Pilot - require compliant device | Includes and excludes the same target | both included and excluded: Pilot Users (group) |
| 12 | MEDIUM | CA-LOCATION-BROAD | Old VPN range | Trusted named location is very wide | trusted ranges wider than /16 (IPv4) or /32 (IPv6): 10.0.0.0/8 |
| 13 | MEDIUM | CA-REPORT-ONLY-STALE | Block legacy authentication | Report-only for 216 days | report-only since 2026-03-02 (more than 30 days); controls: block |
| 14 | MEDIUM | CA-ZERO-TARGET | Pilot - require compliant device | Policy applies to no user | state enabled; 0 of 9 exported users are in scope; include and exclude cancel out |
| 15 | LOW | CA-GAP-DEVICE-CODE | tenant | No policy blocks the device code flow | no enabled policy that includes All users sets authentication flows to device code flow with grant Block |
| 16 | LOW | CA-GAP-USER-RISK | tenant | No enabled policy acts on user risk | no enabled policy sets userRiskLevels with a grant of MFA or block |
| 17 | LOW | CA-TRUSTED-LOCATION-SKIP | Require MFA for all users | MFA is skipped from trusted locations | excluded locations: all trusted locations |
| 18 | LOW | CA-TRUSTED-LOCATION-SKIP | Require MFA for all users (copy) | MFA is skipped from trusted locations | excluded locations: all trusted locations |
| 19 | INFO | CA-DISABLED | Old MFA policy for Office | Policy is disabled | modified 2026-09-01 |
| 20 | INFO | CA-OVERLAP | Require MFA for all users and Require MFA for all users (copy) | Policies with identical conditions and controls | 2 enabled policies are the same apart from their names |

### Fix guidance (shown for review, never run by the script)


... (32 more lines)
````

This file is generated by `python3 scripts/render_skill_readmes.py`; edit that script, not this file.
