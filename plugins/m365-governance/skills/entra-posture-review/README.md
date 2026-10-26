# entra-posture-review

Reviews an Entra ID tenant's identity posture from saved Graph exports: Conditional Access basics, security defaults, standing Global Administrators, guests with roles, stale guests, long-lived app secrets, high-risk Graph application permissions, consent and invitation settings and legacy sign-ins.

How to run it, what to export and how to read the result: [SKILL.md](SKILL.md). Every option: `python3 scripts/entra_posture.py --help`.

## Sample

Run from the repository root on the committed fixture (an example tenant with planted problems; every name, address and id in it is invented). Exit code 1 (findings at or above --fail-on).

```bash
python3 plugins/m365-governance/skills/entra-posture-review/scripts/entra_posture.py tests/fixtures/entra/insecure --config tests/fixtures/entra/config.yaml --as-of 2026-10-04 --min-severity HIGH
```

Output, as printed (first 40 lines):

````markdown
# Entra ID posture review

Evaluated as of 2026-10-04.
Read: applications.json, authorization-policy.json, conditional-access-policies.json, directory-audits.json, graph-app-role-assignments.json, role-assignment-schedule-instances.json, role-assignments.json, role-definitions.json, security-defaults.json, service-principals.json, signins.json, users.json.
Not found (checks that need them were skipped): role-eligibility-schedule-instances.json.

| Severity | Findings |
|---|---|
| CRITICAL | 2 |
| HIGH | 9 |
| MEDIUM | 0 |
| LOW | 0 |
| INFO | 0 |

## Findings

| # | Severity | Check | Subject | Finding | Evidence |
|---|---|---|---|---|---|
| 1 | CRITICAL | CA-NO-MFA-ADMINS | conditional access | No enabled policy requires MFA for Global Administrators | no enabled policy with grant mfa targets All users or the Global Administrator role |
| 2 | CRITICAL | SP-HIGH-PRIV-APPROLE | Example Sync Connector | Holds application permission Directory.ReadWrite.All on Microsoft Graph | appRoleAssignment ara-1 created 2025-04-01 |
| 3 | HIGH | CA-LEGACY-AUTH | conditional access | No enabled policy blocks legacy authentication | no enabled policy for All users blocks clientAppTypes exchangeActiveSync and other |
| 4 | HIGH | CA-NO-MFA-ALL | conditional access | No enabled policy requires MFA for all users and all apps | 1 enabled policies; none has includeUsers All, includeApplications All and grant mfa or an authentication strength |
| 5 | HIGH | ROLE-GA-PERMANENT | admin.one@example.com | Standing Global Administrator assignment | assignmentType Assigned with no endDateTime |
| 6 | HIGH | ROLE-GA-PERMANENT | admin.two@example.com | Standing Global Administrator assignment | assignmentType Assigned with no endDateTime |
| 7 | HIGH | ROLE-GA-PERMANENT | old.admin@example.com | Standing Global Administrator assignment | assignmentType Assigned with no endDateTime |
| 8 | HIGH | ROLE-GA-PERMANENT | partner.admin_example.net#EXT#@example.com | Standing Global Administrator assignment | assignmentType Assigned with no endDateTime |
| 9 | HIGH | ROLE-GUEST-ADMIN | partner.admin_example.net#EXT#@example.com | Guest holds the Global Administrator role (active) | principal 00000000-0000-0000-0000-000000000108 |
| 10 | HIGH | ROLE-SP-PRIVILEGED | Example Sync Connector (service principal 00000000-0000-0000-0000-0000000005f1) | Service principal holds the Application Administrator role | principal 00000000-0000-0000-0000-0000000005f1 (active) |
| 11 | HIGH | SP-HIGH-PRIV-APPROLE | Example Reporting | Holds application permission Mail.Send on Microsoft Graph | appRoleAssignment ara-3 created 2025-04-02 |

### Fix guidance (shown for review, never run by the script)

1. portal: Entra admin center > Protection > Conditional Access > Policies > New policy (template: Require MFA for administrators); Graph: `POST /identity/conditionalAccess/policies (start in report-only mode)`
2. portal: Entra admin center > Enterprise applications > (app) > Permissions; Graph: `DELETE /servicePrincipals/00000000-0000-0000-0000-0000000005f1/appRoleAssignments/ara-1 after confirming the app does not need it`
3. portal: Entra admin center > Protection > Conditional Access > Policies > New policy (template: Block legacy authentication); Graph: `POST /identity/conditionalAccess/policies (start in report-only mode)`
4. portal: Entra admin center > Protection > Conditional Access > Policies > New policy (template: Require MFA for all users); Graph: `POST /identity/conditionalAccess/policies (start in report-only mode)`
5. portal: Entra admin center > Identity governance > Privileged Identity Management > Microsoft Entra roles; Graph: `POST /roleManagement/directory/roleEligibilityScheduleRequests (make eligible), then remove the active assignment`
6. portal: Entra admin center > Identity governance > Privileged Identity Management > Microsoft Entra roles; Graph: `POST /roleManagement/directory/roleEligibilityScheduleRequests (make eligible), then remove the active assignment`
7. portal: Entra admin center > Identity governance > Privileged Identity Management > Microsoft Entra roles; Graph: `POST /roleManagement/directory/roleEligibilityScheduleRequests (make eligible), then remove the active assignment`
8. portal: Entra admin center > Identity governance > Privileged Identity Management > Microsoft Entra roles; Graph: `POST /roleManagement/directory/roleEligibilityScheduleRequests (make eligible), then remove the active assignment`

... (5 more lines)
````

This file is generated by `python3 scripts/render_skill_readmes.py`; edit that script, not this file.
