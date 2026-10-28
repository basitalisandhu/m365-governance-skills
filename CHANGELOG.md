# Changelog

All notable changes to this project are documented here. The format follows Keep a Changelog, and the project uses semantic versioning.

## [Unreleased]

## [0.7.0] - 2026-10-29

### Added

- `entra-posture-review`: `CA-EMPTY-TARGET` (LOW) flags enabled Conditional Access policies with no included users, groups, roles or guest/external-user target, without treating disabled or report-only policies as enforcing (#6).

### Fixed

- Every script refuses a JSON export or config nested more than 200 levels deep with exit 2 and an error naming the file, on every supported Python. Python 3.14 no longer raises `RecursionError` from `json.loads` at the old depth, so the shared `_graphio.py` reader and `copilot_readiness.py` now check nesting first instead of relying on it.
- CI tests Python 3.11 to 3.14 on Linux, macOS and Windows.

## [0.6.0] - 2026-10-26

Second deep pass: trigger evaluation of every description, seeded fuzz tests on every export parser, an end-to-end test across four skills, a performance check on inputs ten to a thousand times the fixtures, and a README with a real sample in every skill folder.

### Added

- `graph-permission-preflight`: reads the consent or sign-in link a vendor sent, saved as `consent-url.txt`. The `scope` parameter is parsed as requested delegated permissions (`https://graph.microsoft.com/Mail.Read` becomes `Mail.Read`); the link is never opened. `openid`, `profile`, `email` and `offline_access` are recognised as sign-in scopes and never reported as unused; the new `SIGNIN-SCOPE` (INFO) notes the ones the needs do not list. A `.default` scope gives a warning asking for `application.json` (#9).
- Every skill folder has a `README.md` with the command that runs its script on a committed fixture and the real output, written by `scripts/render_skill_readmes.py`; a test fails when a sample no longer matches the script.
- `evals/trigger-prompts.yaml`: five should-trigger and five should-not-trigger prompts for every skill, for the skill-trigger-eval scorer.
- Tests: seeded fuzz tests that damage every fixture folder and config file (`tests/test_fuzz_exports.py`, `FUZZ_ITERATIONS` for deeper runs), the tenant handover chain through the dispatcher (`tests/test_integration_chain.py`: entra-posture, pim-review, ca-gaps and access-review must agree on the same Global Administrators, role holders and redaction tokens), and a call-count guard on Conditional Access coverage (`tests/test_performance.py`). 229 to 274 tests.

### Fixed

- All scripts: a value of the wrong type inside an export (a number where Graph writes a string, a list where it writes an object) exits 2 with a message instead of a traceback, a file that is not UTF-8 exits 2 naming the file, and JSON nested too deep to decode exits 2 instead of raising RecursionError. The fuzz run found 88 distinct crash sites across the ten scripts before the fix and none after.
- `copilot-oversharing-readiness`: a PowerShell `/Date(...)/` value too large for a date raised OverflowError; it now reads as no date.
- `_miniyaml` (config and needs files): the input `- - -:` made the parser loop for ever, so a damaged config hung every script; it now exits 2. A flow collection used as a mapping key (`[{x: 1}: 2]`) raised a TypeError; it is now a parse error.

### Changed

- `conditional-access-gap-analysis`: who each policy covers is resolved once per policy instead of once per check (baseline coverage, `CA-ZERO-TARGET`, the persona matrix and the unknown-groups pass). Same output; on 9,000 users and 6 policies the run drops from 0.63 s to 0.21 s, and on the fixture scaled a hundredfold from 1.34 s to 0.45 s.
- Descriptions of `access-review-pack`, `conditional-access-gap-analysis`, `graph-permission-preflight`, `intune-baseline-check`, `license-and-service-plan-audit` and `privileged-access-review` rewritten after the trigger evaluation (lexical proxy, cross mode across the ten skills): precision 0.92 to 0.96 and recall 0.88 to 0.98 overall; `intune-baseline-check` recall 0.60 to 1.00 and `graph-permission-preflight` 0.60 to 0.80.
- Version 0.6.0 in `pyproject.toml`, `plugin.json`, `marketplace.json`, the dispatcher and the README container examples.

## [0.5.1] - 2026-10-18

Skills quality pass: every script was run on its fixtures and on empty, wrong-format and wrong-shape inputs, and every Graph field and export command the checks rely on was checked against the current Microsoft Graph v1.0 reference (beta where the export uses beta).

### Fixed

- `access-review-pack`: service principal sign-in dates now read the documented beta names `applicationAuthenticationClientSignInActivity` and `applicationAuthenticationResourceSignInActivity`; the old names (`applicationClientSignInActivity`, `applicationResourceSignInActivity`) do not exist, so app-only sign-ins were missed. The fixture uses the documented shape.
- `intune-baseline-check`: `BASE-DEFENDER` no longer fires on every v1.0 export. `defenderEnabled`, `antivirusRequired` and `deviceThreatProtectionEnabled` exist on `windows10CompliancePolicy` only in the beta schema; with a v1.0 export the check is listed under "Not evaluated", and SKILL.md gives the beta export that evaluates it.
- `entra-posture-review`: `SIGNIN-LEGACY-USED` matches the legacy `clientAppUsed` values the v1.0 reference documents (`IMAP`, `POP`, `MAPI`, `SMTP`, `other clients`) case-insensitively, as well as the longer forms seen in sign-in logs.
- All `_graphio` scripts: a collection file holding one object without an `id` (for example a saved Graph error response or a settings file under the wrong name), `{"value": ...}` that is not a list, an empty file, or a single-object export with none of its expected properties now exits 2 with a message naming the file, instead of being read as an empty or "everything off" tenant. `entra_posture.py` and `access_review_pack.py` exit 2 on a folder with no known export file instead of printing an empty report.
- `copilot-oversharing-readiness`: `sharing-links.json`, `tenant.json`, `dlp-policies.json` and `labels.json` of the wrong shape exit 2 instead of hiding anyone links or DLP state; an empty `tenant.json` list no longer crashes; label ids match case-insensitively. Compatibility line corrected to Python 3.11.
- `privileged-access-review`, `license-and-service-plan-audit`, `teams-and-groups-sprawl`: a config list given as a single string (`break_glass: ana@example.com`, `unwanted_service_plans: SWAY`, `naming_applies_to: team`) is a one-item list instead of being read letter by letter; a number or mapping there exits 2 (it raised a traceback for `daily_use_exempt`). `teams-activity.csv` without the `Team Id` or `Team Name` and `Last Activity Date` columns exits 2 instead of silently dropping `TEAM-INACTIVE`.

### Changed

- Export tables: `subscribed-skus.json` names `LicenseAssignment.Read.All`, the least-privileged permission for List subscribedSkus (`Organization.Read.All` still works); the Copilot labels export uses the documented beta paths (`/beta/me/security/informationProtection/sensitivityLabels` with `InformationProtectionPolicy.Read`, the tenant-wide path is application-only).
- Descriptions of `entra-posture-review`, `access-review-pack` and `teams-and-groups-sprawl` rewritten: the trigger eval (lexical proxy, cross negatives) moves `entra-posture-review` precision from 0.71 to 1.00 and `access-review-pack` recall from 0.80 to 1.00; `teams-and-groups-sprawl` gains a quoted user phrase.
- Exit codes are documented in every SKILL.md, the README and the plugin README; the plugin README carries real output samples for three skills, and `tests/fixtures/copilot/tenant` gives the Copilot skill a fixture folder.
- Tests: 194 to 229. Version 0.5.1 in `pyproject.toml`, `plugin.json`, `marketplace.json`, the dispatcher and the README container examples.

## [0.5.0] - 2026-10-13

### Added

- `teams-and-groups-sprawl`: new finding `GRP-GUEST-OWNER` (MEDIUM) for a group with at least one guest owner, with the Graph call to remove the owner once a member owner is in place (#25, thanks @Nexform-star).
- `conditional-access-gap-analysis`: new check `CA-GAP-DEVICE-CODE` (LOW) when no enabled policy that includes All users blocks the device code flow (`conditions.authenticationFlows.transferMethods` containing `deviceCodeFlow`, grant Block). The `baseline-met` fixture gains such a policy. Closes #14.

### Changed

- Version 0.5.0 in `pyproject.toml`, `plugin.json`, `marketplace.json`, the dispatcher and the README container examples.

## [0.4.0] - 2026-10-09

### Added

- `access-review-pack`: optional `service-principal-sign-ins.json` (Graph beta `servicePrincipalSignInActivities`, `AuditLog.Read.All`) fills `last_sign_in` for service principals with the latest of the five activity dates, `n/a` when the file is absent or the app has no record.

## [0.3.0] - 2026-10-05

### Added

- `copilot-oversharing-readiness`: `copilot_readiness.py` scores a tenant's readiness for a Microsoft 365 Copilot rollout from read-only PnP, Graph and Security and Compliance exports, with 12 checks: Everyone and Everyone except external users in site groups, anyone and organisation-wide sharing links, sites that allow anyone links, sites with no sensitivity label or no owner, inactive sites many people can reach, the tenant default link type, anyone links without expiry, no published labels, and DLP for SharePoint and OneDrive missing or in test mode. Findings fall into three buckets (fix before rollout, before broad rollout, hygiene) with a readiness rating, a score from a fixed rubric, and a remediation list grouped by site owner as Markdown, JSON or CSV. Sharing link URLs are never printed and secret-shaped strings are masked. The SKILL.md lists the exact read-only command behind each export with a small example.
- Dispatcher subcommand `copilot-readiness`; the container check in CI runs its `--help`.

### Changed

- Version 0.3.0 in `pyproject.toml`, `plugin.json`, `marketplace.json`, the dispatcher and the README container examples; the READMEs list the new skill and the searches it answers.

## [0.2.2] - 2026-10-05

### Changed

- Rewrote all nine skill descriptions to 439 to 582 characters (from 824 to 993): each starts with a verb, states the goal before the mechanism, carries one quoted phrase a user would type, a "Use when ..." sentence and a "Not for ..." boundary, and stays double-quoted.
- Tests open text files with `encoding="utf-8"` (the scripts already did), and CI runs tests, ruff and the `--help` check on `windows-latest` as well as Ubuntu and macOS.
- The plugin and root READMEs mention Copilot oversharing, Microsoft Secure Score and SharePoint site permissions audits, with what the skills do and do not cover.
- `scripts/validate_plugins.py` now fails when a description is over 600 characters, is not double-quoted, or lacks "Use " or "Not for", and when a SKILL.md has no `## Limits` section; `tests/test_skill_frontmatter.py` covers each rule.
- Version 0.2.2 in `pyproject.toml`, `plugin.json`, `marketplace.json`, the dispatcher and the README container examples.

### Added

- Report disabled users that still hold active or eligible directory roles,
  with synthetic fixtures and redaction regression coverage.

## [0.2.1] - 2026-10-04

### Fixed

- Quoted SKILL.md descriptions that contained a colon so the frontmatter parses under strict YAML readers such as the skills CLI; the validator now fails on unquoted scalars with ': ' or ' #'.

## [0.2.0] - 2026-10-04

Four new skills, each with a standard-library script, hand-written fixtures with planted problems, and tests. The plugin now has nine skills.

### Added

- `conditional-access-gap-analysis`: `ca_gaps.py` resolves who each Conditional Access policy applies to (users, transitive group members, active and eligible role holders, guests) and checks 17 conditions: MFA for all users and for admins, legacy authentication blocked, compliant or hybrid-joined device for admins, sign-in and user risk policies, session controls for unmanaged devices, break-glass accounts excluded from every enabled policy, exclusions without a recorded reason, exclusion groups that contain admins, policies in report-only mode beyond a configurable age, include and exclude lists that cancel out, policies that reach no user, duplicate policies, very wide trusted named locations, MFA skipped from trusted locations and disabled policies. Prints a policy by persona coverage matrix.
- `privileged-access-review`: `pim_review.py` reports permanent privileged role assignments (CRITICAL for Global Administrator), eligible assignments never activated, admins with no MFA method or no phishing-resistant method, admin accounts with a mailbox or licences, stale and on-premises synchronised admins, service principals in privileged roles, assignments scoped below the tenant root and roles held by groups, and gives each admin account a hygiene score with one evidence line per deduction.
- `guest-and-external-sharing-review`: `external_sharing.py` reports guests from blocked or not-allowed domains (CRITICAL when also in a sensitive group), guests in sensitive groups, stale guests, invitations not accepted, SharePoint and OneDrive anyone links and their expiry, sharing with no domain restriction, guest resharing, Teams external access open to all domains and chat with personal Teams accounts. Builds a per-guest access map and a draft removal list (`--csv`).
- `license-and-service-plan-audit`: `license_audit.py` reports licences on disabled, never-signed-in and inactive accounts, overlapping SKUs on one user (from the SKUs' service plans, or configured pairs), service plans the organisation has decided not to use, group-based licensing errors and unassigned units, with a reclaim list (`--csv`) and counts per SKU. It holds no prices; totals use only unit costs supplied in the config.
- Dispatcher subcommands `ca-gaps`, `pim-review`, `external-sharing` and `license-audit`, with tests that run each one on its fixtures; the container build check in CI runs their `--help`.
- Six new starter tasks in `docs/good-first-issues.md` for the new skills.

### Changed

- README, plugin README, manifests and image labels list the nine skills; version 0.2.0 in `pyproject.toml`, `plugin.json`, `marketplace.json` and `scripts/cli.py`.

## [0.1.1] - 2026-10-04

The skill scripts are published as a container image on GitHub Packages, using only the workflow's `GITHUB_TOKEN`: `ghcr.io/basitalisandhu/m365-governance-skills`, tagged `0.1.1` and `latest`, for linux/amd64 and linux/arm64, with an SPDX SBOM, a build provenance attestation and a keyless cosign signature. The skills themselves are unchanged.

### Added

- `scripts/cli.py`: a standard-library dispatcher, `m365-governance <subcommand> [args]`, over the skill scripts (`preflight`, `entra-posture`, `intune-baseline`, `groups-sprawl`, `access-review`), with `--help` listing the subcommands and `--version`; tests in `tests/test_cli.py`.
- `Dockerfile`: two stages on a digest-pinned `python:3.12-slim`, only the dispatcher and the skill scripts, no pip dependencies, uid 1000, `WORKDIR /work`, entrypoint `m365-governance`.
- `publish-github-packages.yml`: on a `v*` tag, tests, checks that every version field matches the tag, builds, pushes, attests and signs the image, and creates the GitHub release with the SBOM attached. Pull requests that touch packaging run it as a dry run.
- CI job that builds the image and runs `--help`, every subcommand's `--help` and `--version`, and checks the user and working directory.
- README Install section with the `docker run` usage and the verify commands.

## [0.1.0] - 2026-10-04

### Added

- Plugin marketplace `m365-governance-skills` with one plugin, `m365-governance`.
- `graph-permission-preflight`: `permission_preflight.py` compares an app's requested permissions, delegated grants and application permission assignments (or a connector's declared list) with a needs manifest; reports high-risk permissions, write where read suffices, application where delegated is enough, unused and `.All`-where-scoped permissions, consent types, and a least-privilege replacement set.
- `entra-posture-review`: `entra_posture.py`, 23 offline checks across Conditional Access, security defaults, Global Administrators and PIM, guests, app credentials, service principals with high-risk Graph application permissions, user consent and guest invitation settings, and legacy sign-ins.
- `intune-baseline-check`: `intune_baseline.py`, 15 offline checks across managed devices, compliance policy controls per platform, unassigned policies, profiles assigned to All devices or All users without exclusions, and the "no policy means compliant" setting, with a per-platform summary.
- `teams-and-groups-sprawl`: `groups_sprawl.py` (ownerless and single-owner groups, guests, public and inactive teams, empty groups, naming convention, expiration) and a draft cleanup list with proposed owners from member managers.
- `access-review-pack`: `access_review_pack.py` builds a Markdown reviewer checklist and a sign-off CSV (role holders, app owners, sensitive group owners, guests per group, expiring credentials).
- `--redact` and `--json` on every script; shared `_graphio.py` and `_miniyaml.py` helpers copied into each skill.
- Offline pytest suite with hand-written fixtures, `scripts/validate_plugins.py`, ruff configuration, and a CI workflow with read-only permissions.
