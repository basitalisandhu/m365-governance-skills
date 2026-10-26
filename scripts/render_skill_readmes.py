#!/usr/bin/env python3
"""Write plugins/m365-governance/skills/<skill>/README.md for every skill, with a real sample.

Each README holds a short summary, the command that runs the skill's script on a committed fixture, and the first
lines of that command's actual output. Nothing in a sample is typed by hand: this script runs the command and
pastes what it printed, so the samples stay true when a check changes.

    python3 scripts/render_skill_readmes.py           rewrite the READMEs
    python3 scripts/render_skill_readmes.py --check   exit 1 if any README differs from what would be written

Standard library only; runs the scripts with the current Python and makes no network calls.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "plugins" / "m365-governance" / "skills"
MAX_LINES = 40

# skill: (one-paragraph summary, script, arguments relative to the repository root)
SKILL_SAMPLES: dict[str, tuple[str, str, list[str]]] = {
    "access-review-pack": (
        "Builds the quarterly access review package from saved Graph exports: privileged role holders with last sign-in, "
        "app registration owners, owners of sensitive groups, guests per group and credentials about to expire, as a "
        "reviewer checklist and a sign-off CSV whose decision column stays blank for the reviewer.",
        "access_review_pack.py",
        ["tests/fixtures/access-review/tenant", "--config", "tests/fixtures/access-review/config.yaml", "--as-of", "2026-10-04"],
    ),
    "conditional-access-gap-analysis": (
        "Resolves who each Conditional Access policy really covers and reports the gaps: users and admins without MFA, "
        "legacy authentication, device and risk policies, break-glass accounts and unexplained exclusions, report-only and "
        "self-cancelling policies, with a policy by persona coverage matrix.",
        "ca_gaps.py",
        ["tests/fixtures/ca-gaps/gaps", "--config", "tests/fixtures/ca-gaps/config.yaml", "--as-of", "2026-10-04"],
    ),
    "copilot-oversharing-readiness": (
        "Scores a tenant's readiness for a Copilot rollout from SharePoint and Purview exports: Everyone grants, anyone and "
        "organisation-wide links, sites with no label or no owner, and DLP coverage, with a fix list per site owner.",
        "copilot_readiness.py",
        ["tests/fixtures/copilot/tenant", "--as-of", "2026-10-18", "--org-links", "1"],
    ),
    "entra-posture-review": (
        "Reviews an Entra ID tenant's identity posture from saved Graph exports: Conditional Access basics, security "
        "defaults, standing Global Administrators, guests with roles, stale guests, long-lived app secrets, high-risk "
        "Graph application permissions, consent and invitation settings and legacy sign-ins.",
        "entra_posture.py",
        ["tests/fixtures/entra/insecure", "--config", "tests/fixtures/entra/config.yaml", "--as-of", "2026-10-04",
         "--min-severity", "HIGH"],
    ),
    "graph-permission-preflight": (
        "Compares the Graph permissions an app, connector or MCP server requests or holds with a needs manifest of what it "
        "actually uses, flags high-risk, .All, write-where-read-suffices and unused grants, and proposes a least-privilege set.",
        "permission_preflight.py",
        ["tests/fixtures/preflight/over-broad", "--needs", "tests/fixtures/preflight/over-broad/needs.yaml", "--as-of", "2026-10-04"],
    ),
    "guest-and-external-sharing-review": (
        "Reviews guest accounts and external sharing settings: guests from blocked domains or in sensitive groups, stale "
        "and unaccepted invitations, anyone links and links that never expire, guest resharing and open Teams external "
        "access, with a per-guest access map and a draft removal list.",
        "external_sharing.py",
        ["tests/fixtures/external-sharing/tenant", "--config", "tests/fixtures/external-sharing/config.yaml", "--as-of", "2026-10-04"],
    ),
    "intune-baseline-check": (
        "Checks an Intune estate against a device baseline: non-compliant, stale, unencrypted, jailbroken and outdated "
        "devices, personal devices, unassigned compliance policies, platforms missing baseline controls and the "
        "no-policy-means-compliant setting, per platform.",
        "intune_baseline.py",
        ["tests/fixtures/intune/estate", "--config", "tests/fixtures/intune/config.yaml", "--as-of", "2026-10-04"],
    ),
    "license-and-service-plan-audit": (
        "Finds wasted Microsoft 365 licences: licences on disabled, never-signed-in or inactive accounts, overlapping SKUs, "
        "unwanted service plans, group-based licensing errors and unassigned units, with a draft reclaim list per SKU.",
        "license_audit.py",
        ["tests/fixtures/license-audit/tenant", "--config", "tests/fixtures/license-audit/config.yaml", "--as-of", "2026-10-04"],
    ),
    "privileged-access-review": (
        "Scores every privileged Entra ID role holder: permanent assignments, never-activated PIM eligibility, admins "
        "without phishing-resistant MFA, admin accounts used daily, stale or synchronised admins, and service principals "
        "and groups in roles, with the evidence for each deduction.",
        "pim_review.py",
        ["tests/fixtures/pim-review/tenant", "--config", "tests/fixtures/pim-review/config.yaml", "--as-of", "2026-10-04"],
    ),
    "teams-and-groups-sprawl": (
        "Reports Teams and Microsoft 365 group sprawl: ownerless and single-owner groups, guest owners or members, public "
        "and inactive teams, empty groups, naming violations and groups missing an expiration policy, with owners "
        "proposed from member managers as a draft.",
        "groups_sprawl.py",
        ["tests/fixtures/groups/tenant", "--config", "tests/fixtures/groups/config.yaml", "--as-of", "2026-10-04"],
    ),
}


def sample(skill: str, script: str, args: list[str]) -> tuple[str, int, str]:
    path = SKILLS / skill / "scripts" / script
    proc = subprocess.run([sys.executable, str(path), *args], cwd=ROOT, capture_output=True, text=True, timeout=120,
                          encoding="utf-8")
    if proc.returncode not in (0, 1):
        raise SystemExit(f"{skill}: {script} exited {proc.returncode}: {proc.stderr.strip()}")
    rel = path.relative_to(ROOT).as_posix()
    return "python3 " + " ".join([rel, *args]), proc.returncode, proc.stdout


def render(skill: str) -> str:
    summary, script, args = SKILL_SAMPLES[skill]
    command, rc, out = sample(skill, script, args)
    lines = out.rstrip("\n").splitlines()
    shown = lines[:MAX_LINES]
    more = len(lines) - len(shown)
    body = "\n".join(shown) + (f"\n\n... ({more} more lines)" if more else "")
    return "\n".join([
        f"# {skill}",
        "",
        summary,
        "",
        "How to run it, what to export and how to read the result: [SKILL.md](SKILL.md). Every option: "
        f"`python3 scripts/{script} --help`.",
        "",
        "## Sample",
        "",
        "Run from the repository root on the committed fixture (an example tenant with planted problems; every name, "
        f"address and id in it is invented). Exit code {rc}"
        + (" (findings at or above --fail-on)." if rc == 1 else "."),
        "",
        "```bash",
        command,
        "```",
        "",
        "Output, as printed" + (f" (first {MAX_LINES} lines)" if more else "") + ":",
        "",
        "````markdown",
        body,
        "````",
        "",
        "This file is generated by `python3 scripts/render_skill_readmes.py`; edit that script, not this file.",
        "",
    ])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="exit 1 if a README is missing or out of date; write nothing")
    args = ap.parse_args(argv)
    missing = sorted({d.name for d in SKILLS.iterdir() if (d / "SKILL.md").is_file()} - set(SKILL_SAMPLES))
    if missing:
        print(f"error: no sample defined for {', '.join(missing)}", file=sys.stderr)
        return 1
    stale = []
    for skill in sorted(SKILL_SAMPLES):
        text = render(skill)
        target = SKILLS / skill / "README.md"
        current = target.read_text(encoding="utf-8").replace("\r\n", "\n") if target.is_file() else None
        if current == text:
            continue
        if args.check:
            stale.append(skill)
        else:
            target.write_text(text, encoding="utf-8", newline="\n")
            print(f"wrote {target.relative_to(ROOT).as_posix()}")
    if stale:
        print(f"out of date: {', '.join(stale)}; run python3 scripts/render_skill_readmes.py", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
