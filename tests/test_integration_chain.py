"""End-to-end chain: the tenant handover review, four skills over one export folder through the dispatcher.

An administrator who takes over a tenant saves one folder of Graph exports and runs, in order, entra-posture-review
(baseline), privileged-access-review (score the admins), conditional-access-gap-analysis (who MFA really covers)
and access-review-pack (the sign-off sheet). This test runs that chain through scripts/cli.py, as the container
does, on the committed insecure-tenant fixture, and checks that the four reports agree with each other about the
same people: the Global Administrators, the privileged role holders and the redaction tokens.
"""
from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "scripts" / "cli.py"
TENANT = ROOT / "tests" / "fixtures" / "entra" / "insecure"
AS_OF = ["--as-of", "2026-10-04"]


def cli(*args: str) -> tuple[int, str]:
    proc = subprocess.run([sys.executable, str(CLI), *args], capture_output=True, text=True, timeout=60, cwd=ROOT)
    assert proc.returncode in (0, 1), f"{args[0]} exited {proc.returncode}: {proc.stderr}"
    return proc.returncode, proc.stdout


@pytest.fixture(scope="module")
def chain(tmp_path_factory):
    out = tmp_path_factory.mktemp("handover")
    reports = {}
    for sub in ("entra-posture", "pim-review", "ca-gaps", "access-review"):
        rc, text = cli(sub, str(TENANT), *AS_OF, "--json")
        reports[sub] = (rc, json.loads(text))
    rc, _ = cli("access-review", str(TENANT), *AS_OF, "--out-dir", str(out))
    reports["signoff"] = (rc, list(csv.DictReader((out / "access-review-signoff.csv").open(encoding="utf-8"))))
    return reports


def test_exit_codes_follow_the_planted_problems(chain):
    assert chain["entra-posture"][0] == 1  # standing Global Admins and more
    assert chain["pim-review"][0] == 1
    assert chain["ca-gaps"][0] == 1
    assert chain["access-review"][0] == 0  # the pack is built; it has no --fail-on


def test_every_skill_sees_the_same_global_administrators(chain):
    posture = {r["principal"] for r in chain["entra-posture"][1]["role_holders"] if r["role"] == "Global Administrator"}
    scored = {a["account"] for a in chain["pim-review"][1]["accounts"]
              if any(role.startswith("Global Administrator") for role in a["roles"])}
    review = {r["principal"] for r in chain["access-review"][1]["rows"]
              if r["section"] == "privileged-roles" and r["item"] == "Global Administrator"}
    assert posture, "the fixture plants several Global Administrators"
    assert posture == scored == review


def test_ca_gaps_counts_at_least_the_admin_users_the_other_skills_list(chain):
    admin_users = {r["principal"] for r in chain["entra-posture"][1]["role_holders"] if r["kind"] in ("user", "guest")}
    assert chain["ca-gaps"][1]["personas"]["admins"] >= len(admin_users)


def test_signoff_sheet_has_a_blank_decision_row_for_every_privileged_role_holder(chain):
    rows = [r for r in chain["signoff"][1] if r["section"] == "privileged-roles"]
    holders = {(r["role"], r["principal"]) for r in chain["entra-posture"][1]["role_holders"] if r["kind"] in ("user", "guest")}
    sheet = {(r["item"], r["principal"]) for r in rows}
    assert holders <= sheet
    assert all(r["decision"] == "" and r["date"] == "" for r in rows), "decisions stay with the reviewer"


def test_redaction_gives_one_person_the_same_token_in_every_report():
    texts = [cli(sub, str(TENANT), *AS_OF, "--redact")[1] for sub in ("entra-posture", "pim-review", "access-review")]
    assert all("admin.one@example.com" not in t for t in texts)
    token = next(w for w in texts[0].split() if w.startswith("user-") and "@redacted.invalid" in w)
    token = token.strip("|`,.;()")
    assert all(token in t for t in texts), token
