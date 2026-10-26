"""Cost guards that do not depend on machine speed.

conditional-access-gap-analysis resolves who each policy covers. It used to repeat that per user for every check
(baseline coverage, CA-ZERO-TARGET, the persona matrix and the unknown-groups pass), about nine passes over users x
policies; it now resolves each policy once. On 9,000 users and 6 policies that took the run from 0.63 s to 0.21 s.
This test counts the calls instead of timing them, so it fails if a check goes back to resolving coverage itself.
"""
from __future__ import annotations

import json

from conftest import FIXTURES, load_script, run_json

GAPS = FIXTURES / "ca-gaps" / "gaps"
ca = load_script("conditional-access-gap-analysis", "ca_gaps.py")


def test_each_policy_is_resolved_once_per_user(monkeypatch):
    calls = {"n": 0}
    real = ca.Tenant.applies

    def counting(self, p, uid):
        calls["n"] += 1
        return real(self, p, uid)

    monkeypatch.setattr(ca.Tenant, "applies", counting)
    rc, rep = run_json(ca, [str(GAPS), "--config", str(FIXTURES / "ca-gaps" / "config.yaml"), "--as-of", "2026-10-04", "--json"])
    assert rc == 1 and rep["matrix"]
    users = len(json.loads((GAPS / "users.json").read_text())["value"])
    policies = json.loads((GAPS / "conditional-access-policies.json").read_text())["value"]
    enabled = sum(1 for p in policies if p.get("state") == "enabled")
    # one pass per policy, plus each break-glass account (at most every user) checked against the enabled policies;
    # the old code made 168 calls here
    assert calls["n"] <= users * len(policies) + users * enabled
