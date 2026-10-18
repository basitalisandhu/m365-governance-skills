import csv

from conftest import FIXTURES, load_script, run_json, run_main

mod = load_script("license-and-service-plan-audit", "license_audit.py")
T = str(FIXTURES / "license-audit" / "tenant")
TIDY = str(FIXTURES / "license-audit" / "tidy")
CFG = str(FIXTURES / "license-audit" / "config.yaml")
BASE = ["--config", CFG, "--as-of", "2026-10-04", "--json"]


def checks(rep, check):
    return [f for f in rep["findings"] if f["check"] == check]


def test_planted_disabled_account_with_e5():
    rc, rep = run_json(mod, [T, *BASE])
    assert rc == 1
    [f] = checks(rep, "LIC-DISABLED-ACCOUNT")
    assert (f["subject"], f["evidence"]) == ("left.employee@example.com", "licences: SPE_E5; last sign-in 2026-06-01")
    assert {"user": "left.employee@example.com", "sku": "SPE_E5", "reasons": ["account disabled"], "assigned_by": "direct",
            "last_sign_in": "2026-06-01"} in rep["reclaim"]


def test_all_planted_checks():
    _, rep = run_json(mod, [T, *BASE])
    assert rep["counts"] == {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 3, "LOW": 4, "INFO": 2}
    assert [f["subject"] for f in checks(rep, "LIC-NEVER-SIGNED-IN")] == ["never.used@example.com"]
    assert [f["subject"] for f in checks(rep, "LIC-INACTIVE")] == ["quiet.user@example.com"]
    assert all(f["subject"] != "left.employee@example.com" for f in checks(rep, "LIC-INACTIVE"))


def test_tidy_tenant_is_clean():
    rc, rep = run_json(mod, [TIDY, *BASE])
    assert rc == 0 and rep["findings"] == [] and rep["reclaim"] == []


def test_overlap_from_service_plans():
    _, rep = run_json(mod, [T, *BASE])
    [f] = checks(rep, "LIC-OVERLAP")
    assert f["subject"] == "double.licensed@example.com"
    assert f["evidence"] == "7 of 7 service plans of ENTERPRISEPACK are also in SPE_E5"
    reclaim = [(r["user"], r["sku"]) for r in rep["reclaim"] if r["user"] == "double.licensed@example.com"]
    assert reclaim == [("double.licensed@example.com", "ENTERPRISEPACK")]


def test_overlap_ratio_and_configured_pairs(write):
    strict = write("c.yaml", "overlap_ratio: 1.5\n")
    _, rep = run_json(mod, [T, "--config", str(strict), "--as-of", "2026-10-04", "--json"])
    assert not checks(rep, "LIC-OVERLAP")
    paired = write("p.yaml", "overlap_ratio: 1.5\noverlapping_skus: [[SPE_E5, ENTERPRISEPACK]]\n")
    _, rep = run_json(mod, [T, "--config", str(paired), "--as-of", "2026-10-04", "--json"])
    assert "listed under overlapping_skus" in checks(rep, "LIC-OVERLAP")[0]["evidence"]


def test_unwanted_plans_respect_disabled_plans():
    _, rep = run_json(mod, [T, *BASE])
    plans = {f["subject"]: f["evidence"] for f in checks(rep, "LIC-UNWANTED-PLAN")}
    assert plans == {"SWAY": "enabled for 4 user(s) through ENTERPRISEPACK, SPE_E5",
                     "YAMMER_ENTERPRISE": "enabled for 4 user(s) through ENTERPRISEPACK, SPE_E5"}


def test_group_based_licensing_error():
    _, rep = run_json(mod, [T, *BASE])
    [f] = checks(rep, "LIC-GROUP-ERROR")
    assert f["subject"] == "Licence - Microsoft 365 E5" and f["evidence"] == "1 user(s), errors: CountViolation"


def test_counts_per_sku_and_no_invented_prices():
    _, rep = run_json(mod, [T, *BASE])
    per = {e["sku"]: e for e in rep["per_sku"]}
    assert per["SPE_E5"] == {"sku": "SPE_E5", "purchased": 6, "assigned": 4, "spare": 2, "reclaimable": 1}
    assert per["ENTERPRISEPACK"]["reclaimable"] == 3
    assert all("unit_cost" not in e and "estimated_total" not in e for e in rep["per_sku"])


def test_totals_only_from_supplied_unit_costs(write):
    cfg = write("c.yaml", "unit_costs:\n  ENTERPRISEPACK: 2.5\ncost_label: example units\n")
    rc, out, _ = run_main(mod, [T, "--config", str(cfg), "--as-of", "2026-10-04"])
    assert "| ENTERPRISEPACK | 5 | 3 | 2 | 3 | 2.5 | 12.5 |" in out
    assert "| SPE_E5 | 6 | 4 | 2 | 1 | not supplied | - |" in out and "(example units)" in out


def test_reclaim_csv_and_redact(tmp_path):
    path = tmp_path / "reclaim.csv"
    rc, _, _ = run_main(mod, [T, *BASE, "--csv", str(path), "--redact"])
    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    assert rc == 1 and len(rows) == 4 and list(rows[0]) == ["user", "sku", "reasons", "assigned_by", "last_sign_in", "decision"]
    assert all("@example.com" not in r["user"] and r["decision"] == "" for r in rows)


def test_bad_config(write):
    rc, _, err = run_main(mod, [T, "--config", str(write("c.yaml", "unit_costs: {SPE_E5: lots}\n"))])
    assert rc == 2 and "unit_costs" in err
    rc, _, err = run_main(mod, [T, "--config", str(write("d.yaml", "overlapping_skus: [SPE_E5]\n"))])
    assert rc == 2 and "overlapping_skus" in err


def test_single_unwanted_plan_as_a_string(write):
    """`unwanted_service_plans: SWAY` used to be read letter by letter and matched nothing."""
    one = write("c.yaml", "unwanted_service_plans: SWAY\n")
    _, rep = run_json(mod, [T, "--config", str(one), "--as-of", "2026-10-04", "--json"])
    assert [f["subject"] for f in checks(rep, "LIC-UNWANTED-PLAN")] == ["SWAY"]
    rc, _, err = run_main(mod, [T, "--config", str(write("d.yaml", "unwanted_service_plans: {SWAY: true}\n"))])
    assert rc == 2 and "must be a list of names or ids" in err


def test_documented_license_assignment_error_values(write, tmp_path):
    """licenseAssignmentState.error values from the Graph v1.0 reference (CountViolation, MutuallyExclusiveViolation,
    DependencyViolation, ProhibitedInUsageLocationViolation, UniquenessViolation, Other) with state Error or
    ActiveWithError on a group-assigned licence each raise LIC-GROUP-ERROR."""
    import json
    import shutil

    folder = tmp_path / "t"
    shutil.copytree(T, folder)
    skus = json.loads((folder / "subscribed-skus.json").read_text(encoding="utf-8"))
    sku = (skus["value"] if isinstance(skus, dict) else skus)[0]["skuId"]
    errors = ["CountViolation", "MutuallyExclusiveViolation", "DependencyViolation", "ProhibitedInUsageLocationViolation",
              "UniquenessViolation", "Other"]
    users = [{"id": f"00000000-0000-0000-0000-0000000009{i:02d}", "userPrincipalName": f"e{i}@example.com", "displayName": f"E {i}",
              "accountEnabled": True, "createdDateTime": "2025-01-01T00:00:00Z", "assignedLicenses": [],
              "signInActivity": {"lastSignInDateTime": "2026-10-01T00:00:00Z"},
              "licenseAssignmentStates": [{"skuId": sku, "assignedByGroup": "00000000-0000-0000-0000-000000000777",
                                           "state": "Error" if i % 2 else "ActiveWithError", "error": err, "disabledPlans": []}]}
             for i, err in enumerate(errors)]
    (folder / "users.json").write_text(json.dumps({"value": users}), encoding="utf-8")
    _, rep = run_json(mod, [str(folder), "--as-of", "2026-10-04", "--json"])
    [f] = checks(rep, "LIC-GROUP-ERROR")
    assert all(e in f["evidence"] for e in errors) and "6 user(s)" in f["evidence"]


def test_wrong_shape_subscribed_skus_is_bad_input(tmp_path):
    import shutil

    folder = tmp_path / "t"
    shutil.copytree(T, folder)
    (folder / "subscribed-skus.json").write_text('{"skuPartNumber": "ENTERPRISEPACK"}', encoding="utf-8")
    rc, out, err = run_main(mod, [str(folder), "--as-of", "2026-10-04"])
    assert rc == 2 and out == "" and "subscribed-skus.json" in err and "without an id" in err
