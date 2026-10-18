import csv
import json

from conftest import FIXTURES, load_script, run_json, run_main

mod = load_script("teams-and-groups-sprawl", "groups_sprawl.py")
T = str(FIXTURES / "groups" / "tenant")
CFG = str(FIXTURES / "groups" / "config.yaml")
BASE = ["--config", CFG, "--as-of", "2026-10-04", "--json"]


def by(rep, check):
    return {f["subject"].split(" (")[0]: f["severity"] for f in rep["findings"] if f["check"] == check}


def test_ownerless_severity_by_kind():
    rc, rep = run_json(mod, [T, *BASE])
    assert rc == 1
    assert by(rep, "GRP-OWNERLESS") == {"Finance Team": "HIGH", "TMP-old-project": "MEDIUM", "VPN Users": "LOW"}
    assert by(rep, "GRP-SINGLE-OWNER") == {"PRJ-Apollo": "LOW"}

def test_guest_owner():
    _, rep = run_json(mod, [T, *BASE])
    assert by(rep, "GRP-GUEST-OWNER") == {"PRJ-GuestOwner": "MEDIUM"}

def test_guests_public_inactive_naming_expiration():
    _, rep = run_json(mod, [T, *BASE])
    assert by(rep, "GRP-GUESTS") == {"Finance Team": "MEDIUM", "PRJ-Apollo": "LOW"}
    assert by(rep, "TEAM-PUBLIC") == {"Finance Team": "MEDIUM"}
    assert by(rep, "GRP-PUBLIC") == {"DEP-Marketing": "LOW"}
    assert by(rep, "TEAM-INACTIVE") == {"Finance Team": "LOW"}
    assert by(rep, "GRP-NAMING") == {"Finance Team": "LOW"}  # VPN Users is a security group, outside naming_applies_to
    assert by(rep, "GRP-NO-EXPIRATION") == {"Finance Team": "LOW"}
    assert by(rep, "GRP-EMPTY") == {"TMP-old-project": "LOW"}
    assert "PRJ-Zeus: not in teams-activity.csv" in rep["not_evaluated"]


def test_proposed_owner_is_most_common_manager():
    _, rep = run_json(mod, [T, *BASE])
    rows = {r["name"]: r for r in rep["cleanup"]}
    assert rows["Finance Team"]["proposed_owner"].startswith("dana@example.com (manager of 2")
    assert rows["TMP-old-project"]["proposed_owner"] == ""
    assert rows["DEP-Marketing"]["proposed_owner"] == ""  # has two owners
    assert "PRJ-Zeus" not in rows


def test_cleanup_csv(tmp_path):
    out = tmp_path / "cleanup.csv"
    rc, _, _ = run_main(mod, [T, "--config", CFG, "--as-of", "2026-10-04", "--csv", str(out)])
    assert rc == 1
    rows = list(csv.DictReader(out.open(encoding="utf-8")))
    assert rows[0]["name"] == "Finance Team" and rows[0]["decision"] == ""
    assert len(rows) == 6

def test_no_lifecycle_policy(write):
    write("groups.json", json.dumps({"value": [{"id": "g", "displayName": "X", "groupTypes": ["Unified"], "expirationDateTime": None}]}))
    write("group-lifecycle-policies.json", json.dumps({"value": []}))
    _, rep = run_json(mod, [str(write("x", "").parent), "--json"])
    assert by(rep, "EXP-NO-POLICY") == {"tenant": "MEDIUM"}
    assert any("group-owners" in s for s in rep["not_evaluated"])


def test_default_config_flags_no_naming():
    _, rep = run_json(mod, [T, "--as-of", "2026-10-04", "--json"])
    assert by(rep, "GRP-NAMING") == {}


def test_redact_hides_people():
    rc, out, _ = run_main(mod, [T, *BASE, "--redact"])
    assert rc == 1
    assert "@example.com" not in out and "Dana Example" not in out


def test_bad_config(write):
    rc, _, err = run_main(mod, [T, "--config", str(write("c.yaml", "naming_pattern: \"([\"\n"))])
    assert rc == 2 and "regular expression" in err
    rc, _, err = run_main(mod, [T, "--config", str(write("c2.yaml", "naming_applies_to: [teams]\n"))])
    assert rc == 2 and "unknown kinds" in err


def test_naming_applies_to_accepts_a_single_kind(write):
    """`naming_applies_to: team` used to be read letter by letter ("unknown kinds a, e, m, t")."""
    cfg = write("c.yaml", 'naming_pattern: "^(PRJ|DEP|TMP)-"\nnaming_applies_to: team\n')
    rc, rep = run_json(mod, [T, "--config", str(cfg), "--as-of", "2026-10-04", "--json"])
    assert rc in (0, 1) and by(rep, "GRP-NAMING") == {"Finance Team": "LOW"}


def test_activity_report_with_documented_columns(write, tmp_path):
    """getTeamsTeamActivityDetail CSV columns per the Graph v1.0 reference: Team Name, Team Id, Team Type,
    Last Activity Date (among others). A team with an old last activity is TEAM-INACTIVE."""
    import shutil

    folder = tmp_path / "t"
    shutil.copytree(T, folder)
    (folder / "teams-activity.csv").write_text(
        "Report Refresh Date,Team Name,Team Id,Team Type,Last Activity Date,Report Period,Active Users,Active Channels,Guests,"
        "Reactions,Meetings Organized,Post Messages,Reply Messages,Channel Messages,Urgent Messages,Mentions,"
        "Active Shared Channels,Active External Users\n"
        "2026-10-02,Finance Team,00000000-0000-0000-0000-000000000302,Public,2026-05-01,90,0,0,0,0,0,0,0,0,0,0,0,0\n"
        "2026-10-02,PRJ-Apollo,00000000-0000-0000-0000-000000000301,Private,2026-09-30,90,3,2,1,0,0,0,0,0,0,0,0,0\n",
        encoding="utf-8")
    _, rep = run_json(mod, [str(folder), *BASE])
    assert by(rep, "TEAM-INACTIVE") == {"Finance Team": "LOW"}


def test_activity_report_with_wrong_columns_is_bad_input(tmp_path):
    """A CSV without Team Id or Team Name and Last Activity Date used to hide every TEAM-INACTIVE finding silently."""
    import shutil

    folder = tmp_path / "t"
    shutil.copytree(T, folder)
    (folder / "teams-activity.csv").write_text("foo,bar\n1,2\n", encoding="utf-8")
    rc, out, err = run_main(mod, [str(folder), *BASE])
    assert rc == 2 and out == "" and "teams-activity.csv" in err and "Last Activity Date" in err


def test_wrong_shape_groups_file_is_bad_input(tmp_path):
    import shutil

    folder = tmp_path / "t"
    shutil.copytree(T, folder)
    (folder / "groups.json").write_text('{"displayName": "one group without an id"}', encoding="utf-8")
    rc, _, err = run_main(mod, [str(folder), *BASE])
    assert rc == 2 and "groups.json" in err and "without an id" in err
