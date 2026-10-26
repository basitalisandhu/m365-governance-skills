"""Seeded fuzz tests for every script that reads tenant exports, config files or CSV reports.

Each case copies a real fixture folder, damages one file in a random but repeatable way (a value of the wrong type,
a missing key, a truncated file, a different top-level shape, bytes that are not UTF-8) and runs the script. Bad input
may change the findings or exit 2 with a message on stderr; it must never raise a traceback.

The seed is fixed so a failure reproduces. FUZZ_ITERATIONS (default 30) sets the cases per fixture; raise it locally
for a deeper run, for example FUZZ_ITERATIONS=500 python -m pytest tests/test_fuzz_exports.py.
"""
from __future__ import annotations

import copy
import json
import os
import random
import shutil
from pathlib import Path

import pytest
from conftest import FIXTURES, load_script, run_main

ITERATIONS = int(os.environ.get("FUZZ_ITERATIONS", "30"))
AS_OF = ["--as-of", "2026-10-04", "--json"]

# (skill, script, fixture folder, config file or None, extra arguments)
CASES = [
    ("access-review-pack", "access_review_pack.py", "access-review/tenant", "access-review/config.yaml", []),
    ("conditional-access-gap-analysis", "ca_gaps.py", "ca-gaps/gaps", "ca-gaps/config.yaml", []),
    ("copilot-oversharing-readiness", "copilot_readiness.py", "copilot/tenant", None, []),
    ("entra-posture-review", "entra_posture.py", "entra/insecure", "entra/config.yaml", []),
    ("guest-and-external-sharing-review", "external_sharing.py", "external-sharing/tenant", "external-sharing/config.yaml", []),
    ("intune-baseline-check", "intune_baseline.py", "intune/estate", "intune/config.yaml", []),
    ("license-and-service-plan-audit", "license_audit.py", "license-audit/tenant", "license-audit/config.yaml", []),
    ("privileged-access-review", "pim_review.py", "pim-review/tenant", "pim-review/config.yaml", []),
    ("teams-and-groups-sprawl", "groups_sprawl.py", "groups/tenant", "groups/config.yaml", []),
    ("graph-permission-preflight", "permission_preflight.py", "preflight/over-broad", None, ["--needs", "{dir}/needs.yaml"]),
    ("graph-permission-preflight", "permission_preflight.py", "preflight/connector", None, ["--needs", "{dir}/needs.json"]),
    ("graph-permission-preflight", "permission_preflight.py", "preflight/consent-url", None, ["--needs", "{dir}/needs.yaml"]),
]

ODD_VALUES = [None, 0, -1, 3.5, True, False, "", "x", "not-a-date", "0001-01-01T00:00:00Z", "9999-12-31T23:59:59Z",
              [], {}, [1, 2], {"a": 1}, ["x"], [None], "a|b`c\nd", "1e309", 10**20]


def _paths(node, prefix=()):
    """Every (container, key) pair in a JSON document."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield node, k
            yield from _paths(v, prefix + (k,))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield node, i
            yield from _paths(v, prefix + (i,))


def mutate_json(data, rng: random.Random):
    data = copy.deepcopy(data)
    slots = list(_paths(data))
    roll = rng.random()
    if not slots or roll < 0.08:
        return rng.choice(ODD_VALUES + [[data], {"value": data}, {"value": {"id": 1}}, {"error": {"code": "x"}}])
    container, key = rng.choice(slots)
    if roll < 0.25 and isinstance(container, dict):
        del container[key]
    elif roll < 0.35 and isinstance(container, list):
        container.append(rng.choice(ODD_VALUES))
    else:
        container[key] = rng.choice(ODD_VALUES)
    return data


def mutate_text(text: str, rng: random.Random) -> bytes:
    roll = rng.random()
    raw = text.encode("utf-8")
    if roll < 0.3:
        return raw[: rng.randrange(0, max(1, len(raw)))]
    if roll < 0.5:
        return b"\xff\xfe\x00garbage" + raw[:20]
    lines = text.splitlines(keepends=True)
    if lines:
        i = rng.randrange(len(lines))
        lines[i] = rng.choice(["", ",,,,\n", '"unterminated\n', "a,b\n", lines[i] * 3, "\x00\n"])
    return "".join(lines).encode("utf-8", "surrogatepass")


def damage(folder: Path, rng: random.Random) -> str:
    files = sorted(p for p in folder.rglob("*") if p.is_file())
    target = rng.choice(files)
    text = target.read_text(encoding="utf-8")
    if target.suffix == ".json" and rng.random() < 0.8:
        try:
            new = mutate_json(json.loads(text), rng)
            target.write_text(json.dumps(new), encoding="utf-8")
            return f"{target.name}: json mutation"
        except ValueError:
            pass
    target.write_bytes(mutate_text(text, rng))
    return f"{target.name}: text mutation"


def check_run(mod, argv, what):
    try:
        rc, out, err = run_main(mod, argv)
    except Exception as exc:  # noqa: BLE001 (the point of the test)
        pytest.fail(f"{what}: traceback {type(exc).__name__}: {exc}")
    assert rc in (0, 1, 2), f"{what}: exit {rc}"
    if rc == 2:
        assert err.strip(), f"{what}: exit 2 with no message"


@pytest.mark.parametrize("case", CASES, ids=[f"{c[0]}:{c[2]}" for c in CASES])
def test_damaged_exports_never_raise(case, tmp_path):
    skill, script, fixture, config, extra = case
    mod = load_script(skill, script)
    rng = random.Random(f"{skill}:{fixture}")
    for i in range(ITERATIONS):
        work = tmp_path / f"run{i}"
        shutil.copytree(FIXTURES / fixture, work)
        what = f"seed {skill}:{fixture} iteration {i}, " + damage(work, rng)
        argv = [str(work), *AS_OF, *[a.replace("{dir}", str(work)) for a in extra]]
        if config:
            argv += ["--config", str(FIXTURES / config)]
        check_run(mod, argv, what)


@pytest.mark.parametrize("case", [c for c in CASES if c[3]], ids=[c[0] for c in CASES if c[3]])
def test_damaged_config_never_raises(case, tmp_path):
    skill, script, fixture, config, extra = case
    mod = load_script(skill, script)
    rng = random.Random(f"config:{skill}")
    text = (FIXTURES / config).read_text(encoding="utf-8")
    for i in range(ITERATIONS):
        cfg = tmp_path / f"c{i}.yaml"
        cfg.write_bytes(mutate_text(text, rng) if rng.random() < 0.6 else
                        rng.choice([b"- a\n- b\n", b"key: [unclosed\n", b"a: b: c\n", b"\t- x\n", b"!!python/object x\n",
                                    b"stale_days: -5\n", b"stale_days: yes\n", b"{\"a\": 1}\n", b"? x\n"]))
        check_run(mod, [str(FIXTURES / fixture), *AS_OF, "--config", str(cfg)], f"config seed {skill} iteration {i}")


YAML_ALPHABET = list("ab:- \n\t#'\"[]{},|>&*!?%@`0123456789.") + ["\n  ", ": ", "- ", "key: ", "  - x\n"]


def test_miniyaml_random_text_raises_only_yamlerror():
    """The config parser reads files from outside: on any text it returns a value or raises YAMLError, and it ends.
    (A hang here shows up as the job's timeout.)"""
    yaml = load_script("access-review-pack", "_miniyaml.py")
    rng = random.Random("miniyaml")
    for i in range(ITERATIONS * 200):
        text = "".join(rng.choice(YAML_ALPHABET) for _ in range(rng.randrange(1, 60)))
        try:
            yaml.load(text)
        except yaml.YAMLError:
            pass
        except Exception as exc:  # noqa: BLE001
            pytest.fail(f"iteration {i}: {type(exc).__name__}: {exc} on {text!r}")


@pytest.mark.parametrize("text", ["- - -:", "a: [{x: 1}: 2]", "- [[1]: 2]"])
def test_miniyaml_inputs_found_by_fuzzing(text):
    """"- - -:" used to loop for ever and a flow collection used as a key raised TypeError."""
    yaml = load_script("access-review-pack", "_miniyaml.py")
    with pytest.raises(yaml.YAMLError):
        yaml.load(text)


@pytest.mark.parametrize("case", CASES[:9], ids=[c[0] for c in CASES[:9]])
def test_json_nested_too_deep_exits_2(case, tmp_path):
    """JSON nested deeper than Python's recursion limit raised RecursionError from json.loads."""
    skill, script, fixture, config, extra = case
    mod = load_script(skill, script)
    work = tmp_path / "t"
    shutil.copytree(FIXTURES / fixture, work)
    target = sorted(work.glob("*.json"))[0]
    target.write_text("[" * 100_000 + "]" * 100_000, encoding="utf-8")
    rc, _, err = run_main(mod, [str(work), *AS_OF])
    assert rc == 2 and "RecursionError" in err, err


def test_powershell_date_beyond_the_platform_range_is_ignored(tmp_path):
    """A "/Date(...)/" value too large for datetime raised OverflowError; it now reads as no date."""
    mod = load_script("copilot-oversharing-readiness", "copilot_readiness.py")
    assert mod.parse_dt("/Date(99999999999999999999)/") is None
    assert mod.parse_dt("/Date(1790000000000)/").year == 2026
