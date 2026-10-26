"""Every skill has a README.md whose sample is the real output of its script on a committed fixture."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "render_skill_readmes.py"


def test_skill_readmes_match_the_scripts_output():
    proc = subprocess.run([sys.executable, str(SCRIPT), "--check"], cwd=ROOT, capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stderr


def test_every_skill_has_a_readme_with_a_sample():
    for skill in (ROOT / "plugins" / "m365-governance" / "skills").iterdir():
        if (skill / "SKILL.md").is_file():
            text = (skill / "README.md").read_text(encoding="utf-8")
            assert "## Sample" in text and "````markdown" in text, skill.name
