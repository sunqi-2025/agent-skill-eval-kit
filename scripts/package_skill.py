#!/usr/bin/env python3
"""Build and verify a clean marketplace-ready ZIP archive for agent-skill-eval-kit.

Packages only runtime skill assets (SKILL.md, scripts/skill_auditor.py,
references/skill-eval-rubric.md, LICENSE, and a clean compliance smoke test)
while excluding synthetic negative fixtures so marketplace security scanners
do not false-flag intentional test payloads.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

SKILL_NAME = "agent-skill-eval-kit"

SMOKE_TEST_CONTENT = '''"""Clean compliance smoke tests bundled inside the packaged Agent Skill."""

import tempfile
import unittest
from pathlib import Path

from scripts.skill_auditor import audit_skill_dir, main, parse_frontmatter

SKILL_ROOT = Path(__file__).resolve().parents[1]


class TestPackagedSkillSmoke(unittest.TestCase):
    def test_self_audit_passes_strict_spec(self):
        report = audit_skill_dir(SKILL_ROOT, lang="en", check_dir_name=True)
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["summary"], {"P0": 0, "P1": 0, "P2": 0})

    def test_parse_frontmatter_multiline(self):
        meta, body = parse_frontmatter(
            "---\\nname: clean-demo\\ndescription: >\\n  Validate JSON contracts\\n  in staging.\\n---\\nBody\\n"
        )
        self.assertIsNotNone(meta)
        self.assertEqual(meta["name"], "clean-demo")
        self.assertEqual(meta["description"], "Validate JSON contracts in staging.")
        self.assertEqual(body.strip(), "Body")

    def test_cli_outputs_report_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "audit.json"
            rc = main([str(SKILL_ROOT), "--format", "json", "--spec", "--strict", "--output", str(out)])
            self.assertEqual(rc, 0)
            self.assertTrue(out.is_file())


if __name__ == "__main__":
    unittest.main()
'''


def build_package(repo_root: Path, output_zip: Path) -> Path:
    repo_root = repo_root.resolve()
    output_zip = output_zip.resolve()
    output_zip.parent.mkdir(parents=True, exist_ok=True)

    included_files = [
        ("SKILL.md", repo_root / "SKILL.md"),
        ("LICENSE", repo_root / "LICENSE"),
        ("scripts/__init__.py", repo_root / "scripts" / "__init__.py"),
        ("scripts/skill_auditor.py", repo_root / "scripts" / "skill_auditor.py"),
        ("references/skill-eval-rubric.md", repo_root / "references" / "skill-eval-rubric.md"),
    ]

    for rel, src in included_files:
        if not src.is_file():
            raise FileNotFoundError(f"Required package asset missing: {src} ({rel})")

    with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rel, src in included_files:
            zf.write(src, arcname=f"{SKILL_NAME}/{rel}")
        zf.writestr(f"{SKILL_NAME}/tests/test_smoke.py", SMOKE_TEST_CONTENT)

    return output_zip


def verify_package(zip_path: Path) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        with zipfile.ZipFile(zip_path, "r") as zf:
            names = zf.namelist()
            if not names:
                raise RuntimeError("ZIP archive is empty")
            top_levels = {n.split("/", 1)[0] for n in names}
            if top_levels != {SKILL_NAME}:
                raise RuntimeError(f"ZIP must unpack to single root '{SKILL_NAME}/', got {sorted(top_levels)}")
            zf.extractall(tmp_path)

        extracted_root = tmp_path / SKILL_NAME
        auditor = extracted_root / "scripts" / "skill_auditor.py"

        audit_res = subprocess.run(
            [sys.executable, str(auditor), str(extracted_root), "--spec", "--strict", "--lang", "en"],
            capture_output=True,
            text=True,
            check=False,
        )
        if audit_res.returncode != 0:
            raise RuntimeError(f"Packaged skill failed self-audit:\n{audit_res.stdout}\n{audit_res.stderr}")

        test_res = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
            cwd=str(extracted_root),
            capture_output=True,
            text=True,
            check=False,
        )
        if test_res.returncode != 0:
            raise RuntimeError(f"Packaged smoke tests failed:\n{test_res.stdout}\n{test_res.stderr}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build and verify clean marketplace ZIP for agent-skill-eval-kit.")
    parser.add_argument(
        "--output",
        default=f"dist/{SKILL_NAME}.zip",
        help="Destination ZIP file path (default: dist/agent-skill-eval-kit.zip)",
    )
    args = parser.parse_args(argv)

    repo_root = Path(__file__).resolve().parents[1]
    zip_path = build_package(repo_root, repo_root / args.output if not Path(args.output).is_absolute() else Path(args.output))
    verify_package(zip_path)
    size_kb = zip_path.stat().st_size / 1024.0
    print(f"OK: built and verified {zip_path} ({size_kb:.1f} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
