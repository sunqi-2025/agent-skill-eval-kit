import json
import tempfile
import unittest
from pathlib import Path

from skill_auditor import audit_skill_dir, main, parse_frontmatter


REPO_ROOT = Path(__file__).resolve().parents[1]


class TestSkillAuditor(unittest.TestCase):
    def test_good_skill_passes_cleanly(self):
        report = audit_skill_dir(REPO_ROOT / "examples" / "sample-good-skill")
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["summary"], {"P0": 0, "P1": 0, "P2": 0})
        self.assertEqual(report["findings"], [])

    def test_bad_skill_catches_security_and_hygiene_issues(self):
        report = audit_skill_dir(REPO_ROOT / "examples" / "sample-bad-skill")
        self.assertEqual(report["status"], "FAIL")
        rule_ids = {f["rule_id"] for f in report["findings"]}
        self.assertIn("G4-HARDCODED-SECRET", rule_ids)
        self.assertIn("G4-SUBPROCESS-SHELL-TRUE", rule_ids)
        self.assertIn("G4-SQL-STRING-CONCAT", rule_ids)
        self.assertIn("G4-UNGUARDED-DB-WRITE", rule_ids)
        self.assertIn("G3-UNBOUNDED-LOG-PRINT", rule_ids)
        self.assertIn("G1-BROAD-TRIGGER", rule_ids)
        self.assertIn("G5-NO-TESTS-DIR", rule_ids)

    def test_missing_frontmatter_and_oversized_skill_md(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SKILL.md").write_text("# No Frontmatter\n" + ("line\n" * 400), encoding="utf-8")
            report = audit_skill_dir(root, max_skill_md_lines=350)
            rule_ids = {f["rule_id"] for f in report["findings"]}
            self.assertIn("G1-MISSING-FRONTMATTER", rule_ids)
            self.assertIn("G3-OVERSIZED-SKILL-MD", rule_ids)

    def test_mybatis_dollar_sql_and_os_system_caught(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SKILL.md").write_text(
                "---\nname: demo-sql\ndescription: Inspect read-only database schemas and migration diffs.\n---\n",
                encoding="utf-8",
            )
            scripts = root / "scripts"
            scripts.mkdir()
            (scripts / "bad.xml").write_text(
                "<select>SELECT * FROM t WHERE name = ${userName}</select>\n",
                encoding="utf-8",
            )
            (scripts / "cmd.py").write_text(
                "import os\ndef f(x):\n    os.system('ls ' + x)\n",
                encoding="utf-8",
            )
            report = audit_skill_dir(root)
            rule_ids = {f["rule_id"] for f in report["findings"]}
            self.assertIn("G4-SQL-TEMPLATE-INJECTION", rule_ids)
            self.assertIn("G4-OS-SYSTEM", rule_ids)
            self.assertGreaterEqual(report["summary"]["P0"], 2)

    def test_placeholder_secret_is_not_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SKILL.md").write_text(
                "---\nname: safe-demo\ndescription: Validate configuration templates in local staging environments.\n---\n",
                encoding="utf-8",
            )
            scripts = root / "scripts"
            scripts.mkdir()
            (scripts / "cfg.py").write_text('API_KEY = "your_placeholder_key_here"\n', encoding="utf-8")
            (root / "tests").mkdir()
            (root / "tests" / "test_ok.py").write_text("assert True\n", encoding="utf-8")
            report = audit_skill_dir(root)
            self.assertEqual(report["status"], "PASS")

    def test_cli_exit_codes_and_json_output(self):
        self.assertEqual(main([str(REPO_ROOT / "examples" / "sample-good-skill")]), 0)
        self.assertEqual(main([str(REPO_ROOT / "examples" / "sample-bad-skill")]), 1)

    def test_parse_frontmatter_multiline(self):
        meta, body = parse_frontmatter(
            "---\nname: test-skill\ndescription: >\n  Line one\n  line two.\n---\nHello\n"
        )
        self.assertEqual(meta["name"], "test-skill")
        self.assertEqual(meta["description"], "Line one line two.")
        self.assertEqual(body.strip(), "Hello")


if __name__ == "__main__":
    unittest.main()
