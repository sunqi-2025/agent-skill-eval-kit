# agent-skill-eval-kit

[![CI](https://github.com/sunqi-2025/agent-skill-eval-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/sunqi-2025/agent-skill-eval-kit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-3776AB.svg)](https://www.python.org/)

English | [简体中文](README.zh-CN.md)

A **zero-dependency Agent Skill static security & quality auditor** and **5-Gate Evaluation Rubric** designed for software engineering, QA, and DevOps AI workflows—usable both as a standalone Python CLI and directly as an installable **`SKILL.md` Agent Skill** (compatible with Claude Code, Cursor, Codex CLI, Gemini CLI, Antigravity, and Agensi.io).

Most Agent Skills work fine on happy-path demos but fail in production: overly broad triggers hijack unrelated prompts, raw logs blow up the context window, or helper scripts quietly ship hardcoded credentials, `shell=True`, unsafe deserialization, SQL interpolation, or unguarded database writes. This kit encodes those checks into deterministic Python (stdlib only) plus a field-tested manual review rubric.

---

## Repository Layout

```text
agent-skill-eval-kit/
├── SKILL.md                           # Installable Agent Skill entry (agentskills.io / Agensi spec)
├── scripts/
│   ├── skill_auditor.py               # Zero-dependency static quality & security auditor CLI
│   └── package_skill.py               # Builds & self-verifies clean marketplace ZIP (dist/)
├── skill_auditor.py                   # Backward-compatible root CLI wrapper
├── references/
│   └── skill-eval-rubric.md           # 5-Gate evaluation rubric & defect patterns (English)
├── rubrics/
│   └── skill-eval-rubric.md           # 5-Gate evaluation rubric (Chinese)
├── examples/
│   ├── sample-bad-skill/              # Synthetic negative fixture (for auditor tests only)
│   └── sample-good-skill/             # Compliant skill fixture
└── tests/
    └── test_skill_auditor.py          # Full unittest suite
```

---

## Quick Start

Requires **Python 3.9+**. No `pip install` needed.

```bash
# Audit a skill directory (exits non-zero on P0 security issues)
python3 scripts/skill_auditor.py examples/sample-bad-skill

# Enforce strict Agent Skills spec compliance (directory name == frontmatter name, P0 + P1 gate)
python3 scripts/skill_auditor.py . --spec --strict

# Output JSON for CI/CD pipelines
python3 scripts/skill_auditor.py examples/sample-good-skill --format json

# Write full report to disk and print a concise 1-line summary (Gate G3)
python3 scripts/skill_auditor.py examples/sample-bad-skill --output /tmp/skill-audit.md

# Switch report output to Chinese
python3 scripts/skill_auditor.py examples/sample-bad-skill --lang zh

# Run all unit tests
python3 -m unittest discover -s tests -v
```

> Backward compatibility: `python3 skill_auditor.py <target>` at the repo root remains fully supported.

---

## Built-in Static Rules

| Gate | Severity | Rule IDs | What It Checks |
| :--- | :--- | :--- | :--- |
| **G1 Trigger & Spec Hygiene** | P1 / P2 | `G1-MISSING-SKILL-MD`, `G1-MISSING-FRONTMATTER`, `G1-EMPTY-NAME`, `G1-INVALID-NAME-FORMAT`, `G1-NAME-DIR-MISMATCH`, `G1-SHORT-DESCRIPTION`, `G1-DESCRIPTION-TOO-LONG`, `G1-BROAD-TRIGGER` | Validates `SKILL.md` presence, YAML frontmatter, Agent Skills spec naming (`a-z0-9-`, 1–64 chars), description length (20–1024 chars), directory-name match (`--spec`), and overly broad trigger phrases. |
| **G3 Context Budget** | P2 | `G3-OVERSIZED-SKILL-MD`, `G3-UNBOUNDED-LOG-PRINT` | Flags oversized `SKILL.md` files (>350 lines by default) and unbounded `print(...read())` dumps that bloat conversation context. |
| **G4 Security Guardrails** | P0 / P1 | `G4-PRIVATE-KEY`, `G4-HARDCODED-SECRET`, `G4-DANGEROUS-RM`, `G4-CURL-PIPE-SHELL`, `G4-DYNAMIC-EXEC`, `G4-OS-SYSTEM`, `G4-SUBPROCESS-SHELL-TRUE`, `G4-UNSAFE-DESERIALIZATION`, `G4-SQL-TEMPLATE-INJECTION`, `G4-SQL-STRING-CONCAT`, `G4-UNGUARDED-DB-WRITE`, `G4-PROMPT-OVERRIDE` | Catches private keys, hardcoded credentials (filtering safe placeholders), destructive `rm -rf`, `curl/wget \| sh`, `eval`/`exec`, `os.system`, `shell=True`, unsafe `pickle.load`/`yaml.load`, SQL interpolation (`${}` / f-strings / concat), unguarded DB writes, and prompt-override instructions in Markdown. |
| **G5 Verification Coverage** | P2 | `G5-NO-TESTS-DIR` | Checks that the skill ships a non-empty `tests/` suite for negative-path and dirty-data regression testing. |

---

## Build Clean Marketplace Package (Agensi / Agent Skills ZIP)

To avoid marketplace security scanners false-flagging the synthetic negative fixtures under `examples/sample-bad-skill/`, build a clean runtime `.zip` archive with:

```bash
python3 scripts/package_skill.py
# Output: dist/agent-skill-eval-kit.zip (automatically unpacked, self-audited with --spec --strict, and smoke-tested)
```

---

## 5-Gate Evaluation Rubric

For manual architecture and negative-path review beyond static scanning, see:
- English: [references/skill-eval-rubric.md](references/skill-eval-rubric.md)
- 简体中文: [rubrics/skill-eval-rubric.md](rubrics/skill-eval-rubric.md)
