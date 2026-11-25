---
name: agent-skill-eval-kit
description: Audit AI Agent Skills (SKILL.md directories) for trigger hygiene, YAML frontmatter spec compliance, hardcoded secrets, command/SQL injection, unsafe deserialization, unguarded DB writes, and context-window bloat using a zero-dependency Python CLI and 5-gate evaluation rubric. Do not use for general application codebases without SKILL.md.
license: MIT
compatibility: Python 3.9+ standard library only (zero third-party packages required)
metadata:
  author: sunqi-2025
  version: "1.1.0"
---

# Agent Skill Eval Kit

Deterministic static security auditing and practical 5-gate evaluation for engineering, QA, and DevOps Agent Skills.

## When to Use This Skill
- Auditing a local Agent Skill folder (`SKILL.md` + `scripts/` + `references/`) before publishing, sharing with teammates, or submitting to a marketplace.
- Checking a skill for P0/P1 security risks (leaked secrets, command injection, unsafe deserialization, SQL interpolation, unguarded writes, prompt-override lines).
- Evaluating whether a workflow skill enforces clear trigger boundaries, context-window hygiene, and dirty-data resilience.

## When NOT to Use This Skill
- Do not trigger on ordinary web/backend repositories that are not packaged as an Agent Skill.
- Do not modify target skill files without explicit user approval; report findings and concrete fixes first.

## Workflow

### Step 1: Run Deterministic Static Audit
Always run the bundled zero-dependency Python CLI first instead of eyeballing code manually:

```bash
python3 scripts/skill_auditor.py <path-to-skill-dir> --spec --strict
```

Useful flags:
- `--format json` for machine-readable CI/CD gates
- `--lang zh` for Chinese report output (default is `en`)
- `--output <report.md>` to persist verbose findings to disk and keep conversation context clean (Gate G3)
- `--max-lines 350` to customize the `SKILL.md` line budget

Exit codes:
- `0`: No P0 findings (and no P1 findings when `--strict` is set)
- `1`: Blocking findings detected
- `2`: Invalid target directory

### Step 2: Apply the 5-Gate Manual Review Rubric
Read `references/skill-eval-rubric.md` on demand when performing a deeper design review covering:
1. **Gate 1 — Trigger Boundary & Routing Precision**
2. **Gate 2 — Deterministic Logic in Scripts (not LLM guesswork)**
3. **Gate 3 — Context Budget & Log Persistence**
4. **Gate 4 — Code-Level Security Guardrails**
5. **Gate 5 — Negative-Path & Dirty-Data Resilience**

### Step 3: Report Verdict & Actionable Fixes
Present findings grouped by severity (`P0` blocking -> `P1` high -> `P2` hygiene), cite exact `file:line` locations from the CLI output, and never claim a skill passed if any `P0` issue remains unresolved or if the CLI could not execute cleanly.
