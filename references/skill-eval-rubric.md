# 5-Gate Evaluation Rubric for Engineering Agent Skills

This rubric comes from real-world QA, security auditing, and DevOps Agent Skill engineering. Use it to separate **production-ready workflow skills** from **demo-only prompts**.

---

## The Five Evaluation Gates

### Gate 1 — Trigger Boundary & Routing Precision
- Positive in-scope requests reliably activate the skill.
- Adjacent or out-of-scope prompts are **not** hijacked by overly broad wording.
- `SKILL.md` explicitly documents **when NOT to use this skill**.
- Frontmatter `name` matches the skill directory (lowercase alphanumeric + hyphens, 1–64 chars) and `description` stays within 1,024 chars.

### Gate 2 — Deterministic Logic Offloaded to Scripts
- Exact counts, regex/AST scans, schema diffs, HTTP contract assertions, and health probes live in deterministic scripts under `scripts/`.
- The LLM handles planning, semantic judgment, and synthesis—never guessing exact counts, exit codes, or verification verdicts.

### Gate 3 — Context Budget & Log Governance
- Long stack traces, static scan outputs, or load-test logs are written to local files first; only concise summaries, root-cause lines, and file paths return to the conversation.
- Extended rubrics and reference tables live under `references/` and are loaded on demand rather than bloating `SKILL.md`.

### Gate 4 — Code-Level Security Guardrails
- Database inspection, API checks, and environment operations default to **read-only**.
- Environment whitelists, write-confirmation gates, parameterized queries, and credential masking are enforced in executable code—not left as polite reminders in prompts.
- Zero hardcoded secrets, private keys, unsafe shell piping, dynamic code execution, or unsafe deserialization.

### Gate 5 — Negative-Path & Dirty-Data Resilience
- Test the skill intentionally against `4xx`/`5xx` HTTP errors, empty payloads, transient UI toasts, missing environment variables, and historical dirty records.
- When prerequisites fail or evidence is missing, report **FAIL / BLOCKED** honestly—never fabricate a passing outcome.

---

## Common Defect Patterns & Remediations

| Scenario | Common Skill Defect | Risk Verdict | Recommended Fix |
| :--- | :--- | :--- | :--- |
| Inactive test config noise | Flagging placeholder keys inside `dev`/`test` fixtures as critical leaks | High false-positive rate; erodes developer trust | Filter placeholder values and inactive profiles deterministically, then verify context before reporting |
| Unbounded stack trace dump | Printing 3,000+ raw framework lines directly to stdout | Exhausts context window and degrades downstream reasoning | Strip framework noise, persist full log to disk, return only root cause + file path |
| Unguarded write path | Allowing natural-language input to build SQL write statements directly | Severe accidental mutation risk | Enforce read-only default in code; require explicit environment allowlist and confirmation for writes |
| Silent toolchain failure | Missing session headers in multi-step API calls return empty body, yet skill reports success | False green hiding broken workflow | Assert both HTTP status and non-empty business fields; convert unexpected states to explicit `ERROR` / `REVIEW` |
