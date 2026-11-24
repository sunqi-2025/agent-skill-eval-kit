---
name: sample-good-skill
description: Validate HTTP API response schemas and contract invariants against expected JSON fields in staging environments. Do not use for production write mutations.
---

# Sample Good Skill

## Trigger Boundary
- Use when verifying API response status codes and required JSON keys in test/staging environments.
- Do not execute database writes or production configuration changes.

## Execution
Run `scripts/check_contract.py` and review the summarized output file.
