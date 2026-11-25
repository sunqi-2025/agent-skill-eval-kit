#!/usr/bin/env python3
"""Backward-compatible root CLI entrypoint for scripts/skill_auditor.py."""

from scripts.skill_auditor import (
    Finding,
    audit_skill_dir,
    main,
    parse_frontmatter,
    render_markdown,
)

__all__ = [
    "Finding",
    "audit_skill_dir",
    "main",
    "parse_frontmatter",
    "render_markdown",
]

if __name__ == "__main__":
    raise SystemExit(main())
