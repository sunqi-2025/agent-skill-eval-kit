#!/usr/bin/env python3
"""Zero-dependency static quality and security auditor for Agent Skills.

Checks:
- G1: SKILL.md presence, YAML frontmatter (name/description), trigger hygiene
- G3: Context budget (SKILL.md size & unbounded stdout log printing)
- G4: Code-level security guardrails (hardcoded secrets, shell=True/RCE,
      SQL string interpolation, unguarded DB write statements)
- G5: Test suite presence for dirty-data and negative-path verification
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Tuple


@dataclass
class Finding:
    rule_id: str
    severity: str  # P0, P1, P2
    gate: str      # G1, G3, G4, G5
    file: str
    line: Optional[int]
    message: str


BROAD_TRIGGER_PHRASES = (
    "anything",
    "everything",
    "all tasks",
    "任何任务",
    "所有问题",
    "万能",
)

SECRET_ASSIGN_RE = re.compile(
    r"""(?i)\b(api[_-]?key|api[_-]?secret|access[_-]?token|secret[_-]?key|password|passwd|db[_-]?pass)\b\s*[:=]\s*['"]([^'"]{8,})['"]"""
)

PRIVATE_KEY_HEADER_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")

SAFE_PLACEHOLDER_HINTS = (
    "example",
    "placeholder",
    "your_",
    "changeme",
    "redacted",
    "dummy",
    "<",
    "${",
    "os.environ",
)

DANGEROUS_SHELL_RE = re.compile(r"\brm\s+-rf\s+(/|\$|\*|~)")
MYBATIS_DOLLAR_SQL_RE = re.compile(r"(?i)\b(select|insert|update|delete|where|order\s+by)\b[^\n]*\$\{[^}]+\}")
SQL_FSTRING_RE = re.compile(r"""(?i)f['"][^'"]*\b(select|insert|update|delete|drop)\b[^'"]*\{[^}]+\}""")
SQL_PERCENT_OR_PLUS_RE = re.compile(
    r"""(?i)['"][^'"]*\b(select|insert|update|delete|drop)\b[^'"]*['"]\s*(\+|%\s|\.\s*format\()"""
)
SQL_WRITE_RE = re.compile(r"""(?i)\b(delete\s+from|update\s+\w+\s+set|drop\s+(table|database)|truncate\s+table)\b""")
GUARD_HINT_RE = re.compile(r"(?i)(read_only|readonly|allow_write|whitelist|confirm|dry_run|env\s*==\s*['\"]test)")
UNBOUNDED_READ_PRINT_RE = re.compile(r"print\s*\([^)]*\.read\s*\(\s*\)\s*\)")

IGNORED_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", ".pytest_cache"}


def parse_frontmatter(content: str) -> Tuple[Optional[dict], str]:
    """Parse minimal YAML frontmatter delimited by leading '---' lines."""
    lines = content.splitlines()
    if len(lines) < 3 or lines[0].strip() != "---":
        return None, content

    end_idx = None
    for idx in range(1, len(lines)):
        if lines[idx].strip() == "---":
            end_idx = idx
            break
    if end_idx is None:
        return None, content

    meta: dict[str, str] = {}
    current_key: Optional[str] = None
    for raw in lines[1:end_idx]:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if re.match(r"^[A-Za-z0-9_-]+\s*:", raw):
            key, val = raw.split(":", 1)
            current_key = key.strip()
            cleaned = val.strip().strip("\"'")
            meta[current_key] = "" if cleaned in ("|", ">") else cleaned
        elif current_key and raw.startswith((" ", "\t")):
            sep = " " if meta[current_key] else ""
            meta[current_key] = f"{meta[current_key]}{sep}{raw.strip()}"

    body = "\n".join(lines[end_idx + 1 :])
    return meta, body


def _is_placeholder_secret(value: str) -> bool:
    low = value.strip().lower()
    return any(hint in low for hint in SAFE_PLACEHOLDER_HINTS)


def _iter_files(root: Path, exts: Tuple[str, ...]) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in IGNORED_DIRS)
        for fname in sorted(filenames):
            p = Path(dirpath) / fname
            if p.suffix.lower() in exts:
                yield p


def _audit_skill_md(skill_dir: Path, findings: List[Finding], max_lines: int) -> None:
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.is_file():
        findings.append(
            Finding(
                rule_id="G1-MISSING-SKILL-MD",
                severity="P1",
                gate="G1",
                file="SKILL.md",
                line=None,
                message="缺少 SKILL.md 入口说明文件。",
            )
        )
        return

    text = skill_md.read_text(encoding="utf-8", errors="replace")
    meta, body = parse_frontmatter(text)
    if meta is None:
        findings.append(
            Finding(
                rule_id="G1-MISSING-FRONTMATTER",
                severity="P1",
                gate="G1",
                file="SKILL.md",
                line=1,
                message="SKILL.md 缺少标准 YAML frontmatter（--- 区块），影响路由解析。",
            )
        )
    else:
        name = (meta.get("name") or "").strip()
        desc = (meta.get("description") or "").strip()
        if not name:
            findings.append(
                Finding(
                    rule_id="G1-EMPTY-NAME",
                    severity="P1",
                    gate="G1",
                    file="SKILL.md",
                    line=1,
                    message="frontmatter 中缺少 name 字段。",
                )
            )
        if len(desc) < 20:
            findings.append(
                Finding(
                    rule_id="G1-SHORT-DESCRIPTION",
                    severity="P2",
                    gate="G1",
                    file="SKILL.md",
                    line=1,
                    message="description 过短（<20 字符），触发条件不够明确。",
                )
            )
        low_desc = desc.lower()
        for phrase in BROAD_TRIGGER_PHRASES:
            if phrase in low_desc:
                findings.append(
                    Finding(
                        rule_id="G1-BROAD-TRIGGER",
                        severity="P2",
                        gate="G1",
                        file="SKILL.md",
                        line=1,
                        message=f"description 包含过宽触发词「{phrase}」，容易误抢无关任务。",
                    )
                )
                break

    line_count = len(text.splitlines())
    if line_count > max_lines:
        findings.append(
            Finding(
                rule_id="G3-OVERSIZED-SKILL-MD",
                severity="P2",
                gate="G3",
                file="SKILL.md",
                line=line_count,
                message=f"SKILL.md 共 {line_count} 行（超过 {max_lines} 行阈值），建议将长参考口径拆入 references/ 按需加载。",
            )
        )

    _scan_text_lines(skill_md, skill_dir, text, findings, is_code=False)


def _scan_text_lines(
    path: Path,
    root: Path,
    text: str,
    findings: List[Finding],
    *,
    is_code: bool,
) -> None:
    rel = str(path.relative_to(root))
    has_guard_hint = bool(GUARD_HINT_RE.search(text))

    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if is_code and stripped.startswith("#"):
            continue

        if PRIVATE_KEY_HEADER_RE.search(line):
            findings.append(
                Finding(
                    rule_id="G4-PRIVATE-KEY",
                    severity="P0",
                    gate="G4",
                    file=rel,
                    line=lineno,
                    message="检测到私钥块头（PRIVATE KEY），存在严重凭据泄露风险。",
                )
            )

        secret_match = SECRET_ASSIGN_RE.search(line)
        if secret_match and not _is_placeholder_secret(secret_match.group(2)):
            findings.append(
                Finding(
                    rule_id="G4-HARDCODED-SECRET",
                    severity="P0",
                    gate="G4",
                    file=rel,
                    line=lineno,
                    message=f"检测到疑似硬编码凭据字段「{secret_match.group(1)}」，请改用环境变量注入。",
                )
            )

        if DANGEROUS_SHELL_RE.search(line):
            findings.append(
                Finding(
                    rule_id="G4-DANGEROUS-RM",
                    severity="P0",
                    gate="G4",
                    file=rel,
                    line=lineno,
                    message="检测到高危递归删除命令（rm -rf 根目录/变量/通配符）。",
                )
            )

        if MYBATIS_DOLLAR_SQL_RE.search(line):
            findings.append(
                Finding(
                    rule_id="G4-SQL-TEMPLATE-INJECTION",
                    severity="P0",
                    gate="G4",
                    file=rel,
                    line=lineno,
                    message="SQL 中出现 ${} 直接插值，存在 SQL 注入风险，请改为参数化占位符。",
                )
            )

        if is_code:
            if SQL_FSTRING_RE.search(line) or SQL_PERCENT_OR_PLUS_RE.search(line):
                findings.append(
                    Finding(
                        rule_id="G4-SQL-STRING-CONCAT",
                        severity="P0",
                        gate="G4",
                        file=rel,
                        line=lineno,
                        message="检测到字符串拼接构造 SQL，存在注入风险，请改用参数绑定。",
                    )
                )

            if SQL_WRITE_RE.search(line) and not has_guard_hint:
                findings.append(
                    Finding(
                        rule_id="G4-UNGUARDED-DB-WRITE",
                        severity="P1",
                        gate="G4",
                        file=rel,
                        line=lineno,
                        message="脚本包含数据库写操作但未检测到只读/白名单/确认护栏。",
                    )
                )

            if UNBOUNDED_READ_PRINT_RE.search(line):
                findings.append(
                    Finding(
                        rule_id="G3-UNBOUNDED-LOG-PRINT",
                        severity="P2",
                        gate="G3",
                        file=rel,
                        line=lineno,
                        message="检测到直接打印整份文件读取结果（.read()），长日志易撑爆对话上下文，建议落盘并截断摘要。",
                    )
                )


def _audit_python_ast(path: Path, root: Path, text: str, findings: List[Finding]) -> None:
    rel = str(path.relative_to(root))
    try:
        tree = ast.parse(text, filename=rel)
    except SyntaxError as exc:
        findings.append(
            Finding(
                rule_id="G4-PYTHON-SYNTAX-ERROR",
                severity="P1",
                gate="G4",
                file=rel,
                line=exc.lineno,
                message=f"Python 语法错误，无法完成 AST 检查：{exc.msg}",
            )
        )
        return

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        # Check eval(...) / exec(...)
        if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
            findings.append(
                Finding(
                    rule_id="G4-DYNAMIC-EXEC",
                    severity="P0",
                    gate="G4",
                    file=rel,
                    line=node.lineno,
                    message=f"检测到动态代码执行 {node.func.id}()，存在命令/代码注入风险。",
                )
            )

        # Check os.system(...)
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "os"
            and node.func.attr == "system"
        ):
            findings.append(
                Finding(
                    rule_id="G4-OS-SYSTEM",
                    severity="P0",
                    gate="G4",
                    file=rel,
                    line=node.lineno,
                    message="检测到 os.system() 调用，建议改用 subprocess.run([...], shell=False)。",
                )
            )

        # Check subprocess.*(..., shell=True)
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                findings.append(
                    Finding(
                        rule_id="G4-SUBPROCESS-SHELL-TRUE",
                        severity="P0",
                        gate="G4",
                        file=rel,
                        line=node.lineno,
                        message="检测到 shell=True，存在命令注入风险，请改为参数数组调用。",
                    )
                )


def audit_skill_dir(skill_dir: Path, max_skill_md_lines: int = 350) -> dict:
    """Audit a single Skill directory and return a structured report."""
    skill_dir = skill_dir.resolve()
    findings: List[Finding] = []

    _audit_skill_md(skill_dir, findings, max_lines=max_skill_md_lines)

    code_exts = (".py", ".sh", ".bash", ".js", ".ts", ".sql", ".xml")
    scripts_dir = skill_dir / "scripts"
    scan_root = scripts_dir if scripts_dir.is_dir() else skill_dir

    for file_path in _iter_files(scan_root, code_exts):
        if file_path.name == "SKILL.md":
            continue
        # Skip test files when checking script security patterns unless inside scripts/
        if "tests" in file_path.relative_to(skill_dir).parts:
            continue
        text = file_path.read_text(encoding="utf-8", errors="replace")
        _scan_text_lines(file_path, skill_dir, text, findings, is_code=True)
        if file_path.suffix.lower() == ".py":
            _audit_python_ast(file_path, skill_dir, text, findings)

    tests_dir = skill_dir / "tests"
    has_tests = tests_dir.is_dir() and any(tests_dir.iterdir())
    if not has_tests:
        findings.append(
            Finding(
                rule_id="G5-NO-TESTS-DIR",
                severity="P2",
                gate="G5",
                file="tests/",
                line=None,
                message="未发现 tests/ 测试目录，建议补充正常路径、脏数据与异常分支回归单测。",
            )
        )

    counts = {"P0": 0, "P1": 0, "P2": 0}
    for item in findings:
        counts[item.severity] = counts.get(item.severity, 0) + 1

    status = "FAIL" if counts["P0"] > 0 else ("WARN" if (counts["P1"] > 0 or counts["P2"] > 0) else "PASS")
    return {
        "target": str(skill_dir),
        "status": status,
        "summary": counts,
        "findings": [asdict(f) for f in findings],
    }


def render_markdown(report: dict) -> str:
    s = report["summary"]
    lines = [
        f"## Skill 静态体检报告：{Path(report['target']).name}",
        "",
        f"- **结论**：`{report['status']}`（P0: {s['P0']} | P1: {s['P1']} | P2: {s['P2']}）",
        "",
    ]
    if not report["findings"]:
        lines.append("未发现静态规范或安全护栏问题。")
        return "\n".join(lines)

    lines.extend([
        "| 级别 | 门禁 | 规则 | 位置 | 说明 |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ])
    for f in report["findings"]:
        loc = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
        lines.append(f"| {f['severity']} | {f['gate']} | `{f['rule_id']}` | `{loc}` | {f['message']} |")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Static quality and security auditor for Agent Skills.")
    parser.add_argument("target", help="Path to a Skill directory containing SKILL.md")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown", help="Output format")
    parser.add_argument("--max-lines", type=int, default=350, help="Max recommended lines for SKILL.md")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero on P1 as well as P0")
    args = parser.parse_args(argv)

    target = Path(args.target)
    if not target.is_dir():
        print(f"Error: directory not found: {target}", file=sys.stderr)
        return 2

    report = audit_skill_dir(target, max_skill_md_lines=args.max_lines)
    if args.format == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(render_markdown(report))

    if report["summary"]["P0"] > 0:
        return 1
    if args.strict and report["summary"]["P1"] > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
