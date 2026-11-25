#!/usr/bin/env python3
"""Zero-dependency static quality and security auditor for Agent Skills.

Checks:
- G1: SKILL.md presence, YAML frontmatter (name/description/length/format), trigger hygiene
- G3: Context budget (SKILL.md size & unbounded stdout log printing)
- G4: Code-level security guardrails (hardcoded secrets, private keys, dynamic exec,
      shell invocation flags, curl-pipe-shell, unsafe pickle/yaml deserialization,
      SQL string interpolation, unguarded DB write statements, prompt-override markers)
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
from typing import Dict, Iterable, List, Optional, Tuple


@dataclass
class Finding:
    rule_id: str
    severity: str  # P0, P1, P2
    gate: str      # G1, G3, G4, G5
    file: str
    line: Optional[int]
    message: str


SKILL_NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")

BROAD_TRIGGER_PHRASES = (
    "anything",
    "everything",
    "all tasks",
    "any task",
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
CURL_PIPE_SHELL_RE = re.compile(r"(?i)\b(curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b")
MYBATIS_DOLLAR_SQL_RE = re.compile(r"(?i)\b(select|insert|update|delete|where|order\s+by)\b[^\n]*\$\{[^}]+\}")
SQL_FSTRING_RE = re.compile(r"""(?i)f['"][^'"]*\b(select|insert|update|delete|drop)\b[^'"]*\{[^}]+\}""")
SQL_PERCENT_OR_PLUS_RE = re.compile(
    r"""(?i)['"][^'"]*\b(select|insert|update|delete|drop)\b[^'"]*['"]\s*(\+|%\s|\.\s*format\()"""
)
SQL_WRITE_RE = re.compile(r"""(?i)\b(delete\s+from|update\s+\w+\s+set|drop\s+(table|database)|truncate\s+table)\b""")
GUARD_HINT_RE = re.compile(r"(?i)(read_only|readonly|allow_write|whitelist|confirm|dry_run|env\s*==\s*['\"]test)")
UNBOUNDED_READ_PRINT_RE = re.compile(r"\bprint\s*\([^)]*\w+\.read\s*\(\s*\)\s*\)")
PROMPT_OVERRIDE_RE = re.compile(
    r"(?i)\b(ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|disregard\s+system\s+prompt|exfiltrate\s+(?:secrets|env|credentials))\b"
)

IGNORED_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", ".pytest_cache", "dist", "build"}


_MESSAGES: Dict[str, Dict[str, str]] = {
    "en": {
        "G1-MISSING-SKILL-MD": "Missing required SKILL.md entry file.",
        "G1-MISSING-FRONTMATTER": "SKILL.md is missing standard YAML frontmatter ('---' block), which breaks skill routing.",
        "G1-EMPTY-NAME": "YAML frontmatter is missing the required 'name' field.",
        "G1-INVALID-NAME-FORMAT": "Skill name '{name}' violates the Agent Skills spec (must be 1-64 lowercase alphanumeric chars/hyphens, no leading/trailing/double hyphens).",
        "G1-NAME-DIR-MISMATCH": "Frontmatter name '{name}' does not match parent directory name '{dirname}'.",
        "G1-SHORT-DESCRIPTION": "Description is too short (<20 chars); trigger boundaries are unclear.",
        "G1-DESCRIPTION-TOO-LONG": "Description is {length} chars (exceeds the 1024-char Agent Skills spec limit).",
        "G1-BROAD-TRIGGER": "Description contains overly broad trigger phrase '{phrase}', risking false activation on unrelated tasks.",
        "G3-OVERSIZED-SKILL-MD": "SKILL.md has {count} lines (exceeds {max_lines}-line budget); move lengthy references into references/ for on-demand loading.",
        "G3-UNBOUNDED-LOG-PRINT": "Unbounded full-file read() passed to print() detected; persist long logs to disk and return a concise summary instead.",
        "G4-PRIVATE-KEY": "Private key block header detected; severe credential leak risk.",
        "G4-HARDCODED-SECRET": "Possible hardcoded credential in '{field}'; inject via environment variables instead.",
        "G4-DANGEROUS-RM": "Destructive recursive delete pattern detected (rm -rf targeting root, variable, glob, or home).",
        "G4-CURL-PIPE-SHELL": "Remote download piped directly into a shell interpreter; download, verify checksum, and inspect before executing.",
        "G4-PROMPT-OVERRIDE": "Suspicious prompt-override or credential-exfiltration instruction detected in skill documentation.",
        "G4-SQL-TEMPLATE-INJECTION": "Raw '${{}}' interpolation inside SQL statement; use parameterized bindings to prevent SQL injection.",
        "G4-SQL-STRING-CONCAT": "Dynamic string concatenation/interpolation in SQL query; use parameterized queries instead.",
        "G4-UNGUARDED-DB-WRITE": "Database write statement detected without read-only, whitelist, dry-run, or explicit confirmation guardrail.",
        "G4-PYTHON-SYNTAX-ERROR": "Python syntax error prevented AST inspection: {msg}",
        "G4-DYNAMIC-EXEC": "Dynamic code execution via {func}() detected; code injection risk.",
        "G4-OS-SYSTEM": "os.system() call detected; use subprocess.run([...]) with shell disabled instead.",
        "G4-SUBPROCESS-SHELL-TRUE": "subprocess invocation with shell enabled detected; pass an argument list instead to prevent command injection.",
        "G4-UNSAFE-DESERIALIZATION": "Unsafe deserialization via {func} detected; use JSON or yaml.safe_load() instead.",
        "G5-NO-TESTS-DIR": "No tests/ directory found; add unit tests covering normal paths, dirty data, and error branches.",
        "REPORT_TITLE": "## Agent Skill Static Audit Report: {name}",
        "REPORT_STATUS": "- **Verdict**: `{status}` (P0: {P0} | P1: {P1} | P2: {P2})",
        "REPORT_CLEAN": "No static hygiene or security guardrail issues detected.",
        "REPORT_HEADER": "| Severity | Gate | Rule | Location | Message |",
    },
    "zh": {
        "G1-MISSING-SKILL-MD": "缺少 SKILL.md 入口说明文件。",
        "G1-MISSING-FRONTMATTER": "SKILL.md 缺少标准 YAML frontmatter（--- 区块），影响路由解析。",
        "G1-EMPTY-NAME": "frontmatter 中缺少 name 字段。",
        "G1-INVALID-NAME-FORMAT": "frontmatter 中的 name「{name}」不符合 Agent Skills 规范（须为 1-64 位小写字母、数字或连字符，且不能以连字符开头/结尾或连续出现）。",
        "G1-NAME-DIR-MISMATCH": "frontmatter 中的 name「{name}」与父目录名「{dirname}」不一致。",
        "G1-SHORT-DESCRIPTION": "description 过短（<20 字符），触发条件不够明确。",
        "G1-DESCRIPTION-TOO-LONG": "description 共 {length} 字符（超过 1024 字符规范上限）。",
        "G1-BROAD-TRIGGER": "description 包含过宽触发词「{phrase}」，容易误抢无关任务。",
        "G3-OVERSIZED-SKILL-MD": "SKILL.md 共 {count} 行（超过 {max_lines} 行阈值），建议将长参考口径拆入 references/ 按需加载。",
        "G3-UNBOUNDED-LOG-PRINT": "检测到直接打印整份文件读取结果（.read()），长日志易撑爆对话上下文，建议落盘并截断摘要。",
        "G4-PRIVATE-KEY": "检测到私钥块头（PRIVATE KEY），存在严重凭据泄露风险。",
        "G4-HARDCODED-SECRET": "检测到疑似硬编码凭据字段「{field}」，请改用环境变量注入。",
        "G4-DANGEROUS-RM": "检测到高危递归删除命令（rm -rf 根目录/变量/通配符）。",
        "G4-CURL-PIPE-SHELL": "检测到远程下载内容直接通过管道交由 shell 执行，存在供应链注入风险。",
        "G4-PROMPT-OVERRIDE": "检测到疑似越权提示注入或凭据外传指令，请核查文档内容。",
        "G4-SQL-TEMPLATE-INJECTION": "SQL 中出现 ${{}} 直接插值，存在 SQL 注入风险，请改为参数化占位符。",
        "G4-SQL-STRING-CONCAT": "检测到字符串拼接构造 SQL，存在注入风险，请改用参数绑定。",
        "G4-UNGUARDED-DB-WRITE": "脚本包含数据库写操作但未检测到只读/白名单/确认护栏。",
        "G4-PYTHON-SYNTAX-ERROR": "Python 语法错误，无法完成 AST 检查：{msg}",
        "G4-DYNAMIC-EXEC": "检测到动态代码执行 {func}()，存在命令/代码注入风险。",
        "G4-OS-SYSTEM": "检测到 os.system() 调用，建议改用 subprocess.run([...]) 参数数组方式。",
        "G4-SUBPROCESS-SHELL-TRUE": "检测到子进程开启 shell 解释执行，存在命令注入风险，请改为参数数组调用。",
        "G4-UNSAFE-DESERIALIZATION": "检测到不安全反序列化调用 {func}，请改用 JSON 或 yaml.safe_load()。",
        "G5-NO-TESTS-DIR": "未发现 tests/ 测试目录，建议补充正常路径、脏数据与异常分支回归单测。",
        "REPORT_TITLE": "## Skill 静态体检报告：{name}",
        "REPORT_STATUS": "- **结论**：`{status}`（P0: {P0} | P1: {P1} | P2: {P2}）",
        "REPORT_CLEAN": "未发现静态规范或安全护栏问题。",
        "REPORT_HEADER": "| 级别 | 门禁 | 规则 | 位置 | 说明 |",
    },
}


def _msg(lang: str, key: str, **kwargs: object) -> str:
    table = _MESSAGES.get(lang, _MESSAGES["en"])
    template = table[key]
    return template.format(**kwargs) if kwargs else template


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


def _audit_skill_md(
    skill_dir: Path,
    findings: List[Finding],
    max_lines: int,
    *,
    lang: str,
    check_dir_name: bool,
) -> None:
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.is_file():
        findings.append(
            Finding(
                rule_id="G1-MISSING-SKILL-MD",
                severity="P1",
                gate="G1",
                file="SKILL.md",
                line=None,
                message=_msg(lang, "G1-MISSING-SKILL-MD"),
            )
        )
        return

    text = skill_md.read_text(encoding="utf-8", errors="replace")
    meta, _ = parse_frontmatter(text)
    if meta is None:
        findings.append(
            Finding(
                rule_id="G1-MISSING-FRONTMATTER",
                severity="P1",
                gate="G1",
                file="SKILL.md",
                line=1,
                message=_msg(lang, "G1-MISSING-FRONTMATTER"),
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
                    message=_msg(lang, "G1-EMPTY-NAME"),
                )
            )
        else:
            if not SKILL_NAME_RE.match(name) or "--" in name:
                findings.append(
                    Finding(
                        rule_id="G1-INVALID-NAME-FORMAT",
                        severity="P1",
                        gate="G1",
                        file="SKILL.md",
                        line=1,
                        message=_msg(lang, "G1-INVALID-NAME-FORMAT", name=name),
                    )
                )
            if check_dir_name and name != skill_dir.name:
                findings.append(
                    Finding(
                        rule_id="G1-NAME-DIR-MISMATCH",
                        severity="P1",
                        gate="G1",
                        file="SKILL.md",
                        line=1,
                        message=_msg(lang, "G1-NAME-DIR-MISMATCH", name=name, dirname=skill_dir.name),
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
                    message=_msg(lang, "G1-SHORT-DESCRIPTION"),
                )
            )
        elif len(desc) > 1024:
            findings.append(
                Finding(
                    rule_id="G1-DESCRIPTION-TOO-LONG",
                    severity="P1",
                    gate="G1",
                    file="SKILL.md",
                    line=1,
                    message=_msg(lang, "G1-DESCRIPTION-TOO-LONG", length=len(desc)),
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
                        message=_msg(lang, "G1-BROAD-TRIGGER", phrase=phrase),
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
                message=_msg(lang, "G3-OVERSIZED-SKILL-MD", count=line_count, max_lines=max_lines),
            )
        )

    _scan_text_lines(skill_md, skill_dir, text, findings, is_code=False, lang=lang)


def _scan_text_lines(
    path: Path,
    root: Path,
    text: str,
    findings: List[Finding],
    *,
    is_code: bool,
    lang: str,
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
                    message=_msg(lang, "G4-PRIVATE-KEY"),
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
                    message=_msg(lang, "G4-HARDCODED-SECRET", field=secret_match.group(1)),
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
                    message=_msg(lang, "G4-DANGEROUS-RM"),
                )
            )

        if CURL_PIPE_SHELL_RE.search(line):
            findings.append(
                Finding(
                    rule_id="G4-CURL-PIPE-SHELL",
                    severity="P0",
                    gate="G4",
                    file=rel,
                    line=lineno,
                    message=_msg(lang, "G4-CURL-PIPE-SHELL"),
                )
            )

        if not is_code and PROMPT_OVERRIDE_RE.search(line):
            findings.append(
                Finding(
                    rule_id="G4-PROMPT-OVERRIDE",
                    severity="P1",
                    gate="G4",
                    file=rel,
                    line=lineno,
                    message=_msg(lang, "G4-PROMPT-OVERRIDE"),
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
                    message=_msg(lang, "G4-SQL-TEMPLATE-INJECTION"),
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
                        message=_msg(lang, "G4-SQL-STRING-CONCAT"),
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
                        message=_msg(lang, "G4-UNGUARDED-DB-WRITE"),
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
                        message=_msg(lang, "G3-UNBOUNDED-LOG-PRINT"),
                    )
                )


def _is_safe_yaml_loader(call_node: ast.Call) -> bool:
    for kw in call_node.keywords:
        if kw.arg == "Loader":
            loader_src = ast.unparse(kw.value) if hasattr(ast, "unparse") else ""
            if "SafeLoader" in loader_src or "BaseLoader" in loader_src:
                return True
    return False


def _audit_python_ast(
    path: Path,
    root: Path,
    text: str,
    findings: List[Finding],
    *,
    lang: str,
) -> None:
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
                message=_msg(lang, "G4-PYTHON-SYNTAX-ERROR", msg=exc.msg),
            )
        )
        return

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        # Check dynamic code execution
        if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
            findings.append(
                Finding(
                    rule_id="G4-DYNAMIC-EXEC",
                    severity="P0",
                    gate="G4",
                    file=rel,
                    line=node.lineno,
                    message=_msg(lang, "G4-DYNAMIC-EXEC", func=node.func.id),
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
                    message=_msg(lang, "G4-OS-SYSTEM"),
                )
            )

        # Check unsafe pickle.load / pickle.loads and yaml.load without SafeLoader
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            mod = node.func.value.id
            attr = node.func.attr
            if mod == "pickle" and attr in {"load", "loads"}:
                findings.append(
                    Finding(
                        rule_id="G4-UNSAFE-DESERIALIZATION",
                        severity="P0",
                        gate="G4",
                        file=rel,
                        line=node.lineno,
                        message=_msg(lang, "G4-UNSAFE-DESERIALIZATION", func=f"pickle.{attr}()"),
                    )
                )
            elif mod == "yaml" and attr == "load" and not _is_safe_yaml_loader(node):
                findings.append(
                    Finding(
                        rule_id="G4-UNSAFE-DESERIALIZATION",
                        severity="P0",
                        gate="G4",
                        file=rel,
                        line=node.lineno,
                        message=_msg(lang, "G4-UNSAFE-DESERIALIZATION", func="yaml.load()"),
                    )
                )

        # Check subprocess.* with shell enabled
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                findings.append(
                    Finding(
                        rule_id="G4-SUBPROCESS-SHELL-TRUE",
                        severity="P0",
                        gate="G4",
                        file=rel,
                        line=node.lineno,
                        message=_msg(lang, "G4-SUBPROCESS-SHELL-TRUE"),
                    )
                )


def audit_skill_dir(
    skill_dir: Path,
    max_skill_md_lines: int = 350,
    *,
    lang: str = "en",
    check_dir_name: bool = False,
) -> dict:
    """Audit a single Skill directory and return a structured report."""
    skill_dir = skill_dir.resolve()
    findings: List[Finding] = []

    _audit_skill_md(
        skill_dir,
        findings,
        max_lines=max_skill_md_lines,
        lang=lang,
        check_dir_name=check_dir_name,
    )

    # Also scan markdown references for leaked credentials or prompt-override markers
    refs_dir = skill_dir / "references"
    if refs_dir.is_dir():
        for md_path in _iter_files(refs_dir, (".md", ".txt")):
            md_text = md_path.read_text(encoding="utf-8", errors="replace")
            _scan_text_lines(md_path, skill_dir, md_text, findings, is_code=False, lang=lang)

    code_exts = (".py", ".sh", ".bash", ".js", ".ts", ".sql", ".xml")
    scripts_dir = skill_dir / "scripts"
    scan_root = scripts_dir if scripts_dir.is_dir() else skill_dir

    for file_path in _iter_files(scan_root, code_exts):
        if file_path.name == "SKILL.md":
            continue
        if "tests" in file_path.relative_to(skill_dir).parts:
            continue
        text = file_path.read_text(encoding="utf-8", errors="replace")
        _scan_text_lines(file_path, skill_dir, text, findings, is_code=True, lang=lang)
        if file_path.suffix.lower() == ".py":
            _audit_python_ast(file_path, skill_dir, text, findings, lang=lang)

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
                message=_msg(lang, "G5-NO-TESTS-DIR"),
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


def render_markdown(report: dict, *, lang: str = "en") -> str:
    s = report["summary"]
    lines = [
        _msg(lang, "REPORT_TITLE", name=Path(report["target"]).name),
        "",
        _msg(lang, "REPORT_STATUS", status=report["status"], P0=s["P0"], P1=s["P1"], P2=s["P2"]),
        "",
    ]
    if not report["findings"]:
        lines.append(_msg(lang, "REPORT_CLEAN"))
        return "\n".join(lines)

    lines.extend([
        _msg(lang, "REPORT_HEADER"),
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
    parser.add_argument("--lang", choices=("en", "zh"), default="en", help="Report language (en or zh)")
    parser.add_argument("--max-lines", type=int, default=350, help="Max recommended lines for SKILL.md")
    parser.add_argument(
        "--spec",
        action="store_true",
        help="Enforce strict Agent Skills spec checks (including directory name == frontmatter name)",
    )
    parser.add_argument("--strict", action="store_true", help="Exit non-zero on P1 as well as P0")
    parser.add_argument("--output", help="Optional path to write full report to disk (prints concise summary to stdout)")
    args = parser.parse_args(argv)

    target = Path(args.target)
    if not target.is_dir():
        print(f"Error: directory not found: {target}", file=sys.stderr)
        return 2

    report = audit_skill_dir(
        target,
        max_skill_md_lines=args.max_lines,
        lang=args.lang,
        check_dir_name=args.spec,
    )
    rendered = (
        json.dumps(report, ensure_ascii=False, indent=2)
        if args.format == "json"
        else render_markdown(report, lang=args.lang)
    )

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered + "\n", encoding="utf-8")
        s = report["summary"]
        print(
            f"[{report['status']}] {target.name} (P0:{s['P0']} P1:{s['P1']} P2:{s['P2']}) -> {out_path}"
        )
    else:
        print(rendered)

    if report["summary"]["P0"] > 0:
        return 1
    if args.strict and report["summary"]["P1"] > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
