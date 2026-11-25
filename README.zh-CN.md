# agent-skill-eval-kit

[![CI](https://github.com/sunqi-2025/agent-skill-eval-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/sunqi-2025/agent-skill-eval-kit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[English](README.md) | 简体中文

面向软件研发、测试与运维场景的 **Agent Skill 静态质量自检工具与五项实测评测口径**——纯 Python 标准库零依赖，既可作为独立 CLI 接入 CI 门禁，也本身按标准 `SKILL.md` 规范封装，可直接作为 Agent Skill 安装到 Claude Code、Cursor、Codex CLI、Gemini CLI、Antigravity 或上架 Agensi.io。

平时编写、维护和评测工作流 Skill 时，经常碰到一些共性毛病：触发条件写太泛导致抢活、几千行扫描日志直接塞回对话把上下文吃满、脚本里混进硬编码密钥 / `shell=True` / 不安全反序列化 / `curl | sh` / SQL 拼接，或者只测正常路径不测空返回和脏数据。本仓库把这些高频排查项沉淀为确定性静态审计 CLI，并配套五项实测评测表。

---

## 目录结构

```text
agent-skill-eval-kit/
├── SKILL.md                           # 标准 Agent Skill 入口（兼容 agentskills.io / Agensi）
├── scripts/
│   ├── skill_auditor.py               # 零依赖 Skill 静态质量与安全体检 CLI（支持 en/zh）
│   └── package_skill.py               # 一键打包并自检纯净分发 ZIP（自动剔除反面样例防误杀）
├── skill_auditor.py                   # 根目录兼容入口（保留旧命令调用方式）
├── references/
│   └── skill-eval-rubric.md           # 五项实测评测口径（英文版）
├── rubrics/
│   └── skill-eval-rubric.md           # 五项实测评测口径与脱敏评审案例（中文版）
├── examples/
│   ├── sample-bad-skill/              # 反面合成样例（仅用于单测验证）
│   └── sample-good-skill/             # 规范样例
└── tests/
    └── test_skill_auditor.py          # unittest 全量单元测试集
```

---

## 快速上手

需要 **Python 3.9+**，无需安装任何第三方依赖：

```bash
# 检查反面样例（命中 P0 安全问题时返回非零退出码，可直接接入 CI）
python3 scripts/skill_auditor.py examples/sample-bad-skill --lang zh

# 对仓库自身做严格规范自检（含目录名与 frontmatter name 一致性校验）
python3 scripts/skill_auditor.py . --spec --strict --lang zh

# 输出 JSON 报告供脚本二次消费
python3 scripts/skill_auditor.py examples/sample-bad-skill --format json

# 将完整报告落盘本地文件，仅在终端输出一行摘要（践行 G3 上下文治理）
python3 scripts/skill_auditor.py examples/sample-bad-skill --lang zh --output /tmp/skill-audit.md

# 运行全量单元测试
python3 -m unittest discover -s tests -v
```

> 兼容说明：根目录旧命令 `python3 skill_auditor.py <目录>` 依然完全可用。

---

## 内置检查项

| 门禁 | 级别 | 检查内容 |
| :--- | :--- | :--- |
| **G1 触发与规范** | P1 / P2 | `SKILL.md` 是否存在、YAML frontmatter 的 `name`/`description` 格式与长度上限（name 1–64 位小写字母/数字/连字符，description 20–1024 字符）、`--spec` 目录下名称一致性、过宽触发词检测 |
| **G3 上下文治理** | P2 | `SKILL.md` 行数是否超预算（默认 350 行）、是否存在直接整块打印大文件 `.read()` 导致上下文膨胀 |
| **G4 代码安全护栏** | P0 / P1 | 硬编码凭据与私钥头（自动过滤占位符）、高危 `rm -rf`、`curl/wget \| sh`、`eval`/`exec`、`os.system`、`shell=True`、不安全反序列化（`pickle.load(s)` / 无 `SafeLoader` 的 `yaml.load`）、SQL `${}` 与字符串拼接注入、无保护数据库写操作、Markdown 越权提示注入特征 |
| **G5 单测覆盖** | P2 | 是否配有非空 `tests/` 目录验证异常与脏数据分支 |

---

## 一键打包纯净分发包（适配 Agensi.io / Agent Skill 市场）

仓库里的 `examples/sample-bad-skill/` 含有故意构造的反面测试代码，直接打包整库上传容易触发平台安全扫描误杀。运行下面命令可生成纯净分发包并自动解压跑通自检与冒烟测试：

```bash
python3 scripts/package_skill.py
# 产出：dist/agent-skill-eval-kit.zip
```

---

## 五项实测评测口径

完整的人工实测评测清单与 4 个脱敏评审样例见：
- 中文版：[rubrics/skill-eval-rubric.md](rubrics/skill-eval-rubric.md)
- English：[references/skill-eval-rubric.md](references/skill-eval-rubric.md)
