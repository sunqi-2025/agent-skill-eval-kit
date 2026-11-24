# agent-skill-eval-kit

[![CI](https://github.com/sunqi-2025/agent-skill-eval-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/sunqi-2025/agent-skill-eval-kit/actions/workflows/ci.yml)

面向软件研发、测试与运维场景的 **Agent Skill 质量自检脚本与评测口径**。

平时在本地编写、维护和评测工作流 Skill 时，经常碰到一些共性毛病：触发条件写太泛导致抢活、几千行扫描日志直接塞回对话把上下文吃满、脚本里混进硬编码密钥或 `shell=True` 拼接、或者只测正常路径不测空返回和脏数据。这个仓库把常用的静态排查项做成了一个零依赖的 Python 小工具，并附带一份可直接套用的五项实测评测表。

## 包含内容

```text
agent-skill-eval-kit/
├── skill_auditor.py             # 零第三方依赖的 Skill 静态质量与安全体检 CLI
├── rubrics/
│   └── skill-eval-rubric.md     # 科技软件类 Skill 五项实测评测标准与脱敏案例
├── examples/
│   ├── sample-bad-skill/        # 反面样例（含硬编码密钥、shell=True、SQL 拼接、日志刷屏）
│   └── sample-good-skill/       # 规范样例（边界清晰、脚本确定性校验、有单测和脱敏护栏）
└── tests/
    └── test_skill_auditor.py    # unittest 单元测试集
```

## 快速上手

需要 Python 3.9+，无需安装任何第三方包：

```bash
# 检查反面样例（命中 P0 安全问题时以非零状态码退出，方便接入 CI 门禁）
python3 skill_auditor.py examples/sample-bad-skill

# 检查规范样例
python3 skill_auditor.py examples/sample-good-skill

# 输出 JSON 报告供脚本二次消费
python3 skill_auditor.py examples/sample-bad-skill --format json

# 运行单元测试
python3 -m unittest discover -s tests -v
```

## 内置检查项

| 类别 | 级别 | 检查内容 |
| :--- | :--- | :--- |
| 触发与文档规范 | P1 / P2 | `SKILL.md` 是否存在、YAML frontmatter 的 `name`/`description` 是否完整、是否存在过宽触发词、正文是否过长挤占上下文 |
| 硬编码凭据 | P0 | 脚本或文档中是否出现疑似 API Key、Token、私钥头或明文密码赋值 |
| 高危命令与注入 | P0 | `subprocess(..., shell=True)`、`os.system`、`eval`/`exec`、危险删除命令，以及字符串拼接的 SQL / `${}` 模板变量 |
| 写操作防误写护栏 | P1 | 出现数据库 `UPDATE`/`DELETE`/`DROP` 时是否带有只读或环境保护校验 |
| 长日志上下文治理 | P2 | 是否存在直接整块打印大文件/长日志输出而未做截断或落盘提示 |
| 异常与单测覆盖 | P2 | 是否配有 `tests/` 目录验证边界和异常输入 |

## 评测口径参考

完整的人工实测评测清单与 4 个脱敏评审样例见 [rubrics/skill-eval-rubric.md](rubrics/skill-eval-rubric.md)。
