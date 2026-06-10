# venus-pii 项目全面分析报告

**报告日期**: 2026-06-10
**分析范围**: `main` + 三个 `devin/*` 分支 + 三个 open PR（共四条实质分支）
**当前状态**: `main` 12 tests 全绿；`trace` 分支 123 tests 全绿；demo 可运行

---

## 0. TL;DR（先看这段）

venus-pii 是一个**定位极其清晰、卖点极强**的小而美的库：在数据离开你机器、进入 LLM 之前，用 HMAC-SHA256 把 PII（个人身份信息）令牌化（MASK）或整列删除（BLOCK），处理完还能用本地保留的反向表还原（restore）。核心代码只有一个文件、~270 行，12 个测试全过，API 设计干净。

但它有**一个会直接戳破核心卖点的硬伤**，以及若干"营销话术 > 实际实现"的落差：

1. **默认 HMAC 密钥是公开常量** `venus-pii-default-key`。用户若忘记设 `VENUS_PII_KEY`，README 承诺的"没有你的密钥就不可逆"直接失效——任何人用这个公开默认值就能重算出全部令牌。**没有任何运行时警告。这是 P0。**
2. **令牌只截取 32 bit**（`hexdigest()[:8]`），约 7.7 万个唯一值就有 50% 概率发生碰撞，碰撞会让 `restore()` 静默还原成错误的原始值、让"join 表仍然可用"的承诺悄悄失效。
3. **"Your key. Your rules." 名不副实**：`sanitize()` 根本没有暴露传 key 的参数，唯一设 key 的途径是**导入前**设环境变量（导入后再设无效，连贡献者的 skill 文档都把这点列为"坑"）。
4. **检测规则过宽**：`city`/`zip`/`income`/`account` 这类列名会被直接命中并 MASK/BLOCK，误报会损失数据可用性；而值检测兜底只覆盖中国手机号/身份证/邮箱。
5. **PR 上没有测试 CI**：仓库只有"打 tag 发 PyPI"的 workflow，三个 open PR 没有任何自动测试门禁。

下面是细节，以及我想做什么。

---

## 1. 项目是什么

**一句话**: 给 AI 调用做 PII 前置脱敏的 Polars DataFrame 库。

**三档保护**:
| 档位 | 行为 | 例子 |
|------|------|------|
| BLOCK | 整列删除，AI 永远看不到 | 身份证、银行账号 |
| MASK | 值替换为 `PREFIX_xxxxxxxx` HMAC 令牌，可用本地反向表还原 | 姓名、手机、邮箱、地址 |
| PASS | 原样通过 | 成绩、日期、分类 |

**检测方式**: 先按列名正则匹配（置信度 0.9），命中不到再按列值正则兜底（置信度 0.7，采样前 20 行、命中率需 >50%）。

**令牌化**: `HMAC-SHA256(value, key)` 取前 8 个 hex 字符，拼成 `PERSON_a3f8c21e`。同 key+同值 → 同令牌（确定性，可跨会话、可 join）。

**还原**: `sanitize()` 返回的 `token_maps` 是 token→原值 的反向表，留在本地；`restore()` 用它把令牌换回原值。BLOCK 列不可还原（设计如此）。

**项目定位**: 是 [Venus](https://github.com/weizhanf/venus-agent-site) "白盒 AI 数据处理引擎"的隐私层。哲学是"AI 是女神，但必须断臂"——人类通过可审计、可逆、白盒约束来控制 AI 能碰什么、看什么、做什么。

---

## 2. 四条分支逐条体检

### 2.1 `main`（基线，12 tests 全绿）

- `venus_pii/guard.py`（~270 行）：全部核心逻辑。
- `venus_pii/__init__.py`：导出 `detect/sanitize/restore` + 数据类。
- `tests/test_guard.py`：12 个测试，覆盖检测、BLOCK/MASK/PASS、还原往返、HMAC 确定性、null 保留。
- `pyproject.toml`：hatchling 构建，唯一依赖 `polars>=0.20`，Python ≥3.10。
- `.github/workflows/publish.yml`：打 `v*` tag 时用 OIDC 可信发布到 PyPI。**注意：没有任何跑测试的 CI。**

评价：干净、聚焦、能跑。但下面"问题清单"里的硬伤都在这条分支上。

### 2.2 `devin/1779180929-add-trace-module`（= PR #1，123 tests 全绿）⭐ 最有价值

新增 2857 行：
- `venus_pii/trace.py`（657 行）：`TraceRecorder` 数据流追踪器。`@trace` 装饰器记录 call/return/error；`record_tool_use`（MCP 风格）、`record_shell`/`run_shell`、`record_data_flow`（DataFrame 前后快照）、`note`；导出 JSONL / Markdown / ASCII 时间线；`traced_sanitize` / `traced_restore` 包装器。
- `docs/risk_assessment.md`：对标 EU AI Act Art. 9 的正式风险评估，列了 7 条风险（**RISK-007 就是上面说的默认密钥问题，但只是文档承认、代码未修**）。
- 4 个合规测试套件：`test_reidentification.py`（22）、`test_accuracy.py`（15，含 45 列基准）、`test_bias.py`（17，中英检测一致性）、`test_adversarial.py`（26）+ `test_trace.py`（31）。
- `examples/trace_demo.py`：完整 traced 管线 demo（我实测可运行，19 个事件）。

评价：**质量高、文档全、测试硬**，与"白盒可审计"的项目哲学高度契合。我亲自验证了"123 passed"和 demo 输出。这是三个 PR 里最该优先合并的。`traced_sanitize` 确实与 `sanitize` 行为一致（仅加观测）。唯一注意：它把追踪能力做大了，要确认这是否属于本库 scope，还是该拆成 `venus-trace` 独立包。

### 2.3 `devin/update-skills-1779181223`（= PR #2）

只加了 1 个文件 `.agents/skills/testing-venus-pii/SKILL.md`（64 行），描述"41+ tests"的旧版测试流程。

### 2.4 `devin/update-skills-1779183664`（= PR #3）

同样只加 `.agents/skills/testing-venus-pii/SKILL.md`（69 行），但是**更新、更全的版本**：描述 123 tests、6 个测试套件表格、关键"坑"（含模块级 HMAC key 在 import 时绑定这个真问题）。

**PR #2 与 PR #3 是同一个文件的两个版本，互相冲突，#3 全面取代 #2。**

---

## 3. 问题清单（按严重度）

### P0 — 直接戳破核心卖点

**P0-1 默认 HMAC 密钥是公开常量，且无运行时警告。**
`guard.py:127` `_DEFAULT_HMAC_KEY = os.environ.get("VENUS_PII_KEY", "venus-pii-default-key")`。README 首屏就写"HMAC, irreversible without your key"。但若用户没设环境变量，密钥就是这个写在源码里的公开字符串，攻击者拿到脱敏后的 `PERSON_xxxx`，用公开 key 对候选名单逐个算 HMAC 就能反查——脱敏形同虚设。`risk_assessment.md` 的 RISK-007 已承认，但**代码层零防护**。
*建议*：默认 key 缺失时 `warnings.warn(...)`；或干脆在缺失 `VENUS_PII_KEY` 时拒绝运行 / 自动生成随机 key 并提示用户持久化。

### P1 — 正确性 / 会静默出错

**P1-1 令牌 32 bit，碰撞概率高。** `_hmac_token` 取 `hexdigest()[:8]` = 32 bit。生日界约 7.7 万唯一值即 50% 碰撞。碰撞后：`_tokenize_column` 的 `reverse_map` 后写覆盖先写，`restore()` 把碰撞令牌还原成**错误的原值**（数据损坏，且无报错）；同时 README 宣称的"join 表仍可用"在碰撞处悄悄失效。
*建议*：把截断长度调到 16（64 bit）做默认，或在构建 `forward_map` 时检测碰撞并报错/自动加盐。

**P1-2 `sanitize()` 不暴露 key 参数。** `_tokenize_column` 有 `hmac_key` 形参，但 `sanitize()` 从不传，唯一设 key 途径是**进程内 import 前**设 `VENUS_PII_KEY`。所以"Your key. Your rules."、"multi-tenant isolation"在单进程内**无法切换租户 key**。README 的"Custom HMAC key"小节没说"必须在 import 之前 export"。
*建议*：给 `sanitize(df, *, key=...)` 加显式 key 参数，向下透传。

**P1-3 salary 还原是坏的。** `_salary_band` 的 reverse_map 是 `"SALARY_BAND_A" -> "SALARY_BAND_A(range)"`，`restore()` 会把 band 还原成字符串 `"SALARY_BAND_A(range)"` 而非原值（分桶本就不可逆，但还原出这种串既不是原值也不是 band，语义混乱）。
*建议*：salary 列在 `token_maps` 里明确标注为不可还原，或还原为区间字符串如 `"[5000,10000)"`。

### P2 — 精度 / 可用性

**P2-1 列名规则过宽 → 误报。** `address` 命中 `city|zip|street`，`salary` 命中 `income`，`bank_account` 命中 `account`。名为 `city`、`account_type`、`income_group` 的非 PII 列会被 MASK/BLOCK，损失可用性。

**P2-2 值检测兜底覆盖窄。** `VALUE_PATTERNS` 只有中国身份证 18 位、中国手机 `1[3-9]\d{9}`、邮箱。美/欧手机、国际证件号靠值检测无法兜底（列名不命中就漏）。这正是 RISK-001 残余风险。

**P2-3 值采样只看前 20 行、阈值 >50%。** PII 稀疏或排序靠后时可能漏检。

### P3 — 工程 / 流程

**P3-1 PR 无测试 CI。** 仓库只有发布 workflow，三个 PR 没自动测试门禁，合并全靠人肉。**这是性价比最高的改进点。**
**P3-2 缺 `py.typed`。** 有类型标注但未声明，下游拿不到类型。
**P3-3 PR #2/#3 重复。** 同一文件两版，应合 #3、关 #2。

---

## 4. 三个 Open PR 的处置建议

| PR | 内容 | 建议 | 理由 |
|----|------|------|------|
| **#1** trace 模块 + 合规测试 | 2857 行，123 tests 绿 | **优先合并**（先确认 scope） | 质量高、与项目哲学契合、我已实测通过 |
| **#3** 新版 testing skill | SKILL.md 123-tests 版 | **#1 之后合并** | 取代 #2，且引用了 #1 才有的测试数 |
| **#2** 旧版 testing skill | SKILL.md 41-tests 版 | **关闭** | 被 #3 完全取代，同文件冲突 |

合并顺序：#1 → #3 →（关）#2。

---

## 5. 我想做什么（优先级排序的行动建议）

按"修核心承诺 → 防静默出错 → 补流程 → 提精度"排序：

1. **【P0】给默认密钥加运行时警告** — 一行 `warnings.warn`，立刻让卖点不再是空话。最小改动、最大可信度收益。
2. **【P1】令牌截断从 8 提到 16 hex（64 bit）+ 碰撞检测** — 消除静默数据损坏。
3. **【P1】`sanitize()` 暴露 `key=` 参数** — 让"多租户隔离"真正可用，README 同步说明 env var 的 import-时机限制。
4. **【P3】加测试 CI**（`.github/workflows/test.yml`，在 PR 上跑 `pytest`）— 给现有/未来 PR 上门禁，杜绝"无 CI"现状。
5. **【PR 治理】** 合 #1、合 #3、关 #2。
6. **【P2】收窄过宽的列名正则 + 扩值检测**（美/欧手机、通用证件）— 降误报、补漏检。
7. **【P1】修 salary 还原语义**。

### 关于 PR #1（trace 模块）的归属 — 已定：留库 + 惰性导入

trace 模块**留在 venus-pii 内**（与"白盒可审计"哲学契合），但**不在 `__init__.py` 顶层 eager-import**。本分支的 `venus_pii/__init__.py` 已改为 PEP 562 惰性导入：

- `import venus_pii` 只加载核心 `guard`，**不会**连带拉入 `trace`（及其 `subprocess`/`inspect` 依赖）——核心保持轻量。
- 首次访问 `TraceRecorder` / `traced_sanitize` / `traced_restore`（或直接 `import venus_pii.trace`）时才按需加载 trace。
- `from venus_pii import TraceRecorder` 与 `venus_pii.TraceRecorder` 均可用；`dir(venus_pii)` 也能发现这些名字。

该 `__init__.py` 写法**无论 trace.py 是否存在都能安全顶层导入**，因此可直接替换 PR #1 中现有的 eager-import 版本。实测：本分支（无 trace.py）核心导入正常、17 tests 全绿；临时放入 trace.py 后惰性解析正确、trace 不被提前加载。

**这份报告本身是这条 `claude/project-analysis-report-cw4zf5` 分支的交付物。** 上面 1–7 的代码改动我没有在这条分支上动——它们跨越核心库逻辑与 PR 治理，属于需要你拍板的范围。告诉我做哪几条，我就开干（建议从 1+2+4 这组"低风险高收益"开始）。
