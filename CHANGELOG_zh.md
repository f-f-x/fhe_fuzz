# `fhe_fuzz` 修改日志与实验基线

> **用途**：记录已经落地的修改、对应实验、结论和未完成项。以后每次改动都在本文档的
> 「待补充记录模板」之前新增一条，不能只改代码或 README。
>
> **记录规则**：一次功能修改至少要写清 `日期 / 目的 / 代码或文件 / 验证命令与报告 /
> 结论 / 是否改变已知结果`。没有跑验收时必须写“未验收”，不能把实现完成写成实验完成。

## 0. 基线与证据边界

`fhe_fuzz/` 没有独立的 `.git` 历史；以下时间线根据保留的 `runs/` 报告、作废说明、源文件
修改时间及当前代码重建。因此它能准确说明**当前工作区相对保存下来的第一轮完整 Lattigo
实验**发生了什么，但不能替代未来的 Git 提交记录。

已保存的**项目级最早完整运行报告**是 `runs/control_seal/`（2026-09-23 08:01 UTC）：
`seal-bfv` 跑 120 次，120 `ok`、0 candidate、0 bug。它是最初的 SEAL 控制组，但不能直接拿来
解释后续 Lattigo BGV 的噪声与深度行为。

因此，本日志在判断本轮主要的 Lattigo 改造时，使用保存下来的第一份完整 Lattigo 300 次运行
`runs/lattigo_bgv_300/` 作为**目标级基线**：

| 项目 | 基线值 |
| --- | --- |
| 完成时间 | 2026-09-24 10:45 UTC |
| 目标 | `lattigo-bgv`，300 iterations |
| 结果 | 239 `ok`，61 `candidate`，29 `confirmed`，0 `noise-overflow` |
| 当时问题 | 深度没有被可靠限制，噪声耗尽后的随机解密错误被 oracle 误记为 confirmed bug |
| 基线结论 | **该 29 个“发现”不可作为 Lattigo 漏洞计数。** |

如果“第一次实验”指的是另一个没有保留在 `runs/` 下的运行，请补充其目录或命令；本文档的
基线定义应随之更正，而不是把两批数据混在一起。

## 1. 当前位置（2026-09-26）

主线已经完成 **I0 地基修复** 的代码和已有实验取证；保存的 SEAL oracle 全矩阵为 PASS，
但尚未在本次工作区快照完成一轮新的全量复验。**尚未完成 I1。**

目前可以可靠描述为：

- `run_fuzz.py --target lattigo-bgv` 仍是**固定参数、单变量整数多项式、三形式等价 oracle**；
  它已经具备深度钳制和噪声阈值校准。
- I1 所需的通用“case state”接口（`params_id`、postfix、`scale_invariant`）和报告字段已经
  放入 `Target` / `Corpus` / `Engine`，但 `LattigoBGVTarget` 和 Go helper 尚未消费这些字段。
  因此它是**框架预埋，不是 I1 功能完成**。
- Go 原生侧已新增 BGV 槽编码专项 fuzz；它与 Python 多项式 oracle 并列运行，尚未自动回灌
  Python 语料库，故只算 I5 的局部能力。

| 路线图增量 | 当前判断 | 依据 |
| --- | --- | --- |
| I0 地基修复 | 已实现；验收见第 3 节 | 环境固化、作废记录、校准、钳制均有代码/运行报告 |
| I1 BGV/BFV 搜索扩展 | 未完成（仅框架预埋） | `lattigo_bgv.py` 仍固定 `plain_modulus=257`、`max_depth=5`；`main.go` 仍只有固定 `parameterLiteral`，没有参数池/后缀/`scale_invariant` 协议 |
| I2 CKKS | 未开始 | 无 CKKS target、近似 oracle、scale/level 搜索或高精度参考实现 |
| I3 通用契约不变式 oracle | 未完成；已有定向探针 | `decode_invalid_probe.go`、`scale_probe.go` 是独立探针，尚未成为类型化 API/不变式搜索 |
| I4 跨库/库内差分 | 未开始 | 无类型化 IR、跨库 compare 或归因流水线 |
| I5 覆盖率闭环 | 局部完成 | Go `testing.F` 与槽专项 harness 已有；Go→Python 仅手动 `replay_go_case.py`，没有自动闭环 |

## 2. 已发生的修改记录

### 2026-09-24 — 修正 Lattigo 初始实验的深度/噪声判读

- **目的**：确认基线 29 个 confirmed 是否是真实库缺陷。
- **改动/结果**：以有界深度重跑 `runs/lattigo_bgv_300_bounded/`；结果为 231 `ok`、69
  `noise-overflow`、0 `candidate`、0 bug。另一次 50,000 次受控长跑
  `runs/lattigo_seed_1001/` 得到 0 bug。
- **影响**：证明基线中的大量候选来自噪声溢出，不能继续作为漏洞证据。
- **状态**：完成；旧数字的正式作废记录见下一条。

### 2026-09-25 — I0.1：绑定环境固化

- **目的**：消除 `/tmp/fhe-libs` 被清理后无法复现实验的问题。
- **文件**：`.work/pylibs/`；`eidolon/targets/seal_bfv.py`；`README.md`。
- **改动**：默认绑定路径改为仓库内 `.work/pylibs/`；保留 `FHE_SEAL_PATH` 覆盖；目录缺失时
  显式报错，不再静默回退到 `/tmp`。
- **已有证据**：当前 `seal_bfv.py` 的默认路径与错误信息均指向 `.work/pylibs/`；未设置
  `FHE_SEAL_PATH` 的 `runs/seal_binding_smoke_20260926/` 跑出 5 `ok`、0 bug。
- **状态**：实现完成。原路线图要求的“把 `/tmp/fhe-libs` 改名后跑 5 次”没有留下独立报告，
  后续若需严格追溯，应补一条专门的 `runs/` 记录。

### 2026-09-25 — I0.2：作废历史噪声假阳性

- **目的**：禁止把旧适配器的噪声错误继续写成 Lattigo 漏洞。
- **文件**：`runs/lattigo_seed_1002/INVALIDATED.md`、
  `runs/lattigo_seed_1005/INVALIDATED.md`、`../fhe_eidolon_security_audit_zh.md`、
  `report/00_lattigo_audit_summary.md`。
- **证据**：重放 `bug000` 时 `noise_ratio=0`、`raw=180.3 > budget=178.0`，只有 Horner 输出
  随重执行变化，而 standard/factored 始终与 native 一致。
- **影响**：`lattigo_seed_1002` 的 5,943 和 `lattigo_seed_1005` 的 19,878 confirmed 均为
  **作废数据**；不可用于漏洞数量、回归判断或对外报告。
- **状态**：完成。

### 2026-09-25 — I0.3：噪声阈值校准

- **目的**：用目标实测分布替代不可达的固定 `tau_low=0.10`。
- **文件**：`run_fuzz.py`、`eidolon/engine.py`、`eidolon/corpus.py`。
- **改动**：增加 `--calibrate`；收集 `noise_ratio`，将 P10/P70 与推荐的 `tau_low/tau_high`
  写入 `run.json.calibration`，并标记 boundary 语料。
- **实验**：`runs/lattigo_calibration_seed_1001/`（200 次）得到 P10=`0.52931446`、
  P70=`0.60439433`，并标记 14 个 boundary seeds。
- **状态**：完成。注意：普通运行不会自动读取历史校准值，下一次 campaign 仍须显式传入推荐
  阈值，或后续实现配置加载机制。

### 2026-09-25 — I0.4：深度上限由“丢弃”改为“钳制”

- **目的**：避免高噪声变异持续撞到 `max_depth` 后退回随机种子，造成次数分布塌缩。
- **文件**：`eidolon/engine.py`（`clamp` 与统计字段）；`eidolon/mutator.py`。
- **改动**：超出 per-case `max_depth` 的表达式先钳制；高噪声模式在上限处保留少量边界样本、
  多数情况留出一级余量；报告 `degree_distribution`、`clamped_cases` 和
  `discarded_after_clamp`。
- **对照实验**：同 seed、同 300 次：

  | 报告 | 次数分布 | 钳制数 | 结论 |
  | --- | --- | ---: | --- |
  | `lattigo_i04_before_seed_1001` | degree 5: 243/300 | 0 | 明显塌缩在上限 |
  | `lattigo_i04_after_seed_1001` | degree 1–4: 265/300；degree 5: 35/300 | 106 | 分布已铺开 |

- **状态**：完成。

### 2026-09-25 — Lattigo 适配器与 oracle 可复现性加固

- **目的**：让 Lattigo 运行不因 native helper 崩溃/超时或旧基线语义而污染后续用例。
- **文件**：`eidolon/runner.py`、`eidolon/targets/lattigo_bgv.py`、
  `lattigo_bgv/main.go`、`eidolon/oracle.py`、`eidolon/expr.py`、`eidolon/mutator.py`。
- **已具备能力**：长活 Go JSON helper，失败后重启；BGV 批编码；残余噪声通过扣除期望明文后
  `rlwe.Norm` 计算；逐形式基线 `natives` 支持；故障注入与报告限额。
- **边界**：这不是 I1 的参数/算子扩展；Python 主目标仍只执行三种一元多项式形式。
- **状态**：已落地，相关回归结果见 `report/00_lattigo_audit_summary.md`。

### 2026-09-26 — I1 的通用状态框架（未接入 Lattigo）

- **目的**：为参数集、后缀算子和 scale-invariant(BFV) case state 预留通用接口。
- **文件**：`eidolon/targets/base.py`、`eidolon/corpus.py`、`eidolon/engine.py`。
- **已实现**：`Seed` 可持久化 `params_id`、`postfix`、`postfix_arg`、`scale_invariant`；
  `Target` 提供 `seed_case_states`、`mutate_case`、`max_depth_for_case`、
  `make_xvals_for_case`、`evaluate_case`；`run.json` 可统计这些维度。
- **未实现（决定状态）**：`LattigoBGVTarget` 没有覆写这些 hook；Go request 没有相应字段；
  `main.go` 没有 LRU context pool，也没有 rotate/conjugate/mul-then-add/drop-level 或
  `scale_invariant` 执行路径。
- **状态**：**仅脚手架，不计为 I1 完成。**

### 2026-09-26 — BGV 槽编码专项原生 fuzz

- **目的**：覆盖 `ExprSpec` 无法表达的 SIMD 槽位语义。
- **文件**：`go_native/lattigo_bgv/slot_fuzz_test.go`、
  `go_native/lattigo_bgv/fuzz_test.go`、`LATTIGO_BGV_SLOT_FUZZ_ZH.md`。
- **覆盖**：全槽编码/解码、前缀零填充、列/行旋转、`RotateAndAdd`、`InnerSum`、旋转逆元；
  具备专门的 `rotation-plus-one` 故障注入门。
- **实验**：`runs/lattigo_bgv_slot_regression/` 的 Python 回归为 20 `ok`、0 bug；该报告不等同于
  Go 长跑覆盖率结果。
- **状态**：专项 harness 已实现；Go 语料到 Python oracle 仍是手动
  `go_native/replay_go_case.py`，因此 I5 覆盖率闭环未完成。

### 2026-09-26 — 建立修改日志与基线账本

- **目的**：将“当前做到哪一步”和每次修改的实验影响固定在一个可审计入口，避免把
  已写的框架、已验证的能力和未来路线图混为一谈。
- **文件**：本文件 `CHANGELOG_zh.md`；`README.md` 的目录索引。
- **内容**：固定第一次完整 Lattigo 300 次运行作为当前可追溯基线；记录 I0、I1 脚手架、
  槽专项 harness 的完成边界，并提供后续条目模板。
- **状态**：完成。

### 2026-09-26 — Git 版本管理初始化

- **目的**：将工具源代码、文档和紧凑实验摘要纳入独立版本管理，同时排除本地依赖、二进制和
  大体积运行语料。
- **文件**：`.gitignore`；本文件；已初始化的 `fhe_fuzz/.git/`（分支 `main`）。
- **忽略策略**：不提交 Python 缓存、编译产物、`.artifacts/`、OpenFHE probe 二进制/日志及
  完整 campaign 的 `history.jsonl`、`corpus.json`、`bugs.json`、`console.log`；保留源代码、
  文档、`run.json`、作废说明、issue 草稿和一个最小 Go fuzz seed。
- **远程状态**：已设置 `origin=https://github.com/f-f-x/fhe_fuzz.git`；远程可读取且当前没有
  refs（空仓库）。尚未推送：当前环境没有 GitHub CLI、可用的 GitHub SSH 凭据、token 或 Git
  提交身份；收到认证方式后创建首个提交并推送。
- **本地提交**：`4922e3d Initial import of fhe_fuzz`，含 72 个文件、7,529 行；提交身份为
  `ffx <3027135579@qq.com>`。
- **状态**：本地首个提交已完成；首次 HTTPS 推送因当前环境没有 GitHub 凭据而未成功，远程
  上传待认证后重试。

### 2026-09-26 — GitHub 远程同步

- **目的**：将本地 `fhe_fuzz` 基线安全合并至 `https://github.com/f-f-x/fhe_fuzz.git`。
- **远程既有内容**：`origin/main` 只有 `f0b146d Initial commit`，其中仅含两行初始化 README。
- **合并策略**：以 `--allow-unrelated-histories` 保留远程初始化提交；README 的 add/add 冲突
  采用本地完整工具说明，未强推或覆盖远程历史。
- **结果**：合并提交 `dd346b9 Merge remote main history` 已推送；本地 `main` 已跟踪
  `origin/main`。
- **状态**：完成。

## 3. 验收记录

| 日期 | 命令/报告 | 结果 | 对应修改 |
| --- | --- | --- | --- |
| 2026-09-25 | `runs/lattigo_calibration_seed_1001/run.json` | P10/P70 已写入，14 个 boundary seeds | I0.3 |
| 2026-09-25 | `runs/lattigo_i04_{before,after}_seed_1001/run.json` | 次数分布从上限塌缩变为铺开 | I0.4 |
| 2026-09-24 | `runs/oracle_matrix_seal.json` | 无故障 0 bug；6 种注入故障均检出 | 历史 oracle 基线 |
| 2026-09-26 | `runs/seal_binding_smoke_20260926/run.json` | 默认 `.work/pylibs` 路径下 5 `ok`、0 bug | I0.1 冒烟验证 |
| 2026-09-26 | `python3 -m py_compile eidolon/engine.py eidolon/corpus.py eidolon/targets/base.py run_fuzz.py` | PASS | 本次状态盘点的语法检查 |
| 待补 | `python3 validate_oracle.py --target seal-bfv --iterations 50 --seeds 3` | 最新快照尚无完成报告；不得替代 2026-09-24 的历史 PASS | I0 总体验收 |

## 4. 下一步（按依赖，不按“代码已写多少”）

1. 完成本次 I0 oracle 验收；若失败，先修 I0 回归，不进入新功能。
2. 要么完整做 I1：先让 Lattigo 真正消费 `params_id`，再逐项加入算子和参考语义；
   要么按路线图优先级先做 I3：把已有 Decode/序列化探针提升为可报告的不变式 oracle。
3. 在 I1 完整验收前，不能声称已支持 Lattigo BFV、参数搜索、旋转/共轭或 BGV 层级操作。
4. CKKS、跨库差分和自动 Go→Python 语料闭环均应保持“未开始/未完成”状态。

## 5. 待补充记录模板

把新条目插在本节之前，复制以下模板：

```markdown
### YYYY-MM-DD — <增量编号/简短标题>

- **目的**：
- **文件**：
- **改动**：
- **验证**：`命令`；报告：`runs/...`。
- **结果**：
- **影响/作废项**：无 / 说明具体旧报告或结论。
- **状态**：已实现且验收通过 / 已实现未验收 / 未完成（原因）。
```
