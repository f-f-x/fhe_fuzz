# `fhe_fuzz`——Eidolon 风格的噪声感知 FHE 模糊测试器

这是依据 **Eidolon**（FSE 2026）论文实现的、面向全同态加密库的噪声感知模糊测试器。它用于查找 FHE 计算中的*静默正确性错误*——这类缺陷不会让库停止运行，库仍会返回看似合理的密文，但其底层明文实际上已经错误。

本目录是自包含的，不会导入或修改目录之外的任何内容。

```
fhe_fuzz/
├── CHANGELOG_zh.md             修改日志、实验基线与后续记录模板
├── DESIGN_ROADMAP_zh.md        扩展设计与实验路线图（BFV/BGV/CKKS/契约面/跨库，含提示词模板）
├── run_fuzz.py                 CLI 入口
├── validate_oracle.py          故障注入预言机自验证
├── eidolon/
│   ├── expr.py                 表达式表示和等价变换
│   ├── mutator.py              高噪声/低噪声变异器
│   ├── corpus.py               噪声感知的能量调度
│   ├── oracle.py               等价性预言机（论文第 4.4 节）
│   ├── engine.py               模糊测试循环（论文算法 1）
│   ├── runner.py               长活 native helper 的 waitpid/超时/重启边界
│   ├── faults.py               故障注入，用于验证预言机
│   └── targets/
│       ├── base.py             执行适配器接口
│       ├── seal_bfv.py         Microsoft SEAL BFV（可获取噪声预算）
│       ├── concrete_fhe.py     Zama Concrete（仅支持编译器级等价性）
│       └── lattigo_bgv.py      Lattigo v6 BGV（Go 进程适配器）
├── lattigo_bgv/                Lattigo 专用 Go 适配器和差分探针
├── go_native/lattigo_bgv/      Go 1.25 testing.F 原生 fuzz 目标
│   ├── fuzz_test.go            编解码、算术和已知 Decode 前置条件测试
│   ├── slot_fuzz_test.go       全槽编解码、旋转、RotateAndAdd、InnerSum
│   └── go.mod/go.sum           指向当前 .work/lattigo 的可复现模块
├── go_native/replay_go_case.py Go 语料回灌 Python oracle
├── LATTIGO_BGV_SLOT_FUZZ_ZH.md 槽编码优化清单、风险和长跑方案
└── probes/                     独立的一次性差分探针
```

---

## 1. 用一段话说明原理

取一个多项式 `P(x) = scale · Π(aᵢ·x + bᵢ) + const`，将其写成数学上完全相同的三种形式——**因式分解形式**（原始写法）、**标准形式**（完全展开）和 **Horner 形式**（嵌套形式）。将这三种形式使用相同的输入，全部交给同一个 FHE 库执行。三种形式解密后必须相同，并且结果必须等于按照该库自身明文语义归约后的精确整数运算结果。当某一种形式出现不一致时，原因不可能只是噪声：三种形式都使用同一组参数运行，因此噪声会以相同方式影响*所有*形式。这就是预言机。模糊测试器要做的是引导搜索进入最可能出现不一致的区域——多项式次数高、系数大、接近噪声预算边界。

## 2. 快速开始

```bash
cd fhe_fuzz

# Microsoft SEAL BFV——忠实配置（可以读取噪声预算）
python3 run_fuzz.py --target seal-bfv --iterations 200 --report-dir runs/seal

# 校准噪声阈值：默认采样 200 次，输出 P10/P70 建议并写入 run.json
python3 run_fuzz.py --target seal-bfv --calibrate --report-dir runs/seal_calibration

# Zama Concrete——编译器级等价性预言机
python3 run_fuzz.py --target concrete --iterations 40 --bits 8 --slots 16 \
                    --report-dir runs/concrete

# 证明预言机确实有效：注入一个已知错误并观察它被捕获
python3 run_fuzz.py --target seal-bfv --fault square --iterations 60

# 完整的灵敏度/特异性矩阵（这是验收测试）
python3 validate_oracle.py --target seal-bfv --iterations 50 --seeds 3

# Lattigo：LATTIGO_ROOT 指向上游最新 main 的 checkout
GO=/path/to/go LATTIGO_ROOT=/path/to/lattigo \
  python3 run_fuzz.py --target lattigo-bgv --iterations 300 --slots 16 \
  --repeats 3 --report-dir runs/lattigo_bgv
```

Lattigo 适配器启动时会从 `LATTIGO_ROOT` 编译 Go 适配器，因此报告应同时记录被测仓库的
Git 提交和 Go 版本。适配器现在保持一个长活 Go 会话，复用 KeyGen/RelinKey；会话超时、
EOF、信号退出或 Go panic 时由 `JsonLineRunner` 按 `waitpid(WNOHANG)` 判定并杀掉/重启，
不会把已失效的密钥状态交给下一用例。BGV 适配器明确使用 `IsBatched=true`，与 Python
逐槽基线一致；残余噪声按官方测试方式先减去独立编码的期望明文，再调用 `rlwe.Norm`。
因此 `noise_ratio` 不再是“只要能解密就固定为 1”。

Lattigo 目标额外加载了来自 `schemes/bgv/bgv_test.go` 的专用初始种子，覆盖 Batched
有符号值、常数/负明文、平方与立方、`MulRelin`/`MulThenAdd` 的算术投影，以及明文模数
边界。`ring.Poly` 编解码、错误类型和旋转等无法表示为一元多项式的用例，分别由
`lattigo_bgv/poly_probe.go` 等 Go 探针测试。

`run_fuzz.py --help` 会列出所有可调参数；其中值得关注的是 `--tau-low` / `--tau-high`（用于选择变异器的噪声阈值）、`--noise-floor`（低于该残余噪声比直接归为噪声溢出）、`--repeats`（重新执行过滤器的预算）、`--checkpoint-every`（长跑中间落盘）、`--max-corpus`/`--max-bugs`（限制内存和报告增长）以及 `--no-isolate`（仅适合调试 Python 目标）。Lattigo 自己的 runner 负责 native 进程隔离，不会再被 Engine fork。

SEAL/TenSEAL/OpenFHE 的 Python 绑定固定复制到仓库内的 `.work/pylibs/`（默认路径）。这是
`/tmp/fhe-libs` 的持久化副本，避免重启或清理 `/tmp` 后同一实验无法复现；若确实需要另一份
完整绑定，可设置 `FHE_SEAL_PATH=/绝对路径` 覆盖。目标 setup 遇到缺失目录会直接报错，
不会静默回退到 `/tmp`。校准模式是无故障纯探索：把本轮 `noise_ratio` 的 P10/P70 写入
`run.json.calibration`，并把不高于 P10 的语料标记为 `boundary`；普通运行未使用校准时会
在日志中明确警告并继续使用默认 `tau_low=0.10`、`tau_high=0.80`。

例如校准报告给出 P10=`0.52931446`、P70=`0.60439433` 后，可在下一轮显式使用：

```bash
python3 run_fuzz.py --target lattigo-bgv --tau-low 0.52931446 \
  --tau-high 0.60439433 --iterations 50000 --seed 1001 \
  --report-dir runs/lattigo_calibrated_seed_1001
```

## 3. 如何接入新的 FHE 库

每个库恰好对应一个库专用文件。实现 `eidolon/targets/base.py::Target`：

| 成员 | 含义 |
| --- | --- |
| `name` | 报告中使用的标签 |
| `plain_modulus` | 库使用的明文环；如果不存在唯一的明文环，则为 **`None`** |
| `slots` | 一个密文包含的 SIMD 槽位数 |
| `max_depth` | 当前配置参数可支持的乘法深度 |
| `fresh_noise()` | η₀——新鲜密文的残余噪声，使用*你的*单位 |
| `evaluate(spec, xvals, forms)` | 完整适配器：降低每种形式、运行、解密并报告结果 |
| `close()` | 释放本地句柄 |

`evaluate` 返回一个 `EvalResult`：

```python
EvalResult(
    outputs = {"standard": [...], "factored": [...], "horner": [...]},  # 每种形式也可以为 None
    native  = [...],          # 精确整数基线，所有形式共用
    natives = {...},          # 可选的逐形式基线（见下文）
    noise_ratio = 0.42,       # 残余噪声 / η₀——驱动变异器选择
    crash = False, error = None,
    meta = {...},             # 自由格式的诊断信息，会写入报告
)
```

然后在 `run_fuzz.py::make_target` 中注册它。

### 两个容易出错的地方

**1. `native` 与 `natives`。** 大多数库只有一个明文模数，因此使用单一的 `native` 基线是正确的。但如果*每个电路分别选择明文环*——例如 Concrete 这样的编译器可能为一种形式推断出 `uint7`，为与之等价的另一种形式推断出 `int7`——使用全局模数会制造纯粹由测试框架造成的不一致。此时，应在 `natives[form]` 中填入归约到**该形式自身明文环**的基线，并将 `plain_modulus = None`，这样引擎就不会合成无意义的“接近明文模数”的槽位值。参见 `targets/concrete_fhe.py` 中的完整示例；其中的注释记录了促成这一改动的误报。

**2. 噪声监视器。** 如果库能暴露残余噪声（`SEAL`：`Decryptor.invariant_noise_budget`；`HElib`：`capacity()`；`OpenFHE`：静态估计器），请将其报告为 `noise_ratio = raw / fresh_noise()`，这样引擎的覆盖率引导就能按论文所述工作。如果库不提供该信息，则退回到*正确性引导的推断*——将 `noise_ratio` 设为常量，并让解密成功/失败模式承载信号。`ConcreteTarget` 就采用这种方式。

## 4. 预言机的判定顺序

`eidolon/oracle.py::analyse` 会对一次执行进行分类：

1. **crash**——目标抛出异常，或子进程因信号终止（SIGSEGV/SIGFPE）。始终报告该结果；`engine._run_isolated` 会为每次评估派生一个子进程，因此一次崩溃不会终止整个测试活动。
2. **noise-overflow**——没有任何结果成功解密。这属于预期情况；它会作为退避信号送入语料库，但绝不会报告为漏洞。
3. **ok**——所有可以解密的形式都与各自基线匹配。该结果会奖励语料库。
4. **candidate**——出现不一致。再按信号细分：
   * `cross-form`——部分形式与基线一致，而其他形式不一致。**这是强信号**；噪声无法产生这种结果。
   * `uniform`——所有可以解密的形式都错误。信号较弱，通常是噪声导致的。

`candidate` 还不是漏洞。`engine._consider_candidate` 会使用新的加密随机性重新执行该用例 `--repeats` 次，只有当相同的 `(form, slot)` 偏差签名重复出现（与初始运行相比 Jaccard ≥ 0.5）时才保留它。真实的实现错误具有确定性；噪声导致的失败则会重新打乱出错的槽位。这是论文中的误报过滤器，也是一个可用预言机与一个充斥噪声的漏洞报告生成器之间的区别。

随后，保留下来的候选会由 `engine._shrink` **最小化**为最小工作示例（贪心地删除因子/项，同时保持偏差仍然存在）。

## 5. 验证预言机

如果一个模糊测试器报告“没有漏洞”，但你不知道存在漏洞时它是否确实能够报告，那么这个测试器没有价值。`faults.py` 会破坏 FHE 侧的表达式，而原生基线仍保留真实多项式，从而按需产生真正的分歧。每种故障都对应论文表 1 中记录的一类错误：

| `--fault` | 模拟的错误 |
| --- | --- |
| `square` | 将 `x²` 降低为 `x² − x`（OpenFHE CVE-2024-50669 类问题） |
| `drop-const` | 降低过程中丢失加法常数（SEAL BUG#719 类问题） |
| `wrong-modulus` | 使用错误的明文环归约系数 |
| `negative-plain` | `ct × pt` 对负明文处理错误（论文图 2） |
| `horner` | **只有** Horner 重写出错——这是朴素的“FHE 与原生结果比较”预言机会不断将其误报为噪声的情况 |
| `crash-deep` | 对次数 ≥ 4 的表达式触发 SIGSEGV（论文中的空指针 CVE） |

`validate_oracle.py` 会在 N 个种子上运行控制组和每一种故障，并断言两个性质：

* **灵敏度**——每个注入的故障至少产生一个已确认的漏洞；
* **特异性**——未注入故障的控制组不会产生任何漏洞。

修改 `oracle.py`、`engine.py` 或某个目标后都应运行它。计数值会在不同批次之间波动（它们统计的是随机搜索过程中确认的漏洞数量）；真正必须满足的是上述两个性质。

### 5.1 在信任崩溃检测器之前，请先阅读

`engine._run_isolated` 会为每次评估派生子进程，因此 SIGSEGV 不会终止整个测试活动。这里有两个容易出错的地方；它们都是在验证崩溃故障时付出实际代价后总结出来的：

* **已死亡的子进程不等同于管道遇到 EOF。** LLVM 的崩溃处理器会派生外部符号化工具（`llvm-symbolizer`），该工具会*继承管道的写端*。子进程虽然已经死亡，但写端仍处于打开状态；阻塞式 `read()` 会一直等待。权威的“子进程已结束”信号是 `waitpid(WNOHANG)`，而不是 EOF。
* **必须强制执行超时。** 一个没有真正执行的 `timeout` 参数比完全没有超时更糟：它看起来提供了保护，但一个卡死的子进程会让整个测试活动卡死。

对编译器目标（Concrete）而言，实际后果是：虽然会报告崩溃，但 `signal` 字段显示的是 `timeout after 120s`，而不是 `signal 11 (SIGSEGV)`，因为 MLIR 的处理器会将子进程的回收延迟到超过预算。在 SEAL 上，信号可以正常获取。如果需要在编译器目标上获得准确的信号，请提高单次评估的超时时间，而不要降低它。

## 7. Go 原生 fuzz（互补层）

Go 的 `testing.F` 只把 panic、失败断言和超时视为故障；它不理解“解密结果静默错误”，所以不能替代 Python 的等价表达式 oracle。先通过阶段 1 的 oracle 门禁，再运行：

```bash
cd fhe_fuzz/go_native/lattigo_bgv
GOTOOLCHAIN=local /path/to/go125/bin/go mod tidy
GOTOOLCHAIN=local /path/to/go125/bin/go test ./...
GOTOOLCHAIN=local /path/to/go125/bin/go test -run=^$ \
  -fuzz=FuzzBGVEncodeDecodeRoundTrip -fuzztime=60s
GOTOOLCHAIN=local /path/to/go125/bin/go test -run=^$ \
  -fuzz=FuzzBGVArithmeticAgainstNative -fuzztime=60s
```

`FuzzBGVDecodeDestination` 是当前 upstream 的已知发现，默认跳过；要验证该缺陷：

```bash
FHE_FUZZ_EXPECT_BUG=1 GOTOOLCHAIN=local /path/to/go125/bin/go test -run=^$ \
  -fuzz=FuzzBGVDecodeDestination -fuzztime=1s
```

Go 语料的接口是与 helper 相同的 JSON：`factors`、`scale`、`const`、`x`、`forms`。若原生 fuzz 断言失败，可将该对象保存到 `FHE_FUZZ_ARTIFACT_DIR`，再使用 `go_native/replay_go_case.py artifact.json --lattigo-root ...`；脚本会重新构造 `ExprSpec`、启动长活 Lattigo runner，并输出 Python oracle 的 `ok/noise-overflow/candidate/crash` 判定。Go 侧发现“高噪声”时也只作为语料提示，最终是否为漏洞仍由 Python 侧复核。

当前参数下实测 native fuzz 约 200–280 次/秒（取决于目标和机器）；24 小时的数量级是约 1.7e7–2.4e7 次输入，但有效覆盖取决于 `testing.F` 的新覆盖率，不应把这个乘积当作漏洞数量。

### 7.1 Lattigo BGV 槽编码专项

`go_native/lattigo_bgv/slot_fuzz_test.go` 是与 Python 表达式目标并列的
专项 harness。它覆盖 `MaxSlots()` 全向量、编码前缀清零、列旋转、行交换、
`RotateAndAdd`、`InnerSum` 和旋转逆元；参考语义按上游
`schemes/bgv/encoder.go`、`evaluator.go` 与 `bgv_test.go` 编写。该文件不改
`run_fuzz.py --target lattigo-bgv` 的请求协议，所以原有 BGV 求值器仍可照常测试。

先证明槽 oracle 能抓到一个额外旋转，再运行控制组：

```bash
cd fhe_fuzz/go_native/lattigo_bgv
FHE_FUZZ_SLOT_FAULT=rotation-plus-one \
  GOTOOLCHAIN=local /home/ffx/fuzz-lab2/.work/go125/bin/go test \
  -run=FuzzBGVSlotProgram -count=1       # 预期失败，证明灵敏度
env -u FHE_FUZZ_SLOT_FAULT \
  GOTOOLCHAIN=local /home/ffx/fuzz-lab2/.work/go125/bin/go test \
  -run=^$ -fuzz=FuzzBGVSlotProgram -fuzztime=10m -parallel=1
```

失败时设置 `FHE_FUZZ_ARTIFACT_DIR` 保存槽程序 JSON；Go 自动 corpus 位于
`testdata/fuzz/FuzzBGVSlotProgram`。长跑、tmux、失败复现和 issue 筛选的完整
步骤见 [`LATTIGO_BGV_SLOT_FUZZ_ZH.md`](LATTIGO_BGV_SLOT_FUZZ_ZH.md)。

## 8. 如何阅读报告

`--report-dir` 会写入四个文件：

| 文件 | 内容 |
| --- | --- |
| `bugs.json` | 已确认的漏洞：用例 ID、类型、信号、表达式、最小化形式、逐形式不匹配计数、重新执行证据和目标元数据 |
| `run.json` | 配置、最终计数器和环境 |
| `history.jsonl` | 每次迭代一行：判定结果、噪声比、次数、变异器模式——可用于重新绘图的原始轨迹 |
| `corpus.json` | 带有优先级和标签的存活种子 |

如果 `bugs.json` 为空，应查看 `history.jsonl`，确认搜索是否到达了有意义的区域（`noise_ratio` 接近 τ_low、次数不断升高），还是只是在原地循环。
