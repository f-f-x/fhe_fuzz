# fhe_fuzz 扩展设计与实验路线图

> 目的：把 `fhe_fuzz` 从「能测 Lattigo BGV 的一元整系数多项式求值」扩展到「能测该库全部方案
> （BFV / BGV / CKKS）+ 核心契约面 + 跨库」，并且对**每一个增量**给出三件事：
> ① 提示词怎么构建 ② oracle / corpus / harness 各改什么 ③ 怎么跑实验、拿什么验收。
>
> 现状基线的所有数字都在 2026-09-25 由本机实测得到，可直接引用，不需要执行者重新猜。

---

## 0. 这份文档怎么用

1. 读 §1 建立对现状的准确认识——**尤其是 §1.2 的三个缺陷**，它们是后续一切增量的前提。
2. 读 §2「改造轴」和 §3「核心架构决策」——这是"改什么"的字典，增量只是它的组合。
3. 从 §4 挑一个增量。每个增量给出可直接粘贴的提示词模板，以及该增量的 oracle / corpus /
   harness 改动清单与验收标准。
4. §5 是提示词构建法则（当 §4 的模板不够用时自己拼）；§6 是实验方法学（长跑 / 覆盖率 /
   找漏洞三种目标各自怎么跑）；§7 是统一的验收标准。

**增量之间是有依赖的。** §4 给出的顺序（I0 → I1 → I2 → I3 → I4 → I5）不是偏好，是依赖关系：
I0 不做，后面每个增量都会把假阳性算成漏洞；归因不先做，从第二个库开始结果就不可信。

---

## 1. 现状基线（实测，2026-09-25）

### 1.1 已经能跑的东西

| 组件 | 文件 | 状态 |
| --- | --- | --- |
| 表达式表示 + 三形式变换 | `eidolon/expr.py` | `scale·Π(aᵢx+bᵢ)+const`，标准/因式/Horner |
| 噪声感知变异器 | `eidolon/mutator.py` | 高噪声 / 低噪声两组算子，`MAX_FACTORS=5` |
| 噪声优先语料库 | `eidolon/corpus.py` | 优先级加权选择，无覆盖率项 |
| 等价性 oracle | `eidolon/oracle.py` | 精确整数比较 + 重执行过滤 |
| 主循环 | `eidolon/engine.py` | `TAU_LOW=0.10` / `TAU_HIGH=0.80` |
| 崩溃隔离 | `engine._run_isolated` | fork + `waitpid(WNOHANG)` + 强制超时 |
| 长活 helper 边界 | `eidolon/runner.py` | `JsonLineRunner`，自动重启 |
| 故障注入自检 | `eidolon/faults.py` | 10 个故障，对应论文 Table 1 |
| 适应器 | `eidolon/targets/` | `seal_bfv` / `concrete_fhe` / `lattigo_bgv` |
| Go 原生 fuzz | `go_native/lattigo_bgv/` | `testing.F`，编解码 / 算术 / Decode 前置条件 |
| Go 语料回灌 | `go_native/replay_go_case.py` | Go 语料 → Python oracle 判定 |

被测库能力盘点（本机）：

| 库 | 位置 | 可用方案（已实测） | 噪声/精度读数 |
| --- | --- | --- | --- |
| Lattigo (Go) | `.work/lattigo` @ `5dbffbde`(2026-05-07) | `bgv`（**BFV 也在其中**，见下）、`ckks`、`multiparty/{mpbgv,mpckks}`。v6 无 TFHE | BGV: `rlwe.Norm` 残差；CKKS: `ckks.GetPrecisionStats` / `ct.LogScale` |
| SEAL C++ 4.1.2 | `/home/ffx/.local`（静态库 + 头文件 + cmake） | `scheme_type = {none, bfv, ckks, bgv}` —— **三种都能驱动** | `Decryptor::invariant_noise_budget` |
| SEAL python | `/tmp/fhe-libs`（`tenseal` 0.3.18，内含 SEAL 3.x） | `sealapi.SCHEME_TYPE` **只有 `{BFV, CKKS}`**，无 BGV | 同上；`CKKSEncoder` / `BatchEncoder` 均在 |
| OpenFHE python | `/tmp/fhe-libs`（wheel 1.5.1.0.24.4，预编译） | `GenCryptoContext` + `CCParams{BFV,BGV,CKKS}RNS` + `BinFHEContext` → BFV / BGV / CKKS / BinFHE | 估计器类 |
| OpenFHE C++ | `/home/ffx/fhe-project/deps/openfhe-install`（**v1.0.4**） | 同上；**18 个 BINFHE 崩溃是在这个版本上发现的** | 同上 |
| Zama Concrete | 系统 python（`concrete.fhe` 2.11.0） | TFHE 编译器级 | 无 → 正确性引导 |
| tfhe-rs | `/home/ffx/fuzz-lab3/targets/tfhe-rs`（v1.8.0+17，已有 cargo-fuzz harness） | TFHE integer/boolean/shortint/strings | 在 fuzz-lab2 之外 |

> **三条容易搞错的事实，已逐个验证：**
>
> 1. **Lattigo v6 的 `schemes/bfv/` 只有一个 `README.md`。** BFV 实现在 `bgv` 包内部，是
>    "BGV/BFV 统一变体"；实例化方式是 `bgv.NewEvaluator(..., scaleInvariant=true)`，该 flag 会
>    把 `Mul`/`MulNew`/`MulRelin` 换成 scale-invariant 版本。**所以 I1.4 不是"再写一个 BFV 适配器"，
>    而是给现有 helper 加一个 flag**（详见 I1.4）。
> 2. **SEAL 4.x 没有 `bfv.h`/`bgv.h` 是设计如此，不是安装不完整。** `/home/ffx/.local/include/`
>    里确实只有 `ckks.h`（那是 CKKS 专属编码器），但 BFV/BGV 走的是通用 API：
>    `EncryptionParameters(scheme_type::bfv)` + `Evaluator` + `BatchEncoder`。静态库里
>    `bfv_*`/`bgv_*` 符号齐全。**结论与"头文件不全所以驱动不了"相反**——三种方案都能驱动。
> 3. **两个 OpenFHE 版本并存且不同**：C++ 是 v1.0.4（2023，18 个崩溃的来源），python wheel 是
>    1.5.1。在 wheel 上重测**测的是另一个版本**，不能与既有崩溃结论直接对比。

四个 python 模块的 import 均已在 2026-09-25 实测通过（`tenseal` 0.3.18 / `openfhe` / `concrete.fhe`
2.11.0 / `mpmath` 1.3.0 + `sympy` 1.14.0）。工具链：g++ 13.3.0、clang++ 18.1.3、cmake 3.28.3、
rustc nightly 1.90.0。

> **范围外的可用件（先记下，不要顺手纳入）**：`/home/ffx/fuzz-lab3/targets/tfhe-rs` 有
> tfhe-rs v1.8.0+17 的完整 checkout，且 `/home/ffx/fuzz-lab3/tfhe-rs-fuzz` 已有构建好的
> cargo-fuzz harness（features `integer,zk-pok,strings`）。它是现成的 TFHE 目标，
> 但**在 fuzz-lab2 之外**——`fhe_fuzz/README.md` 开篇承诺"本目录自包含，不导入或修改
> 目录之外的任何内容"。若要用，需要显式修订这条约束，或者把 tfhe-rs 作为 I4 的
> **外部参考实现**（只读调用，不修改）而非内嵌目标。
> 另：HECO（`/home/ffx/fhe-project/HECO-main`）依赖子模块不完整，**当前不可构建**，别去碰。

Lattigo v6 **没有 TFHE**。所以"该库的其他方案"= **CKKS + BFV（同一个 `bgv` 包的 flag 变体）
+ multiparty（`mpbgv` / `mpckks`）**，外加共享核心 `rlwe`/`ring`（序列化、`Scale`、`ring.Poly`）
与 `circuits/{bgv,ckks}`（含 `circuits/ckks/bootstrapping`）。

### 1.2 三个已被实测证实的缺陷（后续一切增量都要先修）

这三个是**方法实现层面的缺陷**，不是被库的 bug——它们不修，后面任何阴性/阳性结论都不可信。

#### 缺陷 A：搜索塌缩在深度上限，噪声反馈失去作用

实测 `runs/lattigo_recheck_current`（300 迭代，当前代码）：

```
degree 分布: {(1,4), (2,6), (3,5), (4,4), (5,281)}      ← 281/300 停在 degree 5
noise_ratio: min 0.348  max 0.977   ← 274/300 挤在 0.4 一档
verdicts:    ok 300, candidate 0, noise-overflow 0
```

原因在 `engine.py:322`：`if spec.degree() > self.target.max_depth:` 时**整条变异被丢弃**并
`corpus.random_new()`。`lattigo_bgv.py:37` 的 `max_depth = 5` 于是变成一堵墙：高噪声变异器
持续插因子，越界就被扔，最后稳定在"刚好 5 次"。这不是在搜索噪声边界，是在搜索**一个常数**。

**改法**：把深度上限从「事后拒绝」改成「变异器内的硬约束」——越界时**钳制**而不是丢弃；
同时把 `max_depth` 从硬编码常量改成由实测噪声预算推出的量。见 §2 轴 C / 轴 D。

#### 缺陷 B：低噪声变异器从未触发（τ 阈值不可达）

`corpus.json` 里 **`boundary` 标签出现 0 次**，`tags` 只有 `shallow`。即
`corpus.reward()` 的 Low-Noise 分支（`noise_ratio < tau_low`）在 Lattigo BGV 上没执行过一次，
`engine.py:317` 的 `mode` 恒为 `"high"`。

原因是量纲不一致：`engine.py:34` 注释写 `tau_low = 0.1 * eta_0`（相对 η₀），但
`noise_ratio` 的定义是「剩余容量占新鲜容量的比例」（1.0 = 新鲜）。实测该 target 的
`noise_ratio` 下界是 0.348——`TAU_LOW=0.10` 在当前参数下**结构上不可达**。论文的 τ 定义
没错，是这里的实现把两种量纲混用了。

**改法**：新增校准步骤（`--calibrate`），实测该 target 的 `noise_ratio` 分布，把 τ_low/τ_high
取成分位数（如 P10 / P70），并写进 `run.json`。**阈值必须是每个 target 校准出来的，不能是常量。**

#### 缺陷 C：Python oracle 比 Go 原生 fuzz 慢约 200 倍

```
Python Eidolon (lattigo-bgv):  300 迭代 / 14.37 s  ≈    21 iter/s
Go testing.F (FuzzBGVEncodeDecodeRoundTrip): 111,780 execs / 27 s ≈ 4,100 exec/s
                                            （并产生 229 个 new interesting 语料）
```

> 注：`README.md:178` 声称 native fuzz 约 200–280 次/秒，实测约 4,100 次/秒，该数字已过时约 15×。

这不是要"选一个"——两者能力正交：

| | Go 原生 fuzz | Python Eidolon |
| --- | --- | --- |
| 速度 | ~4,100 exec/s | ~21 iter/s |
| 覆盖率反馈 | **有**（`testing.F`） | **无** |
| 能看见静默错值 | **不能**（只认 panic/断言/超时） | **能**（这是它的全部价值） |
| 能看见崩溃 | 能 | 能（fork 隔离） |

**结论：必须组合。** Go 侧负责覆盖率与崩溃，Python 侧负责静默正确性，桥梁就是语料
（`replay_go_case.py` 已有雏形）。§4 的 I5 就是把这条桥修成双向的。

### 1.3 真实发现全部来自定向探针，不是随机 oracle

这一点必须写进任何对外报告，否则会高估当前方案。截至 2026-09-25：

| 发现 | 库 | 发现方式 | 状态 |
| --- | --- | --- | --- |
| `bgv.Encoder.Decode` 接受非法 `ring.Poly`：空 Poly → panic；`NewPoly(1,0)` → 静默只拷 1 个系数 | Lattigo | **手写定向探针** `lattigo_bgv/decode_invalid_probe.go` | 已确认，未提上游 |
| `Scale.BinarySize()` < `len(MarshalBinary())`（111 vs 112） | Lattigo | **手写定向探针** `lattigo_bgv/scale_probe.go` | 排除（上游 Issue #570 重复） |
| 18 个崩溃（15 SIGSEGV + 3 SIGFPE） | OpenFHE 1.0.4 BINFHE | **手写定向探针** `probes/openfhe_binfhe/` | 已确认，未提上游 |
| 随机 oracle（`run_fuzz.py`）在真实库上的真实发现 | — | — | **0** |

随机 oracle 目前的产出全部是：故障注入自检（证明它**能**发现注入的错误）+ 一次已诊断清楚的
假阳性洪水（`lattigo_seed_1002` 5943 / `lattigo_seed_1005` 19878，旧版无深度上界的适配器所致，
已在 `report/00_lattigo_audit_summary.md:17-19` 记录作废）。

**这不是说 oracle 没用，是说它还没被喂到能出东西的地方。** 上面三条真实发现有两个共同点：
(a) 它们都不在「一元多项式求值」这个搜索空间里；(b) 它们是**契约违反**（buffer 维度、序列化长度），
不是数值错误。这直接推出 §3 的架构结论。

### 1.4 环境脆弱点（先修，否则增量会踩到）

* **`/tmp/fhe-libs` 是易失目录。** SEAL / TenSEAL / OpenFHE 的 python 绑定原先全部住在 `/tmp`。
  I0.1 已将完整副本固化到 `.work/pylibs/`，`seal_bfv.py` 默认从该副本加载，
  `FHE_SEAL_PATH` 仍可覆盖；缺失时会明确报错而不会静默回退。（SEAL 相关增量依赖它。）
  注意：`tenseal`/`openfhe` 在裸解释器里 **import 不到**，必须带 `PYTHONPATH`。
* Go 工具链在 `.work/go125/bin/go`（go1.25.0），**不在 PATH**，必须显式传 `GO=`；
  Lattigo 要求 ≥1.25，系统 apt 的 1.22 会失败。
* **Lattigo checkout 处于 detached HEAD 且没有任何 tag**（`git describe` 直接失败）。
  报告里必须记录完整 commit（当前 `5dbffbdea05394de2ca3a432ed5318aa832e3f40`），
  否则"测的是哪个版本"无法追溯。SEAL C++ 与 OpenFHE C++ 同理（4.1.2 / v1.0.4）。
* **网络**：PyPI 可达（`pip` 能用）、`go.dev` 可达、crates.io 下载可用；
  但 **`proxy.golang.org` 超时**。Lattigo 的依赖已在 `/home/ffx/go/pkg/mod` 缓存齐全，
  所以本地 `go build`/`go test` 可离线跑；但**不要引入新的 Go 依赖**。
* 系统 python3.12 + `mpmath 1.3.0` / `sympy 1.14.0` / `numpy 1.26.4` 可用（CKKS 参考实现要用 mpmath）。

---

## 2. 改造轴：改什么

任何增量的改动都落在这七个轴上。表中「当前」一列是实测现状，「CKKS」一列是 §4-I2 的目标。

| 轴 | 当前实现 | BGV/BFV 目标 | CKKS 目标 |
| --- | --- | --- | --- |
| **A. oracle 的 ground truth** | `oracle.py:102` `g != e` 精确整数比较 | 保持（这是 BGV 的优势） | mpmath 50 位实参考 + **精度预算内**的相对误差；三形式各自比，**不用 uniform 信号** |
| **B. 输入域** | `engine._make_xvals()`：整数 + 贴近 `t/2` 的边界值 | 补充负数、0、±1、`t/2±1` 的**槽位排列**（当前是固定位置，未搜索） | 归一化 `[-1,1)`；边界 = `\|m\|→1` 与 `2^-prec` 消失区；**复数槽** |
| **C. 计算空间** | 只变异多项式因子（`ExprSpec`） | + Rotate/Conjugate、+ MulThenAdd/MulRelinThenAdd、+ 明文运算、+ 层级操作 | + **scale Δ**、+ **rescale 时机**、+ level、+ 自举 |
| **D. 噪声/精度监视器** | 归一化到「新鲜容量的剩余比例」 | 校准 τ（缺陷 B）；让 helper 回报 per-form depth（现 Lattigo 回报 `None`） | 精度位数：`ckks.GetPrecisionStats` 或 `logQ − level·LogDefaultScale` |
| **E. 归因** | 无（只有重执行过滤） | 参数合法性门槛 + 库内不变式 + 库内自差分 | 同上，且精度容差本身必须是**可解释**的 |
| **F. 覆盖率** | **无任何覆盖率反馈** | Go `-coverprofile` + 语料桥 | 同左（C++ 侧要 SanitizerCoverage） |
| **G. 参数** | **target 构造时固定一次**，不进搜索 | 参数集进 corpus（有限枚举 + context 池） | 同左，且 scale/level 是一等搜索维度 |

### 轴 G 的关键约束（先说清楚，否则会设计错）

`lattigo_bgv.py:64 setup()` 里 `newContext()` 做 KeyGen + RelinKeyGen，**一次约 0.6 秒**
（300 迭代 14.37s 里绝大部分是它）。所以**不能**每迭代换参数。

正确做法是**有限枚举 + context 池**：

```
参数空间 = {LogN} × {Q 素数个数} × {PlaintextModulus} × {level 预算}
         （每个维度取 3–5 个合法值，全组合约 20–80 组，超出 MaxLevel 的组合直接标非法）
ctx 池   = 每组参数建一次 context，懒加载，LRU 保留最近 N 组
corpus   = ExprSpec 之外再挂一个 params_id，变异时可切换
```

这样"参数"成为一个可搜索维度，代价摊薄到整个 campaign。

---

## 3. 核心架构决策：`ExprSpec` 就是当前的天花板

§1.3 的事实指向同一个结论：**`ExprSpec = scale·Π(aᵢx+bᵢ)+const` 决定了 fhe_fuzz 能测什么。**

Lattigo 的两个真实发现都不在这个空间里——`Decode` 的 buffer 维度、`Scale.BinarySize` 的序列化
长度，都不是"多项式求值"。OpenFHE 的 18 个崩溃也不是。所以：

* 想**加深数值正确性**的测试 → 保留 `ExprSpec`，加宽 **lowering**（轴 C）。
* 想**覆盖契约/健壮性**（这才是目前真实发现的主要来源） → 需要把搜索空间从"表达式"换成
  **"对 FHE 对象的类型化 API 调用序列"**。

这就是 CryptoFuzz / CLFuzz 与本文方案的根本差别：它们模糊测试的是 **API**，本文目前模糊测试的是
**表达式**。表达式是 API 的一个很窄的子集。

**建议：分两步走，不要一次重写。**

* **I1–I3 走「加宽 lowering」路线**：保留三形式等价 oracle（它是本方案相对 CryptoFuzz 的差异化价值），
  只是让每个形式能包含更多算子。改动小、风险低、立刻能用。
* **I4 引入一个轻量类型化 IR**，把 `ExprSpec` 作为一个特例容纳进去：

```
IR 节点（草案）:
  CT       密文句柄
  PT       明文句柄
  Poly     系数编码的 ring.Poly
  Scalar   整数/浮点标量
  Level    层级（CKKS 一等公民）
  Scale    Δ（CKKS 一等公民）

操作:
  add/sub/mul/mulrelin/multhenadd/conjugate/rotate(k)/rescale/droplevel/setScale/scaleup
  encode(→PT) / decode(PT→Vec) / marshal(T)→[]byte / unmarshal([]byte)→T
```

关键设计点：**IR 必须能同时被库和"原生参考实现"求值**——`ExprSpec` 之所以能当 oracle，正是因为
它能被 sympy 精确求值。类型化 IR 同样要有一个 Python 侧参考求值器（整数用精确整数，CKKS 用 mpmath），
否则 oracle 就没了。这是 I4 的主要工作量，也是它排在后面的原因。

---

## 4. 增量路线

每个增量格式统一：**目标 → 依赖 → 提示词模板 → 改动清单 → 实验与验收**。
提示词模板可直接复制粘贴给执行者（人或 agent）。

### 4.0 方案覆盖矩阵（"尽量包含所有"的可核对清单）

§1.1 用文字列举了被测库的方案面，但文字清单不会自己暴露遗漏。下表把**每一行都绑定到
一个承接增量**；凡是"承接增量"为空或写着 ⚠️ 的行，就是路线图尚未覆盖的部分。

**Lattigo（当前唯一在测的库）**

| 方案 / 子系统 | 入口 | 承接增量 | 现状 |
| --- | --- | --- | --- |
| BGV 求值器（加 / 乘 / 明文运算） | `schemes/bgv/evaluator.go` | I1 | ✅ 当前默认目标，已在跑 |
| BGV 槽编码（`IsBatched=true`） | `bgv.Encoder` | I1 | ⚠️ 已用；**系数编码路径未做** |
| BGV 旋转 / Galois（`Rotate`/`Conjugate`/`InnerSum`） | `bgv.Evaluator` | I1 | ❌ 未做（需 Galois 密钥） |
| BGV 层级操作（`Rescale`/`DropLevel`/`MulThenAdd`） | `bgv.Evaluator` | I1 | ❌ 未做 |
| **BFV**（= `bgv` 的 scale-invariant 变体） | `bgv.NewEvaluator(..., scaleInvariant=true)` | I1.4 | ❌ 未做 |
| CKKS 求值器 + 近似语义 | `schemes/ckks/` | I2 | ❌ 未做（本路线图的重头戏） |
| CKKS scale / rescale / level 调度 | `ckks.Evaluator`、`ct.LogScale` | I2 | ❌ 未做 |
| CKKS 精度读数 | `schemes/ckks/precision.go` | I2 | ❌ 未做 |
| **CKKS 自举** | `circuits/ckks/bootstrapping/` | I3.1 | ❌ 未做（**依赖 I2 的容差 oracle**） |
| 多密钥 / 门限（`mpbgv`、`mpckks`） | `multiparty/`、`threshold.go`、`refresh.go` | I3.1 | ❌ 未做 |
| 序列化 / `BinarySize` 契约 | `rlwe/`、`ring/` | I3.1 | ⚠️ 仅手写探针；**已出一个真实发现** |
| `Encode`/`Decode` 的 buffer 契约 | `bgv.Encoder.Decode` | I3.1 | ⚠️ 仅手写探针；**已出一个真实发现** |
| `ring.Poly` / `ring` 核心 | `ring/` | I3.1 | ⚠️ 部分探针 |
| `circuits/{bgv,ckks}` 组合电路 | `circuits/` | I1 / I2 | ❌ 未做 |
| Go 原生覆盖率探路 | `go_native/lattigo_bgv/` | I5 | ⚠️ 已能跑，**未闭环**（见 I5） |

**其他库**

| 库 | 方案 | 承接增量 | 现状 |
| --- | --- | --- | --- |
| SEAL C++ 4.1.2 | BFV / BGV / CKKS | I4.4 | ❌ 未做（三种均可驱动，见 §1.1 事实 2） |
| SEAL python（`tenseal` 0.3.18） | BFV / CKKS（**无 BGV**） | I4.4 | ❌ 未做 |
| OpenFHE python 1.5.1 | BFV / BGV / CKKS / BinFHE | I4.4 | ❌ 未做 |
| OpenFHE C++ v1.0.4 | BinFHE | I3 / I4 | ⚠️ **已出 18 个崩溃**（勿在 1.5.1 上"复现"，见 §1.1 事实 3） |
| Zama Concrete 2.11.0 | TFHE 编译器级 | 已有 | ✅ 适配器在，仅等价性 |
| tfhe-rs 1.8.0+17 | TFHE | 范围外 | ⚠️ 在 fuzz-lab3，受自包含约束（见 §1.1） |

> **读法**：Lattigo 的 15 行里有 **6 行 ❌ 未做、4 行 ⚠️ 只做了半边**。这就是"目前只覆盖了
> BGV 的一个子集"的量化表述。**优先级不按这张表的完成度定，按 §7.2 的证据阶梯定**——
> 先 I0 + I3，再 I1 → I2。CKKS 自举与跨库差分都排在 I2 之后，因为它们共同依赖 I2 的
> 容差 oracle；提前做只会得到无法解释的分歧。

---

### I0 — 地基修复（必须先做，1–2 天）

**目标**：让后续任何结论都建立在可信的基础上。不新增测试能力。

**依赖**：无。

#### 提示词模板

```
【任务】修复 fhe_fuzz 的四个地基缺陷，不新增被测目标，不改搜索算法。

【现状事实（已实测，直接引用，不要重新测量）】
1. /tmp/fhe-libs 装有 SEAL/TenSEAL/OpenFHE 的 python 绑定，是易失目录；seal_bfv.py:35 默认路径
   指向它。
2. runs/lattigo_recheck_current 实测：300 迭代中 281 次停在 degree 5；noise_ratio 274/300 挤在
   0.4 一档；corpus 的 "boundary" 标签出现 0 次，即 engine.py:317 的低噪声分支从未触发。
   engine.py:34 注释写 tau_low = 0.1*eta_0，但 noise_ratio 的定义是"剩余容量/新鲜容量"。
3. 论文的 tau 是相对 eta_0 的，实现里量纲不一致。
4. runs/lattigo_seed_1002(5943) 与 lattigo_seed_1005(19878) 的 "confirmed bug" 是旧版无深度
   上界适配器产生的噪声假阳性，今天用当前代码复现其中一个样例（bug000，degree 1，
   coeffs 达 207 bit）得到 noise_ratio=0、raw=180.3 > budget=178.0、horner 每次输出都不同
   （随机），而 factored/standard 每次都与 native 完全一致 —— 确认为噪声溢出而非缺陷。

【本增量范围】只做以下四件事，不得改动 oracle.py 的判定逻辑、不得新增 target：

I0.1 环境固化
  - 把 /tmp/fhe-libs 完整复制到 /home/ffx/fuzz-lab2/.work/pylibs/
  - 改 seal_bfv.py 的默认路径为 .work/pylibs，保留 FHE_SEAL_PATH 覆盖
  - 在 README 记录该路径，并在 target setup() 里对缺失给出明确报错（不要静默回退）

I0.2 作废旧结果
  - 在 runs/lattigo_seed_1002/ 与 runs/lattigo_seed_1005/ 各放一个 INVALIDATED.md，写明
    作废原因（旧适配器无深度上界 → 噪声溢出被记为已确认）与今天复现的证据
  - 更新 fhe_eidolon_security_audit_zh.md，把这两个数字标注为已作废，而不是继续引用

I0.3 tau 校准
  - 新增 run_fuzz.py --calibrate 模式：跑 N（默认 200）次纯探索，收集 noise_ratio 分布，
    输出分位数表，并按 P10/P70 给出建议的 tau_low/tau_high
  - 把校准结果写进 run.json 的 calibration 字段；未校准时保持现有默认值并在日志里警告

I0.4 深度上限改为约束而非拒绝
  - engine.py:322 现在是 `degree > max_depth → corpus.random_new(); continue`（整条变异丢弃）
  - 改成：越界时交由 mutator 钳制（需要一个 spec.clamped(max_depth) 之类的入口），只有钳制后
    仍非法才丢弃
  - 目标：让 degree 分布铺开，而不是塌缩在 max_depth 这一点

【验收标准（必须逐条给出实测证据）】
- I0.1：把 /tmp/fhe-libs 改名后，`--target seal-bfv --iterations 5` 仍能跑通
- I0.3：给出校准前后的噪声分布对照表；校准后 corpus 中 "boundary" 标签数 > 0
- I0.4：给出修改前后 degree 分布对照（同样是 300 迭代、同样 seed），degree < max_depth 的
        比例应显著上升
- 全部改动后 `validate_oracle.py --target seal-bfv --iterations 50 --seeds 3` 必须仍然
  sensitivity PASS / specificity PASS

【诚实性要求】
- 任何一条没做到，直接写"未完成 + 原因"，不要用"基本完成"糊过去
- 环境类问题可以跳过，但必须在报告里显式列出跳过了什么

【禁止】
- 不要为了让指标好看而放宽 oracle 判定
- 不要修改 runs/ 下已有报告的数字
```

#### 改动清单

| 轴 | 改动 |
| --- | --- |
| 环境 | `/tmp/fhe-libs` → `.work/pylibs`；`seal_bfv.py:35` 默认值 |
| A 归因 | 作废 `lattigo_seed_1002/1005`，更新审计报告 |
| D 噪声 | `--calibrate` 模式；τ 由分位数推出并落盘 |
| C 搜索 | 深度越界改为钳制（`engine.py:322`） |

#### 实验与验收

一次性验收跑，不需要长跑。核心判据：**`validate_oracle.py` 的 sensitivity / specificity 仍然 PASS**，
以及 degree 分布铺开、`boundary` 标签非空。这两条一起才说明"修好了而且没修坏"。

---

### I1 — BGV/BFV 加深（搜索空间从"多项式"扩到"多项式 × 参数 × 算子"，3–5 天）

**目标**：把 Lattigo BGV 的搜索空间扩到真正的 BGV 语义面，并让噪声反馈重新起作用。

**依赖**：I0（尤其 I0.3 的 τ 校准和 I0.4 的深度钳制）。不先做 I0，本增量的所有指标都不可解释。

#### 提示词模板

```
【任务】扩展 fhe_fuzz，使 Lattigo BGV/BFV 的搜索空间覆盖 BGV 的真实语义面。

【现状事实】
- ExprSpec 只能表达 scale*Π(a_i x+b_i)+const；变异器只有 mutator.py 的高/低噪声算子。
- 参数在 lattigo_bgv.py:64 setup() 里由 main.go 的 parameterLiteral 硬编码固定，不进搜索。
- lattigo_bgv.py:37 max_depth=5 是硬编码常量，不是从噪声预算推出的。
- Lattigo v6 的 schemes/bfv/ 目录里**只有一个 README.md**：BFV 是 bgv 包内部的一个
  "统一变体"，通过 bgv.NewEvaluator 的 scale-invariant flag 切换（详见 I1.4）。
  **不要新增 BFV 适配器文件。**

【本增量范围】四件事；不得引入 CKKS（那是 I2）；不得改动 oracle.py 的判定顺序。

I1.1 参数进搜索（轴 G）
  - 把 parameterLiteral 提成请求字段；定义有限参数集（LogN ∈ {9,10,11}，
    Q 素数个数 ∈ {3,4,5}，PlaintextModulus ∈ {257, 65537}），非法组合在 Go 侧返回明确错误
  - Go helper 改成 context 池（LRU，默认保留 8 组），避免每组参数重复 KeyGen
  - corpus 的 Seed 增加 params_id；变异时可切换参数
  - max_depth 改成由实测噪声预算推出，写进 run.json

I1.2 算子扩展（轴 C）
  - 在 ExprSpec 之外引入"算子后缀"：对每个形式，允许在其结果上附加
    {identity, rotate(k), conjugate, mul_then_add(c), rescale, droplevel(n)}
    —— 注意 Lattigo BGV 没有 rescale，rescale 只属于 CKKS，本增量只做 BGV 有的：
    rotate / conjugate / mul_then_add / droplevel
  - 这些算子的**原生参考实现**必须同步实现（rotate = 槽位循环移位，conjugate = 槽位共轭，
    在 BGV 的整数槽语义下要明确写出），否则 oracle 失效
  - 这一步的价值：Lattigo 的 Rotate/Conjugate 依赖 Galois 密钥，出错时是静默错值，
    正是等价 oracle 能抓、Go 原生 fuzz 抓不到的类型

I1.3 噪声监视器补齐（轴 D）
  - 现在 Lattigo 支路 res.meta["depths"] 是 None；让 Go helper 回报 per-form 的
    (level, 乘法深度)，写进 bug 报告
  - 把 ROTATE/CONJUGATE 的密钥切换对噪声的影响纳入观察（它们是 level 无关但噪声相关）

I1.4 BGV ↔ 尺度不变（BFV）库内自差分
  【重要事实，不要按上一版设计做】Lattigo v6 的 schemes/bfv 目录下只有一个 README.md。
  BFV 实现在 bgv 包内部，是一个"统一变体"。README 原文：生成一个 BGV evaluator 并把可选的
  scale-invariant 参数设为 true 即得到 BFV；该 flag 在底层把 Evaluator 的这些方法替换为
  scale-invariant 版本：Mul / MulNew / MulRelin（README 里还有更多）。
  所以：
  - **不要**新写一套 BFV 适配器（那会重复 90% 代码，且实际跑的是同一实现）
  - 而是给现有的 lattigo_bgv/main.go 加一个请求字段 scale_invariant(0|1)，
    在 newContext 里传给 bgv.NewEvaluator
  - 两个 flag 取值共享同一个 context 池的骨架（但注意 evaluator 不同，key 可以复用）
  - 目的：这是**同一实现内、由 flag 切换的两条代码路径**——正好是 CryptoFuzz 的
    "库内自差分"招式的形态（见 §4-I4 表），归因极干净：同一个库、同一套密钥、
    同一组参数、同一输入，两条路径结果必须一致
  - 注意：尺度不变与否会影响噪声增长常数与明文模数约束（README 提到 T 必须与 Q 互素），
    所以两者的 noise_ratio 分布不同，τ 校准要分别做

【验收标准】
- I1.1：给出参数集 × 噪声预算的实测表；跑一轮 2000 迭代，报告 params_id 的覆盖分布
- I1.2：故障注入必须能覆盖新算子 —— 为 rotate/conjugate 各写一个注入故障，
        validate_oracle 的 sensitivity 必须 PASS
- I1.4：对同一批 ExprSpec（seed 固定）分别跑 BGV 与 BFV，报告两者结果不一致的用例数；
        不一致的用例必须逐个归因（是库缺陷 / 参数不当 / 编码语义差异），不允许直接报成 bug
- 全程：validate_oracle 对 lattigo-bgv 的 sensitivity/specificity 必须 PASS

【诚实性要求】
- I1.2 的算子参考实现如果写不出来（语义不清楚），必须明确报告"该算子未能纳入搜索"，
  不要用一个近似实现糊过去 —— 错误的参考实现会把真 bug 变成假阳性
- 新算子如果触发大量 candidate，先怀疑自己的参考实现，不要先怀疑库

【禁止】
- 不要为了让 candidate 变少而调高 repeats 或 noise-floor
```

#### 改动清单

| 轴 | 改动 |
| --- | --- |
| G 参数 | 参数集进 corpus；Go context 池；`max_depth` 由预算推出 |
| C 搜索 | 算子后缀：rotate / conjugate / mul_then_add / droplevel（**含原生参考实现**） |
| D 噪声 | Go helper 回报 per-form depth |
| E 归因 | scale-invariant(BFV) vs 非 scale-invariant(BGV) 库内自差分（**flag 切换，不是两个方案**） |
| Harness | `lattigo_bgv/main.go` 增加 `scale_invariant` 请求字段；**不新增适配器文件** |

#### 实验与验收

短跑验证（2000 迭代）确认参数覆盖与算子覆盖铺开；然后一次 8–12 小时长跑找漏洞。
判据见 §7。**特别注意**：本增量最容易出的问题是"新算子的参考实现写错 → candidate 暴涨"。
识别方法：candidate 是否集中在某一个算子上（集中在某一个 → 几乎一定是参考实现的问题）。

---

### I2 — CKKS（本路线图的重头戏，1–2 周）

**目标**：让 oracle 与 engine 能处理"没有精确真值、没有明文模数、scale 是语义一部分"的方案。

**依赖**：I0 + I1（I1.1 的参数进搜索、I1.3 的监视器补齐都是 CKKS 的前置）。

> **务必先读 §3。** CKKS 不是"给 `oracle.py` 加一个容差参数"就能支持的。
> 下面 6 条每一条都是**语义级**的改动，少一条就会得到要么全是假阳性、要么全是假阴性的结果。

#### 为什么不能照搬（先理解失败模式）

| # | CKKS 的现实 | 照搬 BGV 会得到什么 |
| --- | --- | --- |
| 1 | 结果是近似值 | `oracle.py:102` 的 `g != e` 永远是 True → **100% 假阳性** |
| 2 | 没有明文模数 `t` | `engine._make_xvals()` 的 `t//2` 边界值全部失效（`t=None` 时该分支被跳过，只剩整数 base 值，对 CKKS 无意义） |
| 3 | 三种形式的**浮点舍入路径不同** | 三形式之间天然会有微小分歧 → **cross-form 信号本身失效**，这是最危险的一条 |
| 4 | scale Δ 与 rescale 调度是计算的一部分 | `ExprSpec` 完全无法表达 → 搜索空间缺了 CKKS 最核心的一维 |
| 5 | 噪声的类比是**精度位数** | 现有 `noise_ratio` 语义不适用 |
| 6 | 槽值是 `[-1,1)` 的实数/复数 | 整数 `xvals` 无意义 |

#### 提示词模板

```
【任务】为 fhe_fuzz 增加 Lattigo CKKS 支持。这是语义级改动，不是加一个适配器文件。

【必读】fhe_fuzz/DESIGN_ROADMAP_zh.md §2 与 §4-I2。特别是 §4-I2 的"失败模式"表 —— 
逐条对照实现，任何一条没处理都要在报告里显式说明。

【现状事实】
- 现有 oracle.py:102 是 `g != e` 精确整数比较；oracle.py:84 用 noise_ratio 判溢出。
- engine._make_xvals() 在 plain_modulus=None 时只产出整数 base 值。
- ExprSpec 无法表达 scale / rescale / level。
- Lattigo v6 有 schemes/ckks：evaluator 暴露 ScaleUp / SetScale / DropLevel / Rescale /
  RescaleTo / MulRelin / MulThenAdd / RolRotate(New) / Conjugate / InnerSum / RotateAndAdd；
  有 schemes/ckks/precision.go 的 GetPrecisionStats（内部用 bignum，高精度）。
- 环境有 mpmath 1.3.0，可作 50 位实参考。
- faults.py 里的 fault_ckks_approx_bound 是**假的**：它和 fault_horner_only 用的是同一个
  整数变换 lambda e: e+1，只是换了名字。必须替换成真正的近似误差注入。

【本增量范围】

I2.1 真值层（轴 A）
  - 新增 eidolon/refimpl.py：用 mpmath 50 位实现在 Python 侧的 CKKS 语义参考求值
    （encode 归一化 → 逐算子求值 → 每步记录理论误差上界）
  - 新增 oracle 分支 analyse_approx(res, tol_policy)：
      * 判定不是"相等"，而是 |fhe - ref| <= max(abs_tol, rel_tol*|ref|)
      * abs_tol / rel_tol **不能是常数**，必须来自该次执行报告的精度
        （GetPrecisionStats 的 median precision，或 logQ - level*LogDefaultScale）
      * **禁用 cross-form 作为主信号**：CKKS 下三形式的分歧是预期的。改为
        "某形式的偏差是否显著超过它自己报告的精度" —— 这才是 CKKS 的 cross-form
  - Verdict 增加显式字段：required_precision / observed_error / exceeded_by

I2.2 输入域（轴 B）
  - xvals 改为实数域：\pm(1 - 2^-k) 边界、0、\pm 2^-k 消失区、\pm 1 附近、
    以及复数的实部/虚部组合
  - 输入必须与 Encode 的归一化假设一致（Lattigo CKKS 默认把 [-1,1) 映射到整系数）

I2.3 计算空间（轴 C）
  - 引入 CKKS 专属变异维度：scale Δ（如 2^30/2^40/2^50）、rescale 时机（每层/隔层/不rescale）、
    目标 level
  - 这三者必须与多项式结构**联合**变异，不能独立

I2.4 精度监视器（轴 D）
  - 用 GetPrecisionStats 或 ct.LogScale + ct.Level 计算"当前精度位数"，作为 CKKS 的
    noise_ratio 类比；重新校准 τ（I0.3 的 --calibrate 必须支持 CKKS）
  - CKKS 的"噪声溢出"= 精度不足，判定阈值要有实测依据

I2.5 故障注入补齐
  - 删掉假的 fault_ckks_approx_bound，换成真正的近似缺陷：
    (a) rescale 后 scale 不匹配（少除一次 Δ）
    (b) level 用尽后仍继续乘法
    (c) RescaleTo 的 minScale 边界处理错误
  - 每个故障都要能通过 validate_oracle 的 sensitivity

I2.6 契约面（CKKS 特有，出 bug 概率高）
  - Rescale 在 level 0 调用、SetScale 到非法值、scale 不匹配的密文相加、
    DropLevel 超过当前 level —— 这些是明确的 API 契约，用定向探针（照
    lattigo_bgv/decode_invalid_probe.go 的风格）系统扫一遍

【验收标准（必须逐条给证据）】
- I2.1：**阴性对照必须先过** —— 用当前 Lattigo CKKS 跑 500 迭代无故障，
  candidate 数必须为 0（如果 >0，说明容差策略不对，先修容差，不要报告 bug）
- I2.1：灵敏度 —— I2.5 的每个故障至少产生 1 个已确认 candidate
- I2.2：给出 xvals 的取值表与理由
- I2.3：给出"scale × rescale 时机"的覆盖率矩阵
- I2.4：给出 CKKS 的 precision 分布图/表与校准出的 τ
- I2.6：列出所有探测组合及其结果（包括全部通过的组合 —— 阴性也要记录）

【诚实性要求（本增量的核心）】
- CKKS 上"没找到 bug"极可能是容差太松，而不是库没问题。报告必须包含一项：
  "把容差收紧 X 倍后 candidate 数变成多少" —— 用这个来说明容差不是靠调松来消音的
- 三形式分歧在 CKKS 下是正常的。如果实现里仍然把 cross-form 当主信号，
  必须在报告里说明如何处理了浮点舍入差异

【禁止】
- 不要用固定的 abs_tol（如 1e-6）草草了事 —— 必须与报告精度挂钩
- 不要把 CKKS 塞进现有 ExprSpec 就交付；scale/level 必须成为一等搜索维度
```

#### 改动清单

| 轴 | 改动 |
| --- | --- |
| A 真值 | 新增 `eidolon/refimpl.py`（mpmath）；`oracle.analyse_approx`；Verdict 增字段 |
| B 输入 | `_make_xvals` 的分支化；实数/复数槽值 |
| C 搜索 | CKKS 变异维度：Δ / rescale 时机 / level，与多项式结构联合变异 |
| D 噪声 | `GetPrecisionStats` → 精度位数 → 重校准 τ |
| E 归因 | 容差必须可解释；收紧容差的对照实验 |
| 故障 | 删假 `fault_ckks_approx_bound`，换 3 个真近似缺陷 |
| Harness | `targets/lattigo_ckks.py` + `lattigo_ckks/main.go` |

#### 实验与验收

分三段：
1. **容差标定**（1 天）：无故障跑 500 迭代，确认 0 candidate；得到精度分布。
2. **灵敏度**（半天）：3 个新故障各自必须被检出。
3. **长跑**（2–3 天）：确认无误报后才开长跑，否则长跑只是在生产假阳性。

**本增量的判据不是"找到 bug"，而是"阴性结果可信"**（§7.2）。CKKS 上 0 candidate 只有在
第 1、2 段都过了之后才有意义。

---

### I3 — 同库其他契约面（序列化 / 编码 / 多密钥 / 自举，1 周）

**目标**：把 §1.3 里"真实发现都来自定向探针"这件事**制度化**——不是靠人肉写探针，而是把契约
不变式变成 oracle 的一部分。

**依赖**：I0。与 I1/I2 可并行。

#### 核心思路：CLFuzz 式的"逻辑交叉检验"，不需要第二个库

§1.3 的两个 Lattigo 发现有一个共同结构：**某个 API 承诺了一个不变式，实现违反了它**。

* `Encoder.Decode(pt, ring.Poly)` 承诺"目标 Poly 的维度就是环维度" → 违反：不校验，空 Poly panic，
  `NewPoly(1,0)` 静默只拷 1 个系数。
* `Scale.BinarySize()` 承诺 `BinarySize() >= len(MarshalBinary())` → 违反：111 vs 112。

这类不变式**不需要第二个实现**就能检查，是 CLFuzz 的核心手法。它应该成为 fhe_fuzz 的第二个 oracle。

#### 提示词模板

```
【任务】为 fhe_fuzz 增加"契约不变式 oracle"，并对 Lattigo 全部公开类型系统扫一遍。

【背景】目前 3 个真实发现（Lattigo Decode 维度、Lattigo Scale.BinarySize、OpenFHE 18 个崩溃）
全部来自手写定向探针，不是随机 oracle。本增量把它制度化。

【已确认的两个实例（照此模式推广）】
1. bgv.Encoder.Decode(pt, ring.Poly)：空 ring.Poly{} → panic: index out of range [0] with length 0；
   ring.NewPoly(1,0) → err==nil 且静默只拷贝 1 个系数（环维度 16384）。见
   fhe_fuzz/report/001_bgv_decode_invalid_poly.md
2. rlwe.Scale.BinarySize() == 111 但 len(MarshalBinary()) == 112。见
   fhe_fuzz/report/excluded_002_scale_binarysize_issue570.md（上游 Issue #570 重复）

【本增量范围】

I3.1 不变式清单（先写文档 in invariants.md，再实现）
  至少覆盖以下几族，每条写清"承诺什么 / 违反时是崩溃还是静默错值 / 怎么检查"：
  - BinarySize vs MarshalBinary：对**所有**实现了这两个方法的类型
    （Scale, Parameters, Ciphertext, Plaintext, EvaluationKey, Poly, ...）
  - Encode/Decode 的 buffer 维度：目标切片长度、ring.Poly 维度、N vs MaxSlots
  - 序列化往返：unmarshal(marshal(x)) == x，且 level/scale/metadata 全部保持
  - 跨 level 操作：level 不匹配的密文相加、在 level 0 上 rescale/droplevel
  - 密钥依赖：缺 Galois 密钥时 Rotate 应报错而非静默错值
  - Metadata 传播：乘法/加法/rescale 后 IsBatched / Scale / LogSlots 是否被正确传播
  - **MPC 门限语义**（Lattigo 有 multiparty/{mpbgv,mpckks}，含 threshold.go / refresh.go /
    keygen_*.go）：少于门限的参与方不得恢复明文；refresh 后密文语义不变；
    参与方集合改变后旧份额必须失效
    —— 这一族**天然不需要全精度参考实现**：正确性判据是"门限以下拿不到信息"，
    而这是一个结构性判据，非常适合自动化
  - **自举前后语义不变**（`circuits/ckks/bootstrapping`，**依赖 I2 的容差 oracle，不可提前做**）：
    bootstrap(ct) 的明文应在精度预算内等于 ct 的明文；自举后 level 必须下降（承诺提高
    可用层级）；对同一密文连续自举 K 次，漂移不得超出容差
    —— 这是"实现承诺了却没做到"的典型形态：自举的**全部承诺**就是"提高 level 而
    不改变明文"，所以它天然是一条不变式而不是一个数值比较

I3.2 实现为独立 oracle
  - 新增 eidolon/invariants.py，与 oracle.py 并列，判定类型 Kind.INVARIANT_VIOLATION
  - engine 增加 --invariants 开关；违反时不走 repeats 过滤（不变式是确定性的，不需要）
  - 每条违反都要产出最小复现的 Go 程序，放到 report/ 下（照 001 的格式）

I3.3 定向扫描
  - 对 I3.1 的每条不变式写一个 Go 探针（照 lattigo_bgv/*_probe.go 的风格），
    系统枚举参数组合与类型组合
  - 与上游已有 issue 对照去重（README 里已记录 #517 / #478 / #570 三个已排除项）

【验收标准】
- invariants.md 至少 8 族（I3.1 已列 8 族），每条有明确的检查方法与预期
- 每族至少有一个可执行的探针，输出"通过 N 组 / 违反 M 组"的计数
- 违反项必须逐个给出：(a) 是否上游已报（贴 issue 链接）(b) 崩溃还是静默错值
  (c) 最小复现 (d) 是否可在 fhe_fuzz 里稳定复现
- 阴性结果同样要写进报告（"这族扫了 K 组，全部通过"）—— 这是本增量可信度的一半

【禁止】
- 不要把"参数非法导致的报错"当成缺陷 —— 契约违反的定义是"实现承诺了却没做到"
- 不要重复提交上游已报的项（先查 issues）
```

#### 改动清单

| 轴 | 改动 |
| --- | --- |
| A oracle | 新增 `eidolon/invariants.py`，第二类 oracle（不变式违反） |
| E 归因 | 不变式违反天然不需要归因（确定性、无噪声）——这是最干净的归因类别 |
| Harness | `engine --invariants`；每条违反产出最小 Go 复现程序 |
| 方案面 | 序列化 / 编码 / 密钥依赖 / Metadata / MPC 门限 / **CKKS 自举**（后者依赖 I2） |
| 文档 | 新增 `invariants.md`；报告按 `report/00N_*.md` 格式 |

#### 实验与验收

这是**最可能立刻出结果**的增量：成本低（不需要长跑、不需要噪声模型）、产出明确
（契约违反是二值的）。建议在 I1/I2 的长跑进行时并行做。

---

### I4 — 跨库（需要 §3 的类型化 IR，1–2 周）

**目标**：引入第二个实现，用 CryptoFuzz 式差分 + 库内自差分提高归因能力与发现率。

**依赖**：§3 的类型化 IR、I0 的归因准入、I3 的不变式 oracle。

#### 为什么必须先有 §3 的 IR

拿 Lattigo 和 SEAL 做差分，第一个问题就是"用什么统一表示要算的东西"。用 `ExprSpec` 只能是
多项式——而 §1.3 已经说明真实发现在那个空间之外。所以跨库差分必须建立在一个能同时表达
"多项式求值"和"API 调用序列"的中间表示上。

#### 两个可用的差分模式

| 模式 | 来源 | 需要什么 | 适用 |
| --- | --- | --- | --- |
| **跨库差分** | CryptoFuzz（指定参考实现） | 至少 2 个实现同一方案 | BGV/BFV/CKKS 都有多实现 |
| **库内自差分** | CryptoFuzz 的"同库两条代码路径" | 1 个库，2 条 API 路径 | 见下 |

**库内自差分的三个现成机会**（不需要第二个库，归因最干净）：

1. **Lattigo BGV vs BFV**（I1.4 已建）：同一表达式，两个方案，结果应一致。
2. **批量编码 vs 系数编码**：同一多项式，`IsBatched=true/false` 两条路径。
   ——注意这两者语义不同（一个是 SIMD 逐槽、一个是多项式卷积），
   需要先把"系数编码下的正确基线"写对，否则会得到假阳性。
3. **Lattigo vs Lattigo 的不同 API**：如 `Rotate` vs `RotateHoisted`、
   `MulRelin` vs `MulThenAdd`、`Rescale` vs `RescaleTo`。

#### 提示词模板

```
【任务】为 fhe_fuzz 增加跨库差分与库内自差分能力（I4）。

【依赖检查（开始前必须先确认，不满足则先报告）】
- I0 已完成：环境固化、tau 校准、深度钳制
- I3 已完成：不变式 oracle 存在
- §3 的类型化 IR 已实现，且 IR 有 Python 侧参考求值器
- 每个候选库都有能跑通的最小适配器（不是只有骨架）

【本增量范围】

I4.1 跨库差分 oracle
  - 新增 oracle.compare(impl_a, impl_b, ir_program, tol_policy)
  - **必须指定参考实现**（CryptoFuzz 的做法）：初始只把 Lattigo 当参考，
    SEAL/OpenFHE 作为被测；参考实现自身的问题由 I3 的不变式 oracle 兜底
  - 三个实现之间的分歧要输出三方的值，便于人工判断"是谁错"

I4.2 库内自差分（优先级高于 I4.1，因为不需要第二个库且归因干净）
  - 实现 §4-I4 表里的三个机会；每个都要有明确的"两者应相等"的论证
  - 自差分不一致 = 库自身的问题，不需要讨论参数或参考实现 —— 这是最强的归因工具

I4.3 容差与归因
  - 跨库差分在 CKKS 上同样有浮点问题：两库的舍入策略不同，合法差异是预期的
  - 必须复用 I2 的容差策略，而不是新写一套

I4.4 适配器补齐
  - SEAL python：tenseal.sealapi，**SCHEME_TYPE 只有 {BFV, CKKS}，没有 BGV**，
    从 .work/pylibs 导入（裸解释器 import 不到）
  - SEAL C++：/home/ffx/.local 有 4.1.2 的静态库 + 头文件 + cmake。
    **注意 SEAL 4.x 没有 bfv.h/bgv.h 是设计如此**——BFV/BGV 走通用 API
    （EncryptionParameters(scheme_type::bfv) + Evaluator + BatchEncoder），
    头文件是齐的，三种方案都能驱动。若需要 BGV 且不想用 openfhe，走这条路
  - OpenFHE python：wheel 1.5.1 已可用（BFV/BGV/CKKS/BinFHE 都可构造）
  - **版本陷阱**：OpenFHE C++ 装的是 v1.0.4，18 个 BINFHE 崩溃是在它上面发现的；
    python wheel 是 1.5.1。**不要在 wheel 上"复现"那些崩溃**——那是另一个版本，
    要么用 C++ 1.0.4，要么把结论标注为"在 1.5.1 上重测"
  - 每个适配器都必须实现 I3 的不变式检查接口

【验收标准】
- I4.2：给出三个自差分机会各自的实测不一致数，并逐个归因
- I4.1：给出跨库差分在"无故障"下的分歧率（这个数字必须很小且可解释），
        以及注入一个已知缺陷后的检出率
- 每个新适配器都要通过 validate_oracle 的 sensitivity/specificity

【诚实性要求】
- 跨库差分的分歧率如果很高，先怀疑语义对齐没做对（归一化、编码、level 约定），
  不要先报 bug。报告必须包含"分歧的分布：是集中在某个算子/某个参数，还是随机散布"
- 参考实现本身有 bug 时，会把所有人的结果都判成错。必须明确写：参考实现由什么兜底

【禁止】
- 不要在 IR 与参考求值器没到位时硬上跨库差分 —— 会得到一堆无法归因的分歧
```

#### 改动清单

| 轴 | 改动 |
| --- | --- |
| A oracle | 新增 `oracle.compare(impl_a, impl_b, ir_program, tol_policy)`（跨库差分） |
| A oracle | **库内自差分**：同一 IR 程序走两条 API 路径，结果必须一致——**优先于跨库** |
| C 搜索 | 搜索空间由 `ExprSpec` 换成 IR 程序（**依赖 §3 的类型化 IR + Python 参考求值器**） |
| E 归因 | 三种来源并列：跨库分歧 / 自差分分歧 / 不变式违反；参考实现自身由 I3 兜底 |
| Harness | 新增 SEAL / OpenFHE 适配器，每个都必须实现 I3 的不变式检查接口 |
| 文档 | 把"无故障时的分歧率"作为本底噪声写进报告——它是判断后续分歧是否有意义的基准 |

#### 实验与验收

分两段：先做 I4.2（库内自差分，不需要第二实现，归因干净），验证后再做 I4.1。
判据：**无故障时的分歧率必须小且可解释**；否则先修语义对齐。

---

### I5 — 覆盖率导向与长跑（持续）

**目标**：把"随机 + 噪声优先"改造成"覆盖率反馈"，并把 Go 侧与 Python 侧组合成一个闭环。

**依赖**：I0–I4 任意阶段都可开始，但 I5.1 不依赖 I0。

#### 现状与差距（实测）

```
Python Eidolon:  21 iter/s，无覆盖率反馈，corpus 只有噪声优先级
Go testing.F:  4,100 exec/s，有覆盖率反馈，但只认 panic/断言
```

差距是 **200× 的执行速度和完全缺失的覆盖率信号**。合理架构是把两者接起来：

```
Go native fuzz (覆盖率, 4000/s)
        │  产出 interesting 语料（JSON，已有接口）
        ▼
  语料去重 / 排序 / 转换
        │
        ▼
Python Eidolon oracle (静默正确性, 21/s)   ← 只跑 Go 侧筛出来的少量高价值语料
        │  发现 candidate
        ▼
  最小化 + 归因 + 报告
```

即：**Go 侧当"探路器"，Python 侧当"裁判"**，而不是让 Python 侧自己随机游走。

#### 提示词模板

```
【任务】给 fhe_fuzz 建立"覆盖率探路 + 正确性裁判"的双层闭环（I5）。

【现状事实（实测）】
- Python：300 迭代 / 14.37 s ≈ 21 iter/s，corpus.py 只有噪声优先级，无覆盖率项。
- Go：111,780 execs / 27 s ≈ 4,100 exec/s，产生 229 个 new interesting 语料。
- 已有 go_native/replay_go_case.py 可把 Go 的 JSON 语料回灌到 Python oracle，但它目前
  不是自动化的，也不做去重/排序。
- README.md:178 声称 native fuzz 约 200-280 次/秒，实测约 4,100 次/秒，需要更正。

【本增量范围】

I5.1 覆盖率度量（轴 F）
  - Go 侧：用 go test -coverprofile 跑 fuzz 语料，得到被测包的行覆盖率；
    建立"语料数 → 覆盖率"的曲线，确认覆盖率是否还在增长（不增长 = 搜索空间已饱和）
  - C++ 侧（SEAL/OpenFHE）：评估 SanitizerCoverage 或 gcov 接入成本，先出可行性报告
  - 报告每次 campaign 的覆盖率数字，与存活语料数一起看

I5.2 语料桥自动化
  - Go 侧 fuzz 失败或产生 interesting 语料时，自动写入 FHE_FUZZ_ARTIFACT_DIR
  - 一个调度脚本：批量把 Go 语料喂给 replay_go_case.py，做去重（按 ExprSpec.canonical()）
    与优先级排序（按 I0.3 校准的噪声分位数），把高价值语料注入 Python corpus
  - Python 侧发现的 candidate 反向最小化后，可作为 Go 侧的初始语料（双向）

I5.3 Python 侧的覆盖率信号（可选）
  - 若 C++ 侧覆盖率接入成本过高，退而求其次：用"结构指纹覆盖率"
    （expr.structure_fingerprint + 算子序列指纹）作为 Python 侧的多样性信号，
    加进 corpus 的优先级公式
  - 明确说明这只是代理指标，不是真正的分支覆盖率

I5.4 长跑工程
  - 断点续跑：corpus.json 已经落盘，需要能让 run_fuzz.py --resume runs/X 从语料恢复
  - checkpoint 间隔与报告滚动；崩溃后自动重启并续跑
  - tmux 批量脚本（TMUX_FUZZ_GUIDE.md 已有单方案版本，扩展到多方案/多参数）

【验收标准】
- I5.1：给出"语料数 - 覆盖率"曲线；明确指出覆盖率何时停止增长
- I5.2：Go 语料 → Python oracle 的全自动链路跑通，给出处理量与其中的 candidate 数
- I5.4：人为 kill 一次长跑，--resume 能继续且不重复已完成的工作
- 更正 README 里过时的 200-280 次/秒

【诚实性要求】
- 覆盖率数字必须说明是"被测库的覆盖率"还是"harness 的覆盖率" —— 后者没有意义
- 如果 I5.1 发现覆盖率早已停止增长，直接报告"当前搜索空间已饱和"，这本身是重要结论
```

#### 改动清单

| 轴 | 改动 |
| --- | --- |
| F 覆盖率 | Go 侧 `go test -coverprofile`；建立"语料数 → 被测包覆盖率"曲线 |
| F 覆盖率 | Python 侧退路（I5.3）：`structure_fingerprint` 多样性信号进 corpus 优先级公式 |
| corpus | Go interesting 语料自动落盘 → 按 `ExprSpec.canonical()` 去重 → 按 I0.3 校准的噪声分位数排序 → 注入 Python corpus |
| corpus（反向） | Python 确认的 candidate 最小化后回灌为 Go 初始语料（**双向桥**） |
| Harness | `run_fuzz.py --resume runs/X`；崩溃自动重启并续跑 |
| 脚本 | `TMUX_FUZZ_GUIDE.md` 从单方案扩为多方案 / 多参数矩阵 |
| 文档 | 更正 `README.md:178` 的 200–280 次/秒（实测约 4,100 次/秒） |

#### 实验与验收

这部分是**持续的工程改进**，不是一次性增量。核心判据：**每单位时间能触达的、有意义的
被测库代码路径数**是否在上升。

---

## 5. 提示词构建法则

当 §4 的模板不够用时，按下面的骨架自己拼。**五条"必须写"的条款**是这个项目付出了实际
代价总结出来的，缺任何一条都会得到不可信的结果。

### 5.1 骨架

```
【任务】一句话说清要做什么，以及不做什么。

【现状事实】引用实测数字与文件行号，**不要让执行者自己重新测量或猜**。
           本项目的教训：没有这一节，执行者会用"看起来合理"的假设替代事实。

【依赖检查】开始前必须确认什么；不满足就先报告，不要硬做。
            （例：不先做 I0.3 的 tau 校准，I1 的所有噪声指标都不可解释）

【本增量范围】编号列出每一件事，每件事写清"输入 → 输出"。
             明确写出不得改动什么。

【验收标准】可证伪的判据，**必须包含阴性对照**。
            例："无故障跑 500 迭代，candidate 必须为 0" 就是一个可证伪的阴性判据。

【诚实性要求】预先说明哪些情况必须显式报告失败，以及"跳过"必须怎么写。

【禁止】列出为达标而作弊的路径（放宽阈值、改已有数字、把未完成说成基本完成）。
```

### 5.2 五条必须写的条款

| # | 条款 | 为什么（本项目的实际教训） |
| --- | --- | --- |
| 1 | **现状事实要带实测数字和文件行号** | `README.md:178` 的 "200–280 次/秒" 实测是 4,100——过时数字如果不点名，会被继续引用 |
| 2 | **必须有无故障的阴性对照** | Concrete 的假阳性：`inputset` 被截断导致编译域不含实际输入（`concrete_fhe.py:96-102` 的注释）。没有阴性对照，这个 bug 会被报成库缺陷 |
| 3 | **必须要求归因到 (库缺陷 / 参数错误 / oracle 误报) 三者之一** | `lattigo_seed_1005` 的 19878 个 "confirmed" 就是这么来的；40% 的确认率不是 40% 的 bug |
| 4 | **必须为每个新算子/新 oracle 要求"参考实现"** | 错误参考实现会把真 bug 变假阳性，把假阳性变"发现"。I1.2 的算子必须能写出原生语义 |
| 5 | **必须允许并规范"跳过"** | 环境问题可跳过，但必须显式列出跳过了什么、为什么、影响哪个结论 |

### 5.3 提示词里应避免的写法

| 反模式 | 为什么坏 | 改写 |
| --- | --- | --- |
| "尽量多找 bug" | 会把执行者推向放宽阈值 | "在 specificity 保持 PASS 的前提下提高 sensitivity" |
| "优化性能" | 无判据，无法验收 | "把 Lattigo 目标的 iter/s 从 21 提到 100 以上，且 validate_oracle 仍 PASS" |
| "支持 CKKS" | 掩盖了语义改动量 | 引用 §4-I2 的 6 条失败模式，逐条对照 |
| "参考论文实现" | 论文给的是方法，不是本次的参数选择 | 引用论文的**具体判据**（如 §4.4 的重执行过滤），并说明本项目的参数为什么这样取 |

---

## 6. 实验方法学

三种实验目标，跑法与看的东西完全不同。**不要用一套跑法追三个目标。**

### 6.1 目标一：找漏洞

**前提**：阴性对照先过。否则长跑只是在生产假阳性。

```bash
# 1) 先证伪：无故障对照必须 0 candidate
python3 run_fuzz.py --target <T> --iterations 500 --seed 0 --report-dir runs/<T>_control
#    检查 runs/<T>_control/run.json 的 verdicts.candidate == 0 且 confirmed == 0

# 2) 灵敏度：每个注入故障至少检出一次
python3 validate_oracle.py --target <T> --iterations 50 --seeds 3

# 3) 长跑（前提：1 和 2 都过）
for seed in 2001 2002 2003 2004; do
  python3 -u run_fuzz.py --target <T> --iterations 50000 --seed $seed \
    --report-dir runs/<T>_s$seed > runs/<T>_s$seed/console.log 2>&1
done
```

**看什么**：

| 指标 | 健康 | 不健康 → 怎么办 |
| --- | --- | --- |
| `candidate` 率 | < 1% | 高 → 先查 oracle 的容差/基线，不要报 bug |
| `confirmed` 数 | 个位到几十 | 上百 → 归因失败，参考 §1.2 缺陷 A/B |
| `boundary` 标签种子数 | > 0 | = 0 → τ 不可达（缺陷 B），回去校准 |
| degree 分布 | 铺开 | 塌缩在一点 → 缺陷 A，回去改钳制 |
| `noise-overflow` 占比 | 10–50% | > 80% → 参数/深度上限不合适 |

**产出的判定**：每个 confirmed 必须能回答三个问题——(1) 最小复现是什么 (2) 噪声是否充足
(3) 为什么不是参数问题。三问答不全的，不算发现。

### 6.2 目标二：大分支覆盖率

这一项当前**完全没有数据**（§1.2 缺陷 C）。要做的事：

```bash
# Go 侧覆盖率（对 fuzz 语料）
cd go_native/<lib>
GOTOOLCHAIN=local $GO test -run=^$ -fuzz=<FuzzTarget> -fuzztime=300s
GOTOOLCHAIN=local $GO test -coverprofile=cover.out -run=. ./...   # 对语料跑覆盖率
GOTOOLCHAIN=local $GO tool cover -func=cover.out | tail -1        # 总覆盖率
```

**关键判据不是覆盖率绝对值，而是它的导数**：语料数增加时覆盖率还在涨吗？不涨了说明
搜索空间饱和——这本身就是有价值的结论（说明该库的这条路径已经被探完）。

C++ 侧（SEAL / OpenFHE）需要 SanitizerCoverage，接入成本要单独立项评估（I5.1）。

### 6.3 目标三：长跑稳定性

长跑失败的典型原因是**基础设施**，不是库。检查清单：

- `--case-timeout` 必须真正生效（`engine._run_isolated` 已修，见 `README.md:148-153`）
- 子进程存活用 `waitpid(WNOHANG)` 判，不用 EOF（同一节）
- helper 崩溃后 `JsonLineRunner` 自动重启且不复用失效密钥（`runner.py:110-113`）
- checkpoint 落盘 + `--resume`（I5.4 待做）
- 内存：`--max-corpus` 与 `--max-bugs` 有上界
- 报告目录每批独立，不要互相覆盖（`TMUX_FUZZ_GUIDE.md:190`）

**判据**：24 小时不间断，报告完整，`run.json` 的 `elapsed_s` 与墙钟一致，无人工干预。

### 6.4 长跑的时间预算（用实测速度推算）

| 目标 | 速度 | 24 小时 | 说明 |
| --- | --- | --- | --- |
| Python Eidolon | 21 iter/s | ~1.8e6 迭代 | 每个迭代含 3 形式 + 重执行 ×3，实际是 ~1e7 次库调用 |
| Go native | 4,100 exec/s | ~3.5e8 execs | 但没有正确性判据 |

**不要把这个乘积当作漏洞数。** `README.md:178` 已经提醒过这点，仍然成立。

---

## 7. 验收标准

### 7.1 通用（每个增量都必须满足）

1. **`validate_oracle.py` 的 sensitivity 与 specificity 双 PASS**——包括新增的方案。
   这是唯一能区分"库很干净"和"oracle 瞎了"的判据。
2. **归因准确性**（目前缺失，I0 起补）：注入库缺陷 → 报告必须归因到库；故意参数越界 →
   必须判 `OUT_OF_SPEC` 而不是 candidate。
3. **阴性结果同样入档**：扫了 K 组全部通过，也要写下来。
4. **可独立复现**：每个发现都要有一个不依赖 fuzzer 的最小复现程序。

### 7.2 什么算"这个方案有效"

按证据强度从弱到强：

| 等级 | 判据 | 当前状态 |
| --- | --- | --- |
| L0 | 故障注入能被检出（灵敏度） | ✅ 已达成（SEAL / Concrete / Lattigo） |
| L1 | 无故障对照 0 误报（特异性） | ✅ SEAL/Concrete 达成；Lattigo 于 I0 后达成 |
| L2 | 归因准确（库缺陷 / 参数 / 误报 分得清） | ❌ **未达成** —— I0.2 起补 |
| L3 | 在真实库上找到 1 个此前未知的缺陷，且由随机 oracle（非定向探针）发现 | ❌ 未达成 |
| L4 | 该发现被上游确认 | ❌ 未达成 |

**当前停在 L1，L2 是下一个必须跨过的台阶。** 在 L2 达成之前，L3 的任何"发现"都不可信——
§1.2 已经用 19878 个假阳性演示过这个失败模式。

---

## 8. 一页速查

| 增量 | 一句话 | 依赖 | 主要改动 | 判据 |
| --- | --- | --- | --- | --- |
| **I0** | 修地基：环境固化 / 作废旧结果 / τ 校准 / 深度钳制 | — | 环境、轴 C、轴 D | 双 PASS + degree 分布铺开 |
| **I1** | BGV/BFV 加深：参数与算子进搜索 | I0 | 轴 C、G、E | 参数/算子覆盖 + 新故障可检出 |
| **I2** | CKKS：容差 oracle + 精度监视 + scale 进搜索 | I0, I1 | 轴 A、B、C、D | **阴性对照先过** + 新故障可检出 |
| **I3** | 契约不变式 oracle（同库，不需第二实现） | I0（自举那族另需 I2） | 第二类 oracle | 不变式清单 + 探针通过/违反计数 |
| **I4** | 跨库差分 + 库内自差分 | I0, I3, §3 的 IR | 轴 E、A | 无故障分歧率小且可解释 |
| **I5** | 覆盖率闭环：Go 探路 + Python 裁判 | 任意 | 轴 F | 覆盖率导数 > 0 |

**最优先的两件事**（如果只能做两件）：I0.1（环境固化，`/tmp` 随时会没）和 I3（契约不变式，
成本最低、与已有真实发现的模式完全一致）。

---

## 附：本文档引用的事实来源

| 事实 | 来源 |
| --- | --- |
| 300 迭代 degree 塌缩在 5、noise 挤在 0.4、`boundary` 标签为 0 | `runs/lattigo_recheck_current/{history.jsonl,corpus.json}` |
| Python 21 iter/s | 同上，`run.json` 的 `elapsed_s: 14.37` |
| Go 4,100 exec/s、229 new interesting | 本机 `go test -fuzz=FuzzBGVEncodeDecodeRoundTrip -fuzztime=25s` |
| 19878 假阳性的机理 | `runs/lattigo_seed_1005/bugs.json` 的 bug000 重放（noise=0, raw 180.3 > budget 178.0, horner 每次随机） |
| 两个 Lattigo 真实发现来自定向探针 | `report/00_lattigo_audit_summary.md`、`report/001_bgv_decode_invalid_poly.md`、`report/excluded_002_scale_binarysize_issue570.md` |
| OpenFHE 18 个崩溃来自定向探针 | `fhe_eidolon_security_audit_zh.md:109-168` |
| Lattigo v6 只有 bgv/ckks（BFV 在 bgv 内） + multiparty | `.work/lattigo/schemes/`（`bfv/` 只有 README.md）、`schemes/bfv/README.md`、`multiparty/` |
| CKKS API 面 | `.work/lattigo/schemes/ckks/{evaluator.go,precision.go}`、`circuits/ckks/bootstrapping/` |
| SEAL 4.1 三种方案都能驱动 | `/home/ffx/.local/include/SEAL-4.1/seal/encryptionparams.h:25-38`（`scheme_type = {none,bfv,ckks,bgv}`） |
| OpenFHE C++ 为 v1.0.4 / python wheel 为 1.5.1 | `/home/ffx/fhe-project/deps/openfhe-install` vs `/tmp/fhe-libs` |
| 工具链与网络可达性 | 本机实测（PyPI/go.dev/crates 可达，`proxy.golang.org` 超时） |
| 故障注入的假 CKKS 项 | `eidolon/faults.py:211-214` 与 `:195-203` 变换相同 |
| 隔离原语的两个已修缺陷 | `README.md:146-153`、`eidolon/engine.py:65-151` |
| Concrete 假阳性根因 | `eidolon/targets/concrete_fhe.py:90-102` 的注释 |
