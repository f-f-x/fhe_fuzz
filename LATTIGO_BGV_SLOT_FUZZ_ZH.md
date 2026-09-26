# Lattigo BGV 槽编码专项测试方案

本文记录槽编码的改造边界、风险和可复现实验。目标是补足
`lattigo-bgv` 一元多项式求值器无法表达的 SIMD 语义，同时保持原有
`run_fuzz.py --target lattigo-bgv` 求值路径不变。

## 1. 当前能力与边界

原有 Python 目标已经把 `Plaintext.IsBatched` 设为 `true`，因此它可以测试
逐槽加法、乘法、常数和噪声边界；但输入只取用户指定的前缀，且没有
Galois key，也没有 `RotateColumns`、`RotateRows`、`RotateAndAdd` 和
`InnerSum` 的向量 oracle。只把 `slots` 调大不能解决这个问题：旋转方向、
两行布局和未提供槽位清零都需要单独的参考语义。

这次改造把槽程序放在 Go 原生 `testing.F` 中，而不是改变 Python 的
`ExprSpec` 或 JSON 行协议。这样既能覆盖 Lattigo 官方 BGV evaluator API，
又不会影响已有的表达式求值、噪声分类和长活 helper。

## 2. 优化清单

| 项目 | 实现 | 目的 |
| --- | --- | --- |
| 密钥/参数复用 | `fuzz_test.go` 的 `testContext` 在一个 fuzz target 内只创建一次 | 避免每个输入重建 KeyGen、RelinKey，扩大单位时间覆盖 |
| 全物理槽 round-trip | `slot_fuzz_test.go` 解码 `MaxSlots()`，不只比较前缀 | 发现尾槽截断、槽错位和解码缓冲残留 |
| 编码长度边界 | `FuzzBGVBatchPrefix` 覆盖 0、1、2、7、8、16、半行、末槽和满槽 | 验证 `Encode` 对未提供槽位清零的契约 |
| 槽专用操作 | 覆盖列旋转、行交换、RotateAndAdd、InnerSum、旋转逆元 | 检测 Galois 映射、方向和两行布局错误 |
| 有区分度的语料 | one-hot、首尾哨兵、交替符号、周期边界、稀疏哨兵、行区别 ramp | 避免重复值把旋转错误掩盖掉 |
| 真实模数 oracle | 所有比较均使用 BGV `T=257` 的 center residue | 不把合法模等价误报为错误 |
| 故障门禁 | `FHE_FUZZ_SLOT_FAULT=rotation-plus-one` 只在旋转路径注入额外一格旋转 | 证明槽 oracle 能捕获静默错槽，而不是只测正常路径 |
| 可回灌证据 | `FHE_FUZZ_ARTIFACT_DIR` 输出槽程序、输入向量和失败操作 | 便于最小化、复现和提交 issue |

参考语义直接对齐上游：

* `schemes/bgv/encoder.go` 的 Batched 编解码说明和未映射槽清零行为；
* `schemes/bgv/evaluator.go` 的 `RotateColumns`（每行左旋）、`RotateRows`
  （交换两行）、`RotateAndAdd` 和 `InnerSum` 文档；
* `schemes/bgv/bgv_test.go` 中 `innersum` 的逐行参考实现。

## 3. 可能的问题与处理方式

1. **旋转方向不能凭直觉写。** Lattigo 的列旋转是左旋；oracle 使用
   与官方 `utils.RotateSlice` 相同的 `(i+k) mod n` 语义。发现失败时先确认
   不是把左旋误写成右旋。
2. **BGV 槽是两行布局。** `MaxSlots=N/2`，列旋转不能跨行，行旋转才交换
   两半。测试向量必须在两行使用不同哨兵，否则行交换可能看起来正确。
3. **InnerSum 的输出不是所有槽都被规范定义。** 按上游测试只比较每个
   `batchSize*count` 块的前 `batchSize` 个槽，不把未承诺区域当作漏洞。
4. **Galois key 缺失是配置错误，不是库 bug。** harness 为每个操作生成所需
   的最小 key 集；如果 API 返回缺 key 错误，应记录为 harness 配置失败，不能
   归类为静默错误。
5. **Go fuzz 不懂 FHE 语义。** 它只会把 panic、`t.Fatalf` 和超时当失败；
   槽值错误必须显式进入 oracle。Python 侧的一元表达式 fuzz 仍然保留，二者
   是互补路径。
6. **共享上下文不能并行写。** 实验命令固定 `-parallel=1`；如以后引入
   `t.Parallel`，必须为每个 worker 创建独立密钥和 evaluator。
7. **当前故障门禁不是对 Lattigo 的真实缺陷宣称。** 它只验证检测能力；
   未注入模式下发现的失败仍需关闭故障环境、保存 corpus、独立复跑并检查
   Galois key、模等价和噪声后，才能称为库漏洞。

## 4. 推荐实验流程

以下命令使用已验证的 Go 1.25 工具链。先做门禁，再做长跑。

### 4.1 编译和回归

```bash
cd /home/ffx/fuzz-lab2/fhe_fuzz/go_native/lattigo_bgv
GOTOOLCHAIN=local /home/ffx/fuzz-lab2/.work/go125/bin/go test ./...
```

这一步同时保证原有 `FuzzBGVEncodeDecodeRoundTrip`、
`FuzzBGVArithmeticAgainstNative` 和已知 Decode destination 测试仍能编译。

### 4.2 先证明 oracle 能抓到错槽

```bash
FHE_FUZZ_SLOT_FAULT=rotation-plus-one \
GOTOOLCHAIN=local /home/ffx/fuzz-lab2/.work/go125/bin/go test \
  -run=FuzzBGVSlotProgram -count=1
```

预期为失败，并指出 `rotate-columns` 的具体槽位；这次失败是验收证据，
不是待提交的 Lattigo issue。随后必须取消环境变量运行控制组：

```bash
env -u FHE_FUZZ_SLOT_FAULT \
GOTOOLCHAIN=local /home/ffx/fuzz-lab2/.work/go125/bin/go test \
  -run=FuzzBGVSlotProgram -count=1
```

### 4.3 短跑和覆盖导向长跑

```bash
GOTOOLCHAIN=local /home/ffx/fuzz-lab2/.work/go125/bin/go test -run=^$ \
  -fuzz=FuzzBGVBatchPrefix -fuzztime=10m -parallel=1 -timeout=15m

FHE_FUZZ_ARTIFACT_DIR=/home/ffx/fuzz-lab2/fhe_fuzz/report/lattigo_bgv_slots \
GOTOOLCHAIN=local /home/ffx/fuzz-lab2/.work/go125/bin/go test -run=^$ \
  -fuzz=FuzzBGVSlotProgram -fuzztime=24h -parallel=1 -timeout=25h
```

若需要后台运行：

```bash
mkdir -p /home/ffx/fuzz-lab2/fhe_fuzz/report/lattigo_bgv_slots
tmux new -s lattigo_slots
cd /home/ffx/fuzz-lab2/fhe_fuzz/go_native/lattigo_bgv
FHE_FUZZ_ARTIFACT_DIR=/home/ffx/fuzz-lab2/fhe_fuzz/report/lattigo_bgv_slots \
GOTOOLCHAIN=local /home/ffx/fuzz-lab2/.work/go125/bin/go test -run=^$ \
  -fuzz=FuzzBGVSlotProgram -fuzztime=24h -parallel=1 -timeout=25h \
  > /home/ffx/fuzz-lab2/fhe_fuzz/report/lattigo_bgv_slots/fuzz.log 2>&1
```

按 `Ctrl-B` 后按 `D` 脱离；查看用 `tmux attach -t lattigo_slots`，
查看进程用 `pgrep -af 'go test.*FuzzBGVSlotProgram'`。任务结束后保留日志和
Go 自动保存的 `testdata/fuzz/FuzzBGVSlotProgram` corpus，再关闭会话即可。

### 4.4 失败复现和漏洞筛选

Go fuzz 失败会把最小输入写入 `testdata/fuzz/FuzzBGVSlotProgram/<hash>`。
用下面命令单独复现：

```bash
GOTOOLCHAIN=local /home/ffx/fuzz-lab2/.work/go125/bin/go test \
  -run='FuzzBGVSlotProgram/<hash>' -count=1
```

提交 issue 前应至少完成：

1. 关闭 `FHE_FUZZ_SLOT_FAULT` 后仍失败；
2. 使用同一 corpus 输入重复 3 次，确认不是随机解密噪声；
3. 检查失败是否由缺少 Galois key、错误的旋转方向或未定义的 InnerSum 槽引起；
4. 保存 artifact、Lattigo commit、Go 版本、参数和最小输入；
5. 用原有 Python `lattigo-bgv` 目标做一次回归，确保表达式求值器没有被槽测试改动。

## 5. 结果解释

正常控制组没有失败，只能说明当前语料和参数下没有复现槽错误，不能证明
Lattigo 没有漏洞。故障门禁失败说明 oracle 灵敏；长跑的有效产出应按“新覆盖
路径、可稳定复现的错误、最小化输入”统计，而不是按执行次数直接等同于漏洞数。
