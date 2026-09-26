# Lattigo 最新 main 漏洞审计汇总

## 测试对象

- 项目：`https://github.com/tuneinsight/lattigo`
- 分支：`main`
- 提交：`5dbffbdea05394de2ca3a432ed5318aa832e3f40`
- 提交时间：2026-05-07
- Go：`go1.25.0 linux/amd64`

## 结果统计

| 来源 | 结果 | 结论 |
|---|---:|---|
| `lattigo_bgv_300_bounded` | 231 ok，69 noise-overflow，0 bugs | 正常 BGV 受控 fuzz，未发现漏洞 |
| `lattigo_seed_1001` | 37915 ok，12085 noise-overflow，0 bugs | 50000 次长跑，未发现漏洞 |
| `lattigo_bgv_300` | 61 candidates，29 confirmed | 旧适配器未限制深度，噪声误报，剔除 |
| `lattigo_seed_1002` | 5943 confirmed | 旧适配器高次数噪声误报，剔除 |
| `lattigo_seed_1005` | 19878 confirmed | 旧适配器高次数噪声误报，剔除 |
| `drop-const` fault run | 64 confirmed | 工具自检，故障注入，不是 Lattigo 漏洞 |
| `ring.Poly` 差分探针 | 1000 次通过 | 未发现编码/解码正确性偏差 |
| `Scale.BinarySize` 探针 | 可复现 | 已存在官方 Issue #570，剔除重复报告 |
| `bgv.Encoder.Decode` 非法尺寸 `ring.Poly` 探针 | panic/静默截断可复现 | API 健壮性候选，见 `001_bgv_decode_invalid_poly.md` |

## 去重结论

已从候选中剔除：

- `Scale.BinarySize()` 序列化长度不足：官方 [Issue #570](https://github.com/tuneinsight/lattigo/issues/570)。
- BFV/BGV 超过 32 个 Q 素数导致 panic：官方 [Issue #517](https://github.com/tuneinsight/lattigo/issues/517)。
- BGV 非 Batched 编码长度问题：官方 [Issue #478](https://github.com/tuneinsight/lattigo/issues/478)，且已有后续修复记录。

## 可提交 issue 数量

当前经过复现、去重和影响评估后，保留 1 个低危 API issue 候选：

`bgv.Encoder.Decode` 在 `IsBatched=false` 且目标 `ring.Poly` 为空时 panic；目标维度错误时还会静默返回成功并截断输出。

置信度为中等：问题稳定可复现，而且 `Encode` 会检查相同的维度错误；但 `Decode` 文档要求
传入“from Parameters.RingT”的 `ring.Poly`，维护者也可能将非法尺寸视为调用方违反前置条件。
因此它适合按普通 bug/健壮性问题提交，不应描述为安全漏洞。
