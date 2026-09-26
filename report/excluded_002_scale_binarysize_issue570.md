# 已排除：`Scale.BinarySize` 序列化长度不足

该问题在当前上游提交中仍可复现：

```text
binary_size=111 actual_len=112
REPRODUCED: BinarySize underestimates serialized length
```

但它已经发布在官方 [Issue #570](https://github.com/tuneinsight/lattigo/issues/570)，
因此不再生成重复 issue。原始复现程序位于：

`fhe_fuzz/lattigo_bgv/scale_probe.go`

