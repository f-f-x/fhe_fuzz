# Lattigo BGV Fuzz 测试运行指南

本文介绍如何使用 `tmux` 在服务器后台运行 Lattigo BGV fuzz 测试，并查看进程、日志和报告。

## 1. 进入测试目录

```bash
cd /home/ffx/fuzz-lab2/fhe_fuzz
```

## 2. 创建 tmux 会话

```bash
tmux new -s lattigo-fuzz
```

`tmux` 可以在 SSH 断开后保持程序运行。

检查已有会话：

```bash
tmux ls
```

## 3. 批量运行多个随机种子

在 tmux 会话中执行：

```bash
cd /home/ffx/fuzz-lab2/fhe_fuzz

for seed in 1001 1002 1003 1004 1005
do
    report="runs/lattigo_seed_${seed}"
    mkdir -p "$report"

    GO=/home/ffx/fuzz-lab2/.work/go125/bin/go \
    LATTIGO_ROOT=/home/ffx/fuzz-lab2/.work/lattigo \
    python3 -u run_fuzz.py \
        --target lattigo-bgv \
        --iterations 50000 \
        --seed "$seed" \
        --slots 16 \
        --repeats 3 \
        --report-dir "$report" \
        > "$report/console.log" 2>&1 < /dev/null

    echo "finished seed=$seed"
done
```

### 主要参数

| 参数 | 含义 |
|---|---|
| `--target lattigo-bgv` | 测试 Lattigo BGV 目标 |
| `--iterations 50000` | 当前种子执行 50000 次迭代 |
| `--seed "$seed"` | 使用当前循环中的随机种子 |
| `--slots 16` | 每次测试使用 16 个 SIMD 槽位 |
| `--repeats 3` | 候选问题重复执行 3 次确认 |
| `--report-dir "$report"` | 保存当前种子的报告 |

### Shell 语法说明

- `for ... do ... done`：依次运行多个种子。
- `${seed}`：展开当前种子变量。
- `mkdir -p`：创建报告目录。
- `GO=...`：指定 Go 编译器。
- `LATTIGO_ROOT=...`：指定被测 Lattigo 源码目录。
- `python3 -u`：禁用 Python 输出缓冲，使日志实时刷新。
- `> file`：保存标准输出。
- `2>&1`：将错误输出合并到标准输出。
- `< /dev/null`：不读取终端输入，避免误输入影响测试。

## 4. 离开 tmux 但保持测试运行

依次执行：

1. 按住 `Ctrl`，按一次 `B`；
2. 松开按键；
3. 单独按小写 `d`。

也就是：

```text
Ctrl+B，然后松开，再按 d
```

重新连接：

```bash
tmux attach -t lattigo-fuzz
```

## 5. 查看运行进程

建议从另一个 SSH 窗口执行：

```bash
pgrep -af "python3.*run_fuzz.py"
```

或者：

```bash
ps -eo pid,ppid,stat,etime,%cpu,%mem,cmd | grep -E "[r]un_fuzz.py|[e]idolon_bgv"
```

长期运行的主要进程是：

```text
python3 -u run_fuzz.py --target lattigo-bgv ...
```

`eidolon_bgv` 是每次评估时临时启动的 Go 子进程，可能不会持续存在。

## 6. 查看实时日志

```bash
tail -f /home/ffx/fuzz-lab2/fhe_fuzz/runs/lattigo_seed_1001/console.log
```

常见状态：

| 状态 | 含义 |
|---|---|
| `ok` | 当前表达式执行正确 |
| `noise-overflow` | 噪声耗尽，属于预期跳过 |
| `candidate` | 发现候选不一致，等待重复确认 |
| `confirmed` | 候选问题已稳定复现 |

例如：

```text
[2400] ok noise=1.0 deg=2 mode=low
```

表示第 2400 次迭代成功，表达式次数为 2，使用低噪声变异策略。

退出日志查看：

```text
Ctrl+C
```

这只会停止 `tail -f`，不会停止另一个窗口中的 fuzz 测试。

## 7. 查看测试报告

```bash
ls -lh runs/lattigo_seed_1001
```

报告文件：

| 文件 | 内容 |
|---|---|
| `run.json` | 总体统计 |
| `bugs.json` | 已确认的问题 |
| `history.jsonl` | 每次迭代记录 |
| `corpus.json` | 动态种子语料库 |
| `console.log` | 终端日志 |

查看总体统计：

```bash
cat runs/lattigo_seed_1001/run.json
```

查看确认的问题：

```bash
cat runs/lattigo_seed_1001/bugs.json
```

## 8. 停止测试

在 tmux 会话中按：

```text
Ctrl+C
```

然后可以退出 tmux：

```bash
exit
```

建议每批使用独立的 `--report-dir`，避免多个种子的报告互相覆盖。当前工具通常在一批测试
正常结束后写入最终报告，因此不要频繁强制终止长批次。

