# 维护与发布流程

## 1. 日常改动流程

1. 修改 `custom_routing_rules` 或 `scripts/rulegen/*`。
2. 执行 `bash scripts/check.sh`。
3. 仅在检查通过后提交。

## 2. `scripts/check.sh` 覆盖项

- Python 语法检查：`py_compile`
- 单元与端到端回归：`python3 -m unittest`
- 产物重生成：`python3 scripts/generate_clash_rules.py`
- 产物一致性：`git diff --exit-code`

## 3. 常见失败定位

- `repo 推断失败`：在命令中显式传入 `--repo owner/repo`。
- `strict 模式失败`：先处理 warning，再重新生成。
- `git diff --exit-code` 失败：说明脚本生成结果与仓库产物不一致，需要检查是否遗漏提交。

## 4. 发布前最小核对

- `git status --short` 仅包含预期文件。
- `clash/rules/` 无多余历史残留文件。
- `clash/template.fake-ip.yaml` 与 `custom_routing_rules` 语义一致。
