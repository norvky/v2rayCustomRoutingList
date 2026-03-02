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

## 5. 版本发布清单

1. 代码与产物一致：
执行 `bash scripts/check.sh`，并确认 `git status --short` 为空。

2. 变更可追溯：
确认 commit message 明确且范围单一，并记录影响文件与验证结果。

3. 文档同步：
若有行为变化，更新 `README.md` / `clash/README.md` / `docs/maintenance.md`；如属排障增量，可补故障样本记录。

4. 打版本标签：
执行 `git tag -a vX.Y.Z -m \"vX.Y.Z\"`，再用 `git show -s --format='%H %s' vX.Y.Z` 校验指向提交。

5. 推送发布：
执行 `git push origin main --tags`，并确认远端已可见对应 tag 与提交。
