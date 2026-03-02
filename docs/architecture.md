# 项目结构与职责边界

## 1. 分层模型

### Source 层

- 文件：`custom_routing_rules`
- 职责：定义业务规则意图（直连/代理/阻断、domain/ip/protocol、enabled 等）。
- 约束：这是唯一规则输入源，其他目录不得作为输入源参与生成。

### Engine 层

- 文件：`scripts/generate_clash_rules.py`、`scripts/rulegen/*.py`
- 职责：校验源规则、转换协议语义、渲染输出模板与规则文件。
- 约束：生成逻辑必须可重复执行；同一输入应得到稳定输出。

### Artifact 层

- 目录：`clash/`
- 职责：提供可直接接入客户端或订阅站的产物文件。
- 约束：允许覆盖更新；不手工编辑自动生成文件。

### Reference 层

- 目录：`config-references/`
- 职责：存放互联网收集的参考配置，用于人工比对。
- 约束：仅参考，不参与运行，不作为默认前提。

## 2. 运行边界

- 项目默认针对“正常环境”设计，不预设外部异常状态。
- 网络、容器、宿主机代理等外部问题属于排障输入，不在项目内硬编码兜底。

## 3. 变更流程（建议）

1. 修改 `custom_routing_rules` 或生成器逻辑。
2. 执行 `python3 -m py_compile scripts/generate_clash_rules.py`。
3. 执行 `python3 scripts/generate_clash_rules.py` 刷新产物。
4. 检查 `git diff`，确认仅包含预期改动后再提交。

## 4. 验证入口

- 本地统一检查命令：`bash scripts/check.sh`
- CI 与本地检查保持同一入口，避免“本地通过、CI 失败”的脚本漂移。
