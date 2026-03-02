# v2rayCustomRoutingList

基于 `custom_routing_rules` 生成 Clash/mihomo 规则产物的仓库。

## 项目定位

- 唯一规则源：`custom_routing_rules`
- 生成入口：`scripts/generate_clash_rules.py`
- 发布产物：`clash/` 下的模板、主片段与 `rules/*.yaml`

## 固定原则

- 单策略：仅维护 `fake-ip`，不维护 `redir-host` 双轨配置。
- 正常环境默认：不把外部异常场景（例如默认有代理环境）写成项目默认前提。
- 职责边界清晰：仓库只保证可控范围内的规则生成与模板一致性。

## 快速开始

```bash
python3 -m py_compile scripts/generate_clash_rules.py
python3 scripts/generate_clash_rules.py
```

可选参数示例：

```bash
python3 scripts/generate_clash_rules.py --template-profile boost
python3 scripts/generate_clash_rules.py --strict
```

## 目录结构

```text
.
├── custom_routing_rules          # 唯一输入源
├── scripts/
│   └── generate_clash_rules.py   # 规则生成器
├── clash/                        # 生成产物与接入说明
├── config-references/            # 外部参考样例（不参与运行）
├── docs/                         # 项目结构与维护文档
└── AGENTS.md                     # 协作与提交约束
```

## 输出说明

- `clash/mihomo-custom-rules.yaml`：可并入主配置的规则主片段。
- `clash/template.fake-ip.yaml`：订阅站模板（含占位符）。
- `clash/rules/*.yaml`：按源规则拆分后的 rule-provider 文件。

详细接入说明见：[clash/README.md](clash/README.md)

## 参考文件说明

`config-references/` 仅用于人工比对和吸收思路，不作为运行依赖，不会被生成脚本读取。
