# v2rayCustomRoutingList

基于 `custom_routing_rules` 生成 Clash/mihomo 规则产物的仓库。

## 项目定位

- 唯一规则源：`custom_routing_rules`
- 生成入口：`scripts/generate_clash_rules.py`
- 发布产物：`clash/` 下的模板、主片段与 `rules/*.yaml`

## 固定原则

- 默认模板使用 `redir-host`，且“漏网策略”默认首选代理；如需兼容旧行为，可通过参数生成 `fake-ip` 模板。
- DNS 上游默认使用 `compat` 形态；如需尽量避免域名型上游，可通过 `--template-dns-upstream pure-ip` 生成纯 IP 模板。
- 正常环境默认：不把外部异常场景（例如默认有代理环境）写成项目默认前提。
- 职责边界清晰：仓库只保证可控范围内的规则生成与模板一致性。

## 快速开始

```bash
python3 -m py_compile scripts/generate_clash_rules.py
python3 scripts/generate_clash_rules.py
bash scripts/check.sh
```

可选参数示例：

```bash
python3 scripts/generate_clash_rules.py --template-profile boost
python3 scripts/generate_clash_rules.py --template-file template.custom.yaml --template-dns-mode fake-ip
python3 scripts/generate_clash_rules.py --template-file template.pure-ip.yaml --template-dns-upstream pure-ip
python3 scripts/generate_clash_rules.py --strict
```

## 目录结构

```text
.
├── custom_routing_rules          # 唯一输入源
├── scripts/
│   ├── generate_clash_rules.py   # 规则生成入口（兼容旧命令）
│   ├── rulegen/                  # 生成器核心模块
│   └── check.sh                  # 一键检查脚本
├── clash/                        # 生成产物与接入说明
├── config-references/            # 外部参考样例（不参与运行）
├── docs/                         # 项目结构与维护文档
├── tests/                        # 回归测试
├── .github/workflows/            # CI 工作流
└── AGENTS.md                     # 协作与提交约束
```

## 输出说明

- `clash/mihomo-custom-rules.yaml`：可并入主配置的规则主片段。
- `clash/template.redir-host.yaml`：默认推荐的订阅站模板（含占位符）。
- `clash/template.fake-ip.yaml`：默认一并保留的兼容模板。
- `clash/rules/*.yaml`：按源规则拆分后的 rule-provider 文件。

详细接入说明见：[clash/README.md](clash/README.md)
维护与发布流程见：[docs/maintenance.md](docs/maintenance.md)
故障样本模板见：[docs/incident-template.md](docs/incident-template.md)

## 参考文件说明

`config-references/` 仅用于人工比对和吸收思路，不作为运行依赖，不会被生成脚本读取。
