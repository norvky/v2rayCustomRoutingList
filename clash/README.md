# Clash / mihomo 自定义规则迁移说明

## 自动生成命令

```bash
python3 scripts/generate_clash_rules.py
```

建议在提交前统一执行：

```bash
bash scripts/check.sh
```

可选参数示例：

```bash
python3 scripts/generate_clash_rules.py --repo novcky/v2rayCustomRoutingList --branch main --github-id 3379345
```

使用增强模板（保持规则来源仍为 `custom_routing_rules`）：

```bash
python3 scripts/generate_clash_rules.py --template-profile boost
```

启用严格模式（出现 warning 时退出，适合 CI）：

```bash
python3 scripts/generate_clash_rules.py --strict
```

如需只生成规则片段，不生成订阅站模板：

```bash
python3 scripts/generate_clash_rules.py --no-template
```

## 生成结果

- `rules/*.yaml`：按 `custom_routing_rules` 顺序拆分后的 rule-provider 文件。
- `mihomo-custom-rules.yaml`：主片段，包含 `proxy-groups`、`rule-providers` 与 `rules`。
- `template.fake-ip.yaml`：可用于订阅站渲染的模板（含 `__PROXY_PROVIDERS__` / `__PROXY_NODES__` 占位符）。
- `proxy-groups-custom.example.yaml`：可选分组示例（与模板同名组）。
- `geox-url-v2ray-rules-dat.yaml`：可选 GEO 数据源片段。

## 接入建议（Android / PC 通用）

1. 将 `mihomo-custom-rules.yaml` 合并到主配置（内含与模板同名的默认策略组）。
2. 将 `🚀 手动选择` / `♻️ 自动选择` 替换为你的真实代理入口。
3. 如需独立维护策略组，可参考 `proxy-groups-custom.example.yaml`。
4. 如需继续沿用 v2ray 基础库，可合并 `geox-url-v2ray-rules-dat.yaml`。

## 兼容差异

- `protocol:bittorrent` 在 Clash 无等价规则，自动降级为 `GEOSITE,category-pt`。
- 规则可选 `policyGroup` 字段可覆盖默认分组映射；未设置时按 outboundTag 映射。
- `--template-profile boost` 仅增强模板运行参数，不引入外部规则文件依赖。
- fake-ip 基线按“常见本地访问方式可用”设计，不预设外部代理环境为项目前提。
- 模板默认内置面向开发环境的 fake-ip-filter 基线，可在客户端按项目继续增量追加。
- 纯 `0-65535` / `1-65535` 全端口兜底规则会自动转换为 `MATCH`。
- 订阅站模板中，末尾 `MATCH` 默认指向“漏网策略”组，便于在客户端一键切换直连/代理。
- `enabled=false` 条目不会生成 provider 文件与 provider 声明，仅保留注释方便回滚。
- remarks 写“拦截”但 outboundTag 为 `direct` 的条目，会按真实行为映射为 `direct`。
