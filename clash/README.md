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

如需生成兼容旧行为的 fake-ip 模板：

```bash
python3 scripts/generate_clash_rules.py --template-file template.custom.yaml --template-dns-mode fake-ip
```

如需尽量避免域名型 DNS 上游，可生成纯 IP 版本：

```bash
python3 scripts/generate_clash_rules.py --template-file template.pure-ip.yaml --template-dns-upstream pure-ip
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
- `template.redir-host.yaml`：默认推荐的订阅站模板（含 `__PROXY_PROVIDERS__` / `__PROXY_NODES__` 占位符）。
- `template.fake-ip.yaml`：默认一并保留的兼容模板，便于在客户端按需切换。
- `proxy-groups-custom.example.yaml`：可选分组示例（与模板同名组）。
- `geox-url-v2ray-rules-dat.yaml`：可选 GEO 数据源片段。

## 接入建议（Android / PC 通用）

1. 将 `mihomo-custom-rules.yaml` 合并到主配置（内含与模板同名的默认策略组）。
2. 将 `🚀 手动选择` / `♻️ 自动选择` 替换为你的真实代理入口。
3. 如需独立维护策略组，可参考 `proxy-groups-custom.example.yaml`。
4. 如需继续沿用 v2ray 基础库，可合并 `geox-url-v2ray-rules-dat.yaml`。
5. 如需让默认模板识别更多内网 / 开发域名，可在 `clash/template.local-dns-servers.txt` 与 `clash/template.local-dns-domains.txt` 中补充本地 DNS。
6. 如需保留全局 IPv6、但让少数双栈站点仅返回 A 记录，可在 `clash/template.disable-ipv6-domains.txt` 中补充域名模式。

## 兼容差异

- `protocol:bittorrent` 在 Clash 无等价规则，自动降级为 `GEOSITE,category-pt`。
- 规则可选 `policyGroup` 字段可覆盖默认分组映射；未设置时按 outboundTag 映射。
- `--template-profile boost` 仅增强模板运行参数，不引入外部规则文件依赖。
- 默认模板使用 `redir-host`，降低开发机场景下的真实地址联调成本。
- 默认同时生成 redir-host / fake-ip 两份标准模板，避免仓库在常规重生成时出现无意义的增删漂移。
- `fake-ip` 模式会恢复旧版 `fake-ip-filter` 基线；如需单独导出，可配合 `--template-file` 与 `--template-dns-mode` 使用。
- `redir-host` 模式默认内置 `sniffer` 基线，减少真实 IP 连接下的分流误判。
- 默认模板会把常见内网 / 开发域名模式定向到 `direct-nameserver`，降低多端联调时被公网 DNS 抢答的概率。
- 如需解析自定义内网域名，可在 `clash/template.local-dns-servers.txt` / `clash/template.local-dns-domains.txt` 中补充本地 DNS。
- 如需保留全局 IPv6、但让少数站点禁用 AAAA，可在 `clash/template.disable-ipv6-domains.txt` 中补充域名模式；生成器会把这些域名定向到附带 `disable-ipv6=true` 的公网 DNS。
- DNS 默认按“显式直连少数规则 + MATCH 默认代理”建模：`nameserver` 走可信公网解析，`geosite:cn/private` 走 `direct-nameserver`。
- `ping` / `ICMP` 不属于 `sniffer` 覆盖范围；验证 `redir-host` 是否生效时，应优先使用浏览器、`curl` 或脚本里的 HTTP/TLS/QUIC 请求。
- 如需尽量避免域名型 DNS 上游，可配合 `--template-dns-upstream pure-ip` 生成纯 IP 模板。
- 纯 `0-65535` / `1-65535` 全端口兜底规则会自动转换为 `MATCH`。
- 订阅站模板中，末尾 `MATCH` 固定指向“漏网策略”组，且该组默认首选代理，便于按需切换直连/代理。
- `enabled=false` 条目不会生成 provider 文件与 provider 声明，仅保留注释方便回滚。
- remarks 写“拦截”但 outboundTag 为 `direct` 的条目，会按真实行为映射为 `direct`。
