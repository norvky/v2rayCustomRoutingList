"""文件渲染与输出。"""

from __future__ import annotations

import re
from pathlib import Path

from .constants import (
    FAKE_IP_FILTER_BASELINE,
    LOCAL_DNS_POLICY_BASELINE,
    TEMPLATE_DISABLE_IPV6_DOMAINS_FILE,
    TEMPLATE_LOCAL_DNS_DOMAINS_FILE,
    TEMPLATE_LOCAL_DNS_SERVERS_FILE,
)
from .convert import collect_custom_policy_groups, resolve_policy_group
from .models import ConvertedRule


def write_rule_file(path: Path, rule: ConvertedRule) -> None:
    """写入单条 rule-provider 文件。"""

    lines: list[str] = []
    lines.append(f"# 由 custom_routing_rules 第 {rule.index} 条（{rule.remarks}）自动生成。")
    if rule.notes:
        for note in rule.notes:
            lines.append(f"# {note}")
    lines.append("payload:")
    if rule.payload:
        for item in rule.payload:
            lines.append(f"  - {item}")
    else:
        lines.append("  # 空规则：原始条目无可迁移匹配项。")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_main_file(
    path: Path,
    rules: list[ConvertedRule],
    repo: str,
    branch: str,
    interval: int,
    github_id: str,
) -> None:
    """生成 `mihomo-custom-rules.yaml` 主片段。

    文件目标是“可直接并入主配置”，因此同时输出策略组、provider 声明和规则顺序。
    """

    # 参数保留：当前主片段未使用图标字段，但保持签名一致可减少未来模板合并成本。
    _ = github_id
    proxy_group = "🚀 手动选择"
    auto_group = "♻️ 自动选择"
    direct_group = "🎯 全球直连"
    block_group = "⛔ 强制阻断"
    fallback_group = "🐟 漏网策略"

    builtin_groups = {proxy_group, auto_group, direct_group, block_group, fallback_group}
    custom_policy_groups = collect_custom_policy_groups(rules, builtin_groups)

    lines: list[str] = []
    lines.append("# 包含“自定义规则 + 默认策略组”的主片段，不含节点与订阅配置。")
    lines.append("# 本文件由 scripts/generate_clash_rules.py 自动生成。")
    lines.append("# 说明：")
    lines.append("# 1) 该文件中的分组命名与订阅站模板保持一致。")
    lines.append("# 2) `🚀 手动选择`/`♻️ 自动选择` 默认是可启动兜底，接入时请替换为你的真实代理入口。")
    lines.append("")
    lines.append("proxy-groups:")
    lines.append(f"  - name: {proxy_group}")
    lines.append("    type: select")
    lines.append("    proxies:")
    lines.append(f"      - {auto_group}")
    lines.append(f"      - {direct_group}")
    lines.append(f"  - name: {auto_group}")
    lines.append("    type: select")
    lines.append("    proxies:")
    lines.append(f"      - {direct_group}")
    lines.append(f"  - name: {direct_group}")
    lines.append("    type: select")
    lines.append("    proxies:")
    lines.append("      - DIRECT")
    lines.append(f"  - name: {block_group}")
    lines.append("    type: select")
    lines.append("    proxies:")
    lines.append("      - REJECT")
    lines.append("      - DIRECT")
    for group_name in custom_policy_groups:
        # 扩展分组由 custom_routing_rules 的 policyGroup 声明驱动，避免模板内写死业务分组。
        lines.append(f"  - name: {group_name}")
        lines.append("    type: select")
        lines.append("    proxies:")
        lines.append(f"      - {proxy_group}")
        lines.append(f"      - {auto_group}")
        lines.append(f"      - {direct_group}")
        lines.append(f"      - {block_group}")
    # 社区里更常见的是让 MATCH 默认落到代理；这里把“漏网策略”首项放在代理侧，
    # 同时保留直连入口，便于用户按场景切换。
    lines.append(f"  - name: {fallback_group}")
    lines.append("    type: select")
    lines.append("    proxies:")
    lines.append(f"      - {proxy_group}")
    lines.append(f"      - {auto_group}")
    lines.append(f"      - {direct_group}")
    lines.append("")
    # 先写 provider 声明，便于阅读时先看到“依赖了哪些规则文件”。
    lines.append("rule-providers:")
    for rule in rules:
        if rule.is_match_all or not rule.enabled:
            continue
        lines.append(f"  {rule.provider_name}:")
        lines.append("    type: http")
        lines.append("    behavior: classical")
        lines.append("    format: yaml")
        lines.append(
            f"    url: https://raw.githubusercontent.com/{repo}/{branch}/clash/rules/{rule.file_name}"
        )
        lines.append(f"    path: ./ruleset/custom/{rule.file_name}")
        lines.append(f"    interval: {interval}")
        lines.append("")

    lines.append("rules:")
    has_terminal_match = False
    for rule in rules:
        policy_group = resolve_policy_group(rule, proxy_group, direct_group, block_group)
        lines.append(f"  # {rule.index:02d} {rule.remarks}")
        if rule.is_match_all:
            # MATCH 是终止型规则；只允许保留最后一次启用结果。
            if not rule.enabled:
                lines.append("  # 原规则 enabled=false，默认保持禁用。")
                append_match_all_explanation(lines, fallback_group)
                lines.append(f"  # - MATCH,{fallback_group}")
                continue
            append_match_all_explanation(lines, fallback_group)
            lines.append(f"  - MATCH,{fallback_group}")
            has_terminal_match = True
            continue
        if not rule.enabled:
            # disabled 条目保留为注释，便于回滚时直接取消注释恢复。
            lines.append("  # 原规则 enabled=false，默认保持禁用。")
            lines.append(f"  # - RULE-SET,{rule.provider_name},{policy_group}")
            continue
        lines.append(f"  - RULE-SET,{rule.provider_name},{policy_group}")

    if not has_terminal_match:
        # 防御式兜底：源规则若未包含全端口/全流量兜底，自动补一个 MATCH。
        lines.append(f"  - MATCH,{fallback_group}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_proxy_group_example(path: Path, github_id: str) -> None:
    """生成独立的策略组示例文件。"""

    # 参数保留：示例文件暂未写入 icon 字段，后续如需接入可直接复用调用签名。
    _ = github_id
    # 这里输出的是“最小可启动分组”，便于用户在不同订阅模板之间复用命名。
    lines = [
        "# 可选示例：与订阅站模板同名分组，便于在本地与模板之间保持一致行为。",
        "# 说明：",
        "# 1) 这里的 `🚀 手动选择` / `♻️ 自动选择` 是可启动兜底，请替换为你的真实代理入口。",
        "# 2) `🐟 漏网策略` 作为末尾 MATCH 指向组，可在客户端一键切换直连/代理。",
        "",
        "proxy-groups:",
        "  - name: 🚀 手动选择",
        "    type: select",
        "    proxies:",
        "      - ♻️ 自动选择",
        "      - 🎯 全球直连",
        "",
        "  - name: ♻️ 自动选择",
        "    type: select",
        "    proxies:",
        "      - 🎯 全球直连",
        "",
        "  - name: 🎯 全球直连",
        "    type: select",
        "    proxies:",
        "      - DIRECT",
        "",
        "  - name: ⛔ 强制阻断",
        "    type: select",
        "    proxies:",
        "      - REJECT",
        "      - DIRECT",
        "",
        "  - name: 🐟 漏网策略",
        "    type: select",
        "    proxies:",
        "      - 🎯 全球直连",
        "      - 🚀 手动选择",
        "      - ♻️ 自动选择",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_geox_url_snippet(path: Path) -> None:
    """生成 geox-url 片段，便于继续沿用 v2ray-rules-dat。"""

    lines = [
        "# 可选：继续沿用 v2ray-rules-dat 作为 GEO 基础数据源。",
        "# 若你已在主配置设置 geox-url，则以主配置为准。",
        "",
        "geodata-mode: true",
        "geox-url:",
        "  geoip: https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geoip.dat",
        "  geosite: https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geosite.dat",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_readme(path: Path) -> None:
    """生成 clash 目录下的使用说明文档。"""

    lines = [
        "# Clash / mihomo 自定义规则迁移说明",
        "",
        "## 自动生成命令",
        "",
        "```bash",
        "python3 scripts/generate_clash_rules.py",
        "```",
        "",
        "建议在提交前统一执行：",
        "",
        "```bash",
        "bash scripts/check.sh",
        "```",
        "",
        "可选参数示例：",
        "",
        "```bash",
        "python3 scripts/generate_clash_rules.py --repo novcky/v2rayCustomRoutingList --branch main --github-id 3379345",
        "```",
        "",
        "使用增强模板（保持规则来源仍为 `custom_routing_rules`）：",
        "",
        "```bash",
        "python3 scripts/generate_clash_rules.py --template-profile boost",
        "```",
        "",
        "如需生成兼容旧行为的 fake-ip 模板：",
        "",
        "```bash",
        "python3 scripts/generate_clash_rules.py --template-file template.custom.yaml --template-dns-mode fake-ip",
        "```",
        "",
        "如需尽量避免域名型 DNS 上游，可生成纯 IP 版本：",
        "",
        "```bash",
        "python3 scripts/generate_clash_rules.py --template-file template.pure-ip.yaml --template-dns-upstream pure-ip",
        "```",
        "",
        "启用严格模式（出现 warning 时退出，适合 CI）：",
        "",
        "```bash",
        "python3 scripts/generate_clash_rules.py --strict",
        "```",
        "",
        "如需只生成规则片段，不生成订阅站模板：",
        "",
        "```bash",
        "python3 scripts/generate_clash_rules.py --no-template",
        "```",
        "",
        "## 生成结果",
        "",
        "- `rules/*.yaml`：按 `custom_routing_rules` 顺序拆分后的 rule-provider 文件。",
        "- `mihomo-custom-rules.yaml`：主片段，包含 `proxy-groups`、`rule-providers` 与 `rules`。",
        "- `template.redir-host.yaml`：默认推荐的订阅站模板（含 `__PROXY_PROVIDERS__` / `__PROXY_NODES__` 占位符）。",
        "- `template.fake-ip.yaml`：默认一并保留的兼容模板，便于在客户端按需切换。",
        "- `proxy-groups-custom.example.yaml`：可选分组示例（与模板同名组）。",
        "- `geox-url-v2ray-rules-dat.yaml`：可选 GEO 数据源片段。",
        "",
        "## 接入建议（Android / PC 通用）",
        "",
        "1. 将 `mihomo-custom-rules.yaml` 合并到主配置（内含与模板同名的默认策略组）。",
        "2. 将 `🚀 手动选择` / `♻️ 自动选择` 替换为你的真实代理入口。",
        "3. 如需独立维护策略组，可参考 `proxy-groups-custom.example.yaml`。",
        "4. 如需继续沿用 v2ray 基础库，可合并 `geox-url-v2ray-rules-dat.yaml`。",
        "5. 如需让默认模板识别更多内网 / 开发域名，可在 `clash/template.local-dns-servers.txt` 与 `clash/template.local-dns-domains.txt` 中补充本地 DNS。",
        "6. 如需保留全局 IPv6、但让少数双栈站点仅返回 A 记录，可在 `clash/template.disable-ipv6-domains.txt` 中补充域名模式。",
        "",
        "## 兼容差异",
        "",
        "- `protocol:bittorrent` 在 Clash 无等价规则，自动降级为 `GEOSITE,category-pt`。",
        "- 规则可选 `policyGroup` 字段可覆盖默认分组映射；未设置时按 outboundTag 映射。",
        "- `--template-profile boost` 仅增强模板运行参数，不引入外部规则文件依赖。",
        "- 默认模板使用 `redir-host`，降低开发机场景下的真实地址联调成本。",
        "- 默认同时生成 redir-host / fake-ip 两份标准模板，避免仓库在常规重生成时出现无意义的增删漂移。",
        "- `fake-ip` 模式会恢复旧版 `fake-ip-filter` 基线；如需单独导出，可配合 `--template-file` 与 `--template-dns-mode` 使用。",
        "- `redir-host` 模式默认内置 `sniffer` 基线，减少真实 IP 连接下的分流误判。",
        "- 默认模板会把常见内网 / 开发域名模式定向到 `direct-nameserver`，降低多端联调时被公网 DNS 抢答的概率。",
        "- 如需解析自定义内网域名，可在 `clash/template.local-dns-servers.txt` / `clash/template.local-dns-domains.txt` 中补充本地 DNS。",
        "- 如需保留全局 IPv6、但让少数站点禁用 AAAA，可在 `clash/template.disable-ipv6-domains.txt` 中补充域名模式；生成器会把这些域名定向到附带 `disable-ipv6=true` 的公网 DNS。",
        "- DNS 默认按“显式直连少数规则 + MATCH 默认代理”建模：`nameserver` 走可信公网解析，`geosite:cn/private` 走 `direct-nameserver`。",
        "- `ping` / `ICMP` 不属于 `sniffer` 覆盖范围；验证 `redir-host` 是否生效时，应优先使用浏览器、`curl` 或脚本里的 HTTP/TLS/QUIC 请求。",
        "- 如需尽量避免域名型 DNS 上游，可配合 `--template-dns-upstream pure-ip` 生成纯 IP 模板。",
        "- 纯 `0-65535` / `1-65535` 全端口兜底规则会自动转换为 `MATCH`。",
        "- 订阅站模板中，末尾 `MATCH` 固定指向“漏网策略”组，且该组默认首选代理，便于按需切换直连/代理。",
        "- `enabled=false` 条目不会生成 provider 文件与 provider 声明，仅保留注释方便回滚。",
        "- remarks 写“拦截”但 outboundTag 为 `direct` 的条目，会按真实行为映射为 `direct`。",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def merge_unique_items(*groups: list[str]) -> list[str]:
    """按出现顺序合并列表并去重。"""

    merged: list[str] = []
    seen: set[str] = set()
    for group in groups:
        for item in group:
            if item in seen:
                continue
            seen.add(item)
            merged.append(item)
    return merged


def append_nameserver_policy_entry(lines: list[str], key: str, servers: list[str]) -> None:
    """写入单条 nameserver-policy。"""

    lines.append(f'    "{key}":')
    for item in servers:
        lines.append(f"      - {item}")


def append_dns_server_bool_param(server: str, key: str, enabled: bool) -> str:
    """为 DNS 上游补充 mihomo 布尔附加参数。"""

    separator = "&" if "#" in server else "#"
    value = "true" if enabled else "false"
    return f"{server}{separator}{key}={value}"



def append_match_all_explanation(lines: list[str], fallback_group: str) -> None:
    """为全量兜底规则补充语义说明。"""

    # 源规则里的“全端口直连/代理”在 Clash 中都会折叠成 MATCH；
    # 这里显式提示最终落点，避免用户只看 remarks 误以为仍是单纯直连。
    lines.append(f"  # 全端口/全流量兜底规则已折叠为 MATCH,{fallback_group}；该组默认首选代理，可在客户端切回直连。")

def resolve_template_dns_servers(
    template_dns_upstream: str,
    template_local_dns_servers: list[str],
) -> tuple[list[str], list[str], list[str], list[str]]:
    """返回模板使用的 DNS 上游集合。"""

    # 直连规则主要承接 `cn/private` 这类明确本地流量，因此继续使用本地可达的 IP 上游，
    # 避免把 LAN/内网访问强行送去默认代理侧的公网解析。
    default_nameserver = ["223.5.5.5", "119.29.29.29"]
    # 用户补充的局域网 DNS 需要排在前面，才能真正接住 home.arpa / 公司内网域名这类“只在本地可解析”的请求。
    direct_nameserver = merge_unique_items(template_local_dns_servers, ["223.5.5.5", "119.29.29.29"])
    # 代理节点域名需要尽量避开本地污染链路，因此默认固定到公共 IP DNS。
    proxy_server_nameserver = ["1.1.1.1", "8.8.8.8"]
    if template_dns_upstream == "pure-ip":
        nameserver = ["1.1.1.1", "8.8.8.8"]
    else:
        # 仅在 compat 档保留域名型 DoH；这里依赖 TLS 域名身份，比直接写成 IP 形式的 DoH 更稳妥。
        nameserver = ["https://dns.cloudflare.com/dns-query", "https://dns.google/dns-query"]
    return nameserver, default_nameserver, direct_nameserver, proxy_server_nameserver


def append_template_dns(
    lines: list[str],
    template_profile: str,
    template_dns_mode: str,
    template_dns_upstream: str,
    template_local_dns_servers: list[str],
    template_local_dns_domains: list[str],
    template_disable_ipv6_domains: list[str],
) -> None:
    """写入订阅模板 DNS 段。

    当前模板以“显式直连少数规则 + MATCH 默认代理”为基线：默认 nameserver 走可信公网解析，
    仅在命中 `cn/private` 这类明确直连规则时回落到 direct-nameserver。
    """

    _ = template_profile
    nameserver, default_nameserver, direct_nameserver, proxy_server_nameserver = resolve_template_dns_servers(
        template_dns_upstream,
        template_local_dns_servers,
    )
    local_dns_policy_domains = merge_unique_items(LOCAL_DNS_POLICY_BASELINE, template_local_dns_domains)
    disable_ipv6_policy_domains = [
        item
        for item in template_disable_ipv6_domains
        if item not in local_dns_policy_domains and item != "geosite:cn,private"
    ]
    # 少数风控敏感站点只需要“禁 AAAA”，不应因此把整套模板切回 IPv4-only；
    # 这里继续沿用默认公网 nameserver，只在命中这些域名时附加 disable-ipv6=true。
    ipv4_only_nameserver = [append_dns_server_bool_param(item, "disable-ipv6", True) for item in nameserver]

    lines.append("dns:")
    lines.append("  enable: true")
    lines.append("  ipv6: true")
    lines.append("  respect-rules: true")
    lines.append(f"  enhanced-mode: {template_dns_mode}")
    lines.append("  nameserver:")
    for item in nameserver:
        lines.append(f"    - {item}")
    lines.append("  proxy-server-nameserver:")
    for item in proxy_server_nameserver:
        lines.append(f"    - {item}")
    lines.append("  direct-nameserver:")
    for item in direct_nameserver:
        lines.append(f"    - {item}")
    lines.append("  direct-nameserver-follow-policy: true")
    lines.append("  nameserver-policy:")
    lines.append("    geosite:cn,private:")
    for item in direct_nameserver:
        lines.append(f"      - {item}")
    # 常见内网/开发域名应优先落到 direct-nameserver：
    # 1) 让 redir-host 在本地联调时先走“本地 DNS + 直连”路径，而不是默认公网解析；
    # 2) 当用户补充 template.local-dns-servers.txt 时，同一份模板即可无缝吸收这些本地域名。
    for item in local_dns_policy_domains:
        append_nameserver_policy_entry(lines, item, direct_nameserver)
    for item in disable_ipv6_policy_domains:
        append_nameserver_policy_entry(lines, item, ipv4_only_nameserver)
    # default-nameserver 只负责解析域名型 DNS 上游本身；保持 IP 形式可避免启动期出现循环依赖。
    lines.append("  default-nameserver:")
    for item in default_nameserver:
        lines.append(f"    - {item}")

    if template_dns_mode == "fake-ip":
        # 仅在 fake-ip 模式输出过滤基线，避免 redir-host 模式携带无效配置造成理解偏差。
        lines.append("  fake-ip-filter:")
        for item in FAKE_IP_FILTER_BASELINE:
            # 使用双引号输出，避免通配符被 YAML 解析为 alias 语义。
            lines.append(f'    - "{item}"')

    if template_profile != "boost":
        return

    lines.append("  listen: 127.0.0.1:5335")
    lines.append("  use-system-hosts: false")
    if template_dns_mode == "fake-ip":
        # fake-ip-range 仅对 fake-ip 生效；保留在 boost 档位可与旧模板行为保持一致。
        lines.append("  fake-ip-range: 198.18.0.1/16")


def append_template_sniffer(lines: list[str], include_force_dns_mapping: bool) -> None:
    """写入订阅模板 sniffer 段。"""

    lines.append("sniffer:")
    lines.append("  enable: true")
    if include_force_dns_mapping:
        lines.append("  force-dns-mapping: true")
    lines.append("  parse-pure-ip: true")
    lines.append("  sniff:")
    lines.append("    TLS: {ports: [443, 8443]}")
    lines.append("    HTTP: {ports: [80, 8080-8880], override-destination: true}")
    lines.append("    QUIC: {ports: [443, 8443]}")


def append_template_runtime(
    lines: list[str],
    template_profile: str,
    template_dns_mode: str,
) -> None:
    """写入订阅模板运行时增强配置。"""

    if template_dns_mode == "redir-host":
        # redir-host 依赖域名映射与嗅探结果协同工作；这里即使在 compat 档位也保留最小 sniffer 基线，
        # 以避免用户切到真实 IP 直连场景后，规则侧因为缺失 SNI/Host 信息而退化成仅按目标 IP 决策。
        append_template_sniffer(lines, include_force_dns_mapping=True)
    elif template_profile == "boost":
        # fake-ip 保持旧 boost 行为：仅在增强档位打开 sniff，不改变 compat 档位的历史表现。
        append_template_sniffer(lines, include_force_dns_mapping=False)

    if template_profile != "boost":
        return

    lines.append("geodata-mode: true")
    lines.append("geo-auto-update: true")
    lines.append("geo-update-interval: 24")


def write_subscription_template(
    path: Path,
    rules: list[ConvertedRule],
    repo: str,
    branch: str,
    interval: int,
    github_id: str,
    template_profile: str,
    template_dns_mode: str,
    template_dns_upstream: str,
    template_local_dns_servers: list[str],
    template_local_dns_domains: list[str],
    template_disable_ipv6_domains: list[str],
) -> None:
    """生成订阅站模板。

    模板与主片段共享同一套规则语义，但包含订阅站占位符与更完整的 DNS 基础段。
    """

    # 参数保留：模板当前不直接拼 icon URL，保留签名便于后续无破坏扩展。
    _ = github_id
    # 模板默认使用固定分组名，确保订阅站渲染前后命名稳定，不影响规则引用。
    proxy_group = "🚀 手动选择"
    auto_group = "♻️ 自动选择"
    direct_group = "🎯 全球直连"
    block_group = "⛔ 强制阻断"
    fallback_group = "🐟 漏网策略"
    builtin_groups = {proxy_group, auto_group, direct_group, block_group, fallback_group}
    custom_policy_groups = collect_custom_policy_groups(rules, builtin_groups)

    lines: list[str] = []
    lines.append("# 订阅站模板：由 scripts/generate_clash_rules.py 自动生成。")
    lines.append("# 说明：")
    lines.append("# 1) `__PROXY_PROVIDERS__` 与 `__PROXY_NODES__` 由订阅站在渲染阶段替换。")
    lines.append("# 2) 自定义规则顺序来自 custom_routing_rules，并按原 enabled 状态输出。")
    lines.append("# 3) 末尾 MATCH 固定使用“漏网策略”组；该组默认首选代理，仍可在客户端切换直连/代理。")
    lines.append(f"# 4) 当前模板档位：{template_profile}。")
    lines.append(f"# 5) 当前 DNS 模式：{template_dns_mode}。")
    lines.append(f"# 6) 当前 DNS 上游：{template_dns_upstream}。")
    lines.append(
        f"# 7) 如需补充内网 / 开发域名解析，可在同目录维护 {TEMPLATE_LOCAL_DNS_SERVERS_FILE} / {TEMPLATE_LOCAL_DNS_DOMAINS_FILE}。"
    )
    lines.append(
        f"# 8) 如需保留全局 IPv6、但让少数站点强制仅返回 A 记录，可在同目录维护 {TEMPLATE_DISABLE_IPV6_DOMAINS_FILE}。"
    )
    lines.append("")
    lines.append("mixed-port: 7897")
    lines.append("allow-lan: true")
    lines.append("mode: rule")
    lines.append("log-level: info")
    lines.append("unified-delay: true")
    lines.append("tcp-concurrent: true")
    lines.append("find-process-mode: strict")
    lines.append("global-client-fingerprint: chrome")
    append_template_runtime(lines, template_profile, template_dns_mode)
    lines.append("external-controller: 127.0.0.1:9090")
    append_template_dns(
        lines,
        template_profile,
        template_dns_mode,
        template_dns_upstream,
        template_local_dns_servers,
        template_local_dns_domains,
        template_disable_ipv6_domains,
    )
    lines.append("proxies: null")
    lines.append("proxy-groups:")
    lines.append(f"  - name: {proxy_group}")
    lines.append("    type: select")
    lines.append("    include-all: true")
    lines.append("    include-all-proxies: true")
    lines.append("    include-all-providers: true")
    lines.append("    proxies:")
    lines.append(f"      - {auto_group}")
    lines.append("      - __PROXY_PROVIDERS__")
    lines.append("      - __PROXY_NODES__")
    lines.append(f"  - name: {auto_group}")
    lines.append("    type: url-test")
    lines.append("    include-all: true")
    lines.append("    include-all-proxies: true")
    lines.append("    include-all-providers: true")
    lines.append("    proxies:")
    lines.append("      - __PROXY_PROVIDERS__")
    lines.append("      - __PROXY_NODES__")
    lines.append("    url: https://cp.cloudflare.com/generate_204")
    lines.append("    interval: 300")
    lines.append("    tolerance: 50")
    lines.append(f"  - name: {direct_group}")
    lines.append("    type: select")
    lines.append("    proxies:")
    lines.append("      - DIRECT")
    lines.append(f"  - name: {block_group}")
    lines.append("    type: select")
    lines.append("    proxies:")
    lines.append("      - REJECT")
    lines.append("      - DIRECT")
    for group_name in custom_policy_groups:
        # 扩展分组由 custom_routing_rules 的 policyGroup 声明驱动，避免模板内写死业务分组。
        lines.append(f"  - name: {group_name}")
        lines.append("    type: select")
        lines.append("    include-all: true")
        lines.append("    include-all-proxies: true")
        lines.append("    include-all-providers: true")
        lines.append("    proxies:")
        lines.append(f"      - {proxy_group}")
        lines.append(f"      - {auto_group}")
        lines.append(f"      - {direct_group}")
        lines.append(f"      - {block_group}")
        lines.append("      - __PROXY_PROVIDERS__")
        lines.append("      - __PROXY_NODES__")
    # 订阅站模板同样保持 MATCH 默认代理，避免用户导入节点后因为首项是直连而产生预期偏差。
    lines.append(f"  - name: {fallback_group}")
    lines.append("    type: select")
    lines.append("    include-all: true")
    lines.append("    include-all-proxies: true")
    lines.append("    include-all-providers: true")
    lines.append("    proxies:")
    lines.append(f"      - {proxy_group}")
    lines.append(f"      - {auto_group}")
    lines.append(f"      - {direct_group}")
    lines.append("      - __PROXY_PROVIDERS__")
    lines.append("      - __PROXY_NODES__")
    lines.append("rules:")
    has_terminal_match = False
    for rule in rules:
        policy_group = resolve_policy_group(rule, proxy_group, direct_group, block_group)
        lines.append(f"  # {rule.index:02d} {rule.remarks}")
        if rule.is_match_all:
            if not rule.enabled:
                lines.append("  # 原规则 enabled=false，默认保持禁用。")
                append_match_all_explanation(lines, fallback_group)
                lines.append(f"  # - MATCH,{fallback_group}")
                continue
            append_match_all_explanation(lines, fallback_group)
            lines.append(f"  - MATCH,{fallback_group}")
            has_terminal_match = True
            continue
        if not rule.enabled:
            lines.append("  # 原规则 enabled=false，默认保持禁用。")
            lines.append(f"  # - RULE-SET,{rule.provider_name},{policy_group}")
            continue
        lines.append(f"  - RULE-SET,{rule.provider_name},{policy_group}")
    if not has_terminal_match:
        lines.append(f"  - MATCH,{fallback_group}")
    # 模板中的 provider 路径使用 `./providers/custom/`，与常见订阅站目录结构兼容。
    lines.append("rule-providers:")
    for rule in rules:
        if rule.is_match_all or not rule.enabled:
            continue
        lines.append(f"  {rule.provider_name}:")
        lines.append("    type: http")
        lines.append("    behavior: classical")
        lines.append("    format: yaml")
        lines.append(
            f"    url: https://raw.githubusercontent.com/{repo}/{branch}/clash/rules/{rule.file_name}"
        )
        lines.append(f"    path: ./providers/custom/{rule.file_name}")
        lines.append(f"    interval: {interval}")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def cleanup_generated_rule_files(rules_dir: Path) -> None:
    """清理旧的自动生成 rule 文件。

    仅删除符合“序号-名称”格式的文件，避免误删用户手工维护的自定义规则文件。
    """

    # 仅清理“序号前缀”的生成产物，避免误删用户手工维护的其它文件。
    pattern = re.compile(r"^\d{2}-.+\.ya?ml$")
    for file_path in rules_dir.glob("*.y*ml"):
        if pattern.match(file_path.name):
            try:
                file_path.unlink()
            except FileNotFoundError:
                # 并发生成时文件可能已被另一进程删掉，这里按“已清理”处理即可。
                continue
