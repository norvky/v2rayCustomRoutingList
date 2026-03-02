"""文件渲染与输出。"""

from __future__ import annotations

import re
from pathlib import Path

from .constants import FAKE_IP_FILTER_BASELINE
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
    lines.append(f"  - name: {fallback_group}")
    lines.append("    type: select")
    lines.append("    proxies:")
    lines.append(f"      - {direct_group}")
    lines.append(f"      - {proxy_group}")
    lines.append(f"      - {auto_group}")
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
                lines.append(f"  # - MATCH,{fallback_group}")
                continue
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
        "- `template.fake-ip.yaml`：可用于订阅站渲染的模板（含 `__PROXY_PROVIDERS__` / `__PROXY_NODES__` 占位符）。",
        "- `proxy-groups-custom.example.yaml`：可选分组示例（与模板同名组）。",
        "- `geox-url-v2ray-rules-dat.yaml`：可选 GEO 数据源片段。",
        "",
        "## 接入建议（Android / PC 通用）",
        "",
        "1. 将 `mihomo-custom-rules.yaml` 合并到主配置（内含与模板同名的默认策略组）。",
        "2. 将 `🚀 手动选择` / `♻️ 自动选择` 替换为你的真实代理入口。",
        "3. 如需独立维护策略组，可参考 `proxy-groups-custom.example.yaml`。",
        "4. 如需继续沿用 v2ray 基础库，可合并 `geox-url-v2ray-rules-dat.yaml`。",
        "",
        "## 兼容差异",
        "",
        "- `protocol:bittorrent` 在 Clash 无等价规则，自动降级为 `GEOSITE,category-pt`。",
        "- 规则可选 `policyGroup` 字段可覆盖默认分组映射；未设置时按 outboundTag 映射。",
        "- `--template-profile boost` 仅增强模板运行参数，不引入外部规则文件依赖。",
        "- fake-ip 基线按“常见本地访问方式可用”设计，不预设外部代理环境为项目前提。",
        "- 模板默认内置面向开发环境的 fake-ip-filter 基线，可在客户端按项目继续增量追加。",
        "- 纯 `0-65535` / `1-65535` 全端口兜底规则会自动转换为 `MATCH`。",
        "- 订阅站模板中，末尾 `MATCH` 默认指向“漏网策略”组，便于在客户端一键切换直连/代理。",
        "- `enabled=false` 条目不会生成 provider 文件与 provider 声明，仅保留注释方便回滚。",
        "- remarks 写“拦截”但 outboundTag 为 `direct` 的条目，会按真实行为映射为 `direct`。",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def append_template_dns(lines: list[str], template_profile: str) -> None:
    """写入订阅模板 DNS 段。

    `boost` 在兼容基线上追加增强项，避免因为默认强开新特性导致旧内核加载失败。
    """

    lines.append("dns:")
    lines.append("  enable: true")
    lines.append("  ipv6: true")
    lines.append("  respect-rules: true")
    lines.append("  enhanced-mode: fake-ip")
    lines.append("  nameserver:")
    lines.append("    - https://120.53.53.53/dns-query")
    lines.append("    - https://223.5.5.5/dns-query")
    lines.append("  proxy-server-nameserver:")
    lines.append("    - https://120.53.53.53/dns-query")
    lines.append("    - https://223.5.5.5/dns-query")
    lines.append("  nameserver-policy:")
    lines.append("    geosite:cn,private:")
    lines.append("      - https://120.53.53.53/dns-query")
    lines.append("      - https://223.5.5.5/dns-query")
    lines.append("    geosite:geolocation-!cn:")
    lines.append("      - https://dns.cloudflare.com/dns-query")
    lines.append("      - https://dns.google/dns-query")
    lines.append("  fake-ip-filter:")
    for item in FAKE_IP_FILTER_BASELINE:
        # 使用双引号输出，避免通配符被 YAML 解析为 alias 语义。
        lines.append(f'    - "{item}"')

    if template_profile != "boost":
        return

    lines.append("  listen: 127.0.0.1:5335")
    lines.append("  use-system-hosts: false")
    lines.append("  fake-ip-range: 198.18.0.1/16")
    lines.append("  default-nameserver:")
    lines.append("    - 223.5.5.5")
    lines.append("    - 119.29.29.29")
    lines.append("    - 1.1.1.1")
    lines.append("    - 8.8.8.8")
    lines.append("  fallback:")
    lines.append("    - https://dns.google/dns-query")
    lines.append("    - https://cloudflare-dns.com/dns-query")
    lines.append("  fallback-filter:")
    lines.append("    geoip: true")
    lines.append("    ipcidr:")
    lines.append("      - 240.0.0.0/4")
    lines.append("      - 0.0.0.0/32")
    lines.append("      - 127.0.0.1/32")
    lines.append("    domain:")
    lines.append("      - +.google.com")
    lines.append("      - +.googleapis.com")
    lines.append("      - +.gvt1.com")
    lines.append("      - +.youtube.com")


def append_template_runtime(lines: list[str], template_profile: str) -> None:
    """写入订阅模板运行时增强配置。"""

    if template_profile != "boost":
        return

    lines.append("unified-delay: true")
    lines.append("tcp-concurrent: true")
    lines.append("find-process-mode: strict")
    lines.append("sniffer:")
    lines.append("  enable: true")
    lines.append("  parse-pure-ip: true")
    lines.append("  sniff:")
    lines.append("    TLS: {ports: [443, 8443]}")
    lines.append("    HTTP: {ports: [80, 8080-8880], override-destination: true}")
    lines.append("    QUIC: {ports: [443, 8443]}")
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
) -> None:
    """生成订阅站 fake-ip 模板。

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
    lines.append("# 3) 末尾 MATCH 固定使用“漏网策略”组，方便在客户端一键切换直连/代理。")
    lines.append(f"# 4) 当前模板档位：{template_profile}。")
    lines.append("")
    lines.append("port: 7890")
    lines.append("socks-port: 7891")
    lines.append("allow-lan: true")
    lines.append("mode: rule")
    lines.append("log-level: info")
    append_template_runtime(lines, template_profile)
    lines.append("external-controller: 127.0.0.1:9090")
    append_template_dns(lines, template_profile)
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
    lines.append(f"  - name: {fallback_group}")
    lines.append("    type: select")
    lines.append("    include-all: true")
    lines.append("    include-all-proxies: true")
    lines.append("    include-all-providers: true")
    lines.append("    proxies:")
    lines.append(f"      - {direct_group}")
    lines.append(f"      - {proxy_group}")
    lines.append(f"      - {auto_group}")
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
                lines.append(f"  # - MATCH,{fallback_group}")
                continue
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
