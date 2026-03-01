#!/usr/bin/env python3
"""将 custom_routing_rules 自动转换为 Clash/mihomo 规则文件。"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

REMARK_TOKEN_MAP = {
    "crack": "crack",
    "bt": "bt",
    "ip": "ip",
    "steam": "steam",
    "域名": "domain",
    "类别": "category",
    "直连": "direct",
    "代理": "proxy",
    "拦截": "block",
    "广告": "ads",
    "端口": "port",
    "全部": "all",
}

POLICY_MAP = {
    "direct": "direct",
    "proxy": "proxy",
    "block": "block",
}

# v2ray protocol 到 Clash 的兼容映射。
# 这里属于“语义近似”而非“语义等价”，因此会在输出里显式标注风险。
PROTOCOL_FALLBACK_MAP = {
    "bittorrent": "GEOSITE,category-pt",
}


@dataclass
class ConvertedRule:
    index: int
    remarks: str
    enabled: bool
    outbound: str
    provider_name: str
    file_name: str
    payload: list[str]
    is_match_all: bool = False
    notes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="生成 Clash/mihomo 自定义规则文件")
    parser.add_argument(
        "--input",
        default="custom_routing_rules",
        help="v2ray 规则文件路径（默认：custom_routing_rules）",
    )
    parser.add_argument(
        "--output-dir",
        default="clash",
        help="输出目录（默认：clash）",
    )
    parser.add_argument(
        "--repo",
        default="",
        help="GitHub 仓库 owner/repo；为空时尝试从 git remote 自动推断",
    )
    parser.add_argument(
        "--branch",
        default="main",
        help="Raw URL 使用的分支名（默认：main）",
    )
    parser.add_argument(
        "--github-id",
        default="3379345",
        help="用于 proxy-group icon 的 GitHub 用户 ID（默认：3379345）",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=86400,
        help="rule-providers 刷新周期秒数（默认：86400）",
    )
    parser.add_argument(
        "--template-file",
        default="template.fake-ip.yaml",
        help="订阅站模板输出文件名（默认：template.fake-ip.yaml）",
    )
    parser.add_argument(
        "--no-template",
        action="store_true",
        help="不生成订阅站模板文件",
    )
    return parser.parse_args()


def infer_repo_slug(project_root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(project_root), "config", "--get", "remote.origin.url"],
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return ""

    if result.returncode != 0:
        return ""

    return parse_repo_slug_from_url(result.stdout.strip())


def parse_repo_slug_from_url(url: str) -> str:
    # 支持：
    # - https://github.com/owner/repo.git
    # - git@github.com:owner/repo.git
    # - https://github.com/owner/repo
    patterns = [
        r"^https://github\.com/([^/]+/[^/.]+?)(?:\.git)?$",
        r"^git@github\.com:([^/]+/[^/.]+?)(?:\.git)?$",
        r"^ssh://git@github\.com/([^/]+/[^/.]+?)(?:\.git)?$",
    ]
    for pattern in patterns:
        match = re.match(pattern, url)
        if match:
            return match.group(1)
    return ""


def load_source_rules(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as fp:
        data = json.load(fp)
    if not isinstance(data, list):
        raise ValueError("源规则文件不是 JSON 数组")
    return data


def to_slug(remarks: str, used: set[str]) -> str:
    parts: list[str] = []
    for token in re.split(r"[_\s]+", remarks.strip()):
        if not token:
            continue
        mapped = REMARK_TOKEN_MAP.get(token.lower())
        if mapped:
            parts.append(mapped)
            continue
        ascii_part = re.sub(r"[^A-Za-z0-9]+", "-", token).strip("-").lower()
        if ascii_part:
            parts.extend([item for item in ascii_part.split("-") if item])

    slug = "-".join(parts) if parts else "rule"
    if slug not in used:
        used.add(slug)
        return slug

    seq = 2
    while True:
        candidate = f"{slug}-{seq}"
        if candidate not in used:
            used.add(candidate)
            return candidate
        seq += 1


def convert_domain(item: str, warnings: list[str]) -> str:
    if item.startswith("domain:"):
        return f"DOMAIN-SUFFIX,{item[7:]}"
    if item.startswith("full:"):
        return f"DOMAIN,{item[5:]}"
    if item.startswith("keyword:"):
        return f"DOMAIN-KEYWORD,{item[8:]}"
    if item.startswith("regexp:"):
        return f"DOMAIN-REGEX,{item[7:]}"
    if item.startswith("geosite:"):
        return f"GEOSITE,{item[8:]}"
    if item.startswith("ext:"):
        warnings.append(f"不支持的 domain 扩展格式：{item}")
        return ""
    return f"DOMAIN,{item}"


def convert_ip(item: str, warnings: list[str]) -> str:
    if item.startswith("geoip:"):
        return f"GEOIP,{item[6:]},no-resolve"

    value = item.strip()
    if not value:
        return ""

    try:
        if "/" in value:
            network = ipaddress.ip_network(value, strict=False)
            if network.version == 6:
                return f"IP-CIDR6,{network.with_prefixlen},no-resolve"
            return f"IP-CIDR,{network.with_prefixlen},no-resolve"

        address = ipaddress.ip_address(value)
        if address.version == 6:
            return f"IP-CIDR6,{address.compressed}/128,no-resolve"
        return f"IP-CIDR,{address.compressed}/32,no-resolve"
    except ValueError:
        warnings.append(f"无法解析 IP，已按原值降级输出：{item}")
        return f"IP-CIDR,{value},no-resolve"


def convert_protocol(item: str, notes: list[str], warnings: list[str]) -> str:
    key = item.strip().lower()
    if not key:
        return ""
    if key in PROTOCOL_FALLBACK_MAP:
        # 显式记录降级原因，防止后续维护误认为 1:1 等价。
        notes.append(
            f"v2ray protocol `{item}` 在 Clash 无等价字段，使用 `{PROTOCOL_FALLBACK_MAP[key]}` 近似映射。"
        )
        return PROTOCOL_FALLBACK_MAP[key]

    warnings.append(f"不支持的 protocol：{item}")
    return ""


def dedupe_keep_order(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if not item or item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def is_full_port_range(port_expr: str) -> bool:
    compact = port_expr.replace(" ", "")
    return compact in {"0-65535", "1-65535"}


def convert_rule(index: int, source: dict, used_slugs: set[str]) -> ConvertedRule:
    remarks = str(source.get("remarks", f"rule-{index}"))
    enabled = bool(source.get("enabled", True))
    outbound = str(source.get("outboundTag", "direct")).strip() or "direct"
    notes: list[str] = []
    warnings: list[str] = []
    payload_items: list[str] = []
    is_match_all = False

    for domain_item in source.get("domain", []) or []:
        payload_items.append(convert_domain(str(domain_item), warnings))

    for ip_item in source.get("ip", []) or []:
        payload_items.append(convert_ip(str(ip_item), warnings))

    for protocol_item in source.get("protocol", []) or []:
        payload_items.append(convert_protocol(str(protocol_item), notes, warnings))

    port = str(source.get("port", "")).strip()
    if port:
        if is_full_port_range(port) and not payload_items:
            # 纯“全端口兜底”在 Clash 中更规范的写法是 MATCH。
            is_match_all = True
            notes.append("全端口兜底规则已规范化转换为 MATCH。")
        else:
            payload_items.append(f"DST-PORT,{port}")

    payload = dedupe_keep_order(payload_items)

    if "拦截" in remarks and outbound == "direct":
        notes.append("remarks 含“拦截”，但原规则 outboundTag=direct；按真实行为迁移。")

    if not payload and not is_match_all:
        warnings.append("该规则未生成任何 payload，请手工确认。")

    slug = to_slug(remarks, used_slugs)
    file_name = f"{index:02d}-{slug}.yaml"
    provider_name = f"custom-{index:02d}-{slug}"

    return ConvertedRule(
        index=index,
        remarks=remarks,
        enabled=enabled,
        outbound=outbound,
        provider_name=provider_name,
        file_name=file_name,
        payload=payload,
        is_match_all=is_match_all,
        notes=dedupe_keep_order(notes),
        warnings=dedupe_keep_order(warnings),
    )


def write_rule_file(path: Path, rule: ConvertedRule) -> None:
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
    proxy_group = "🚀 手动选择"
    auto_group = "♻️ 自动选择"
    direct_group = "🎯 全球直连"
    block_group = "⛔ 强制阻断"
    fallback_group = "🐟 漏网策略"

    def map_policy_group(outbound: str) -> str:
        if outbound == "proxy":
            return proxy_group
        if outbound == "block":
            return block_group
        return direct_group

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
    lines.append(f"    icon: https://avatars.githubusercontent.com/u/{github_id}?s=128")
    lines.append("    proxies:")
    lines.append(f"      - {auto_group}")
    lines.append(f"      - {direct_group}")
    lines.append(f"  - name: {auto_group}")
    lines.append("    type: select")
    lines.append(f"    icon: https://avatars.githubusercontent.com/u/{github_id}?s=128")
    lines.append("    proxies:")
    lines.append(f"      - {direct_group}")
    lines.append(f"  - name: {direct_group}")
    lines.append("    type: select")
    lines.append(f"    icon: https://avatars.githubusercontent.com/u/{github_id}?s=128")
    lines.append("    proxies:")
    lines.append("      - DIRECT")
    lines.append(f"  - name: {block_group}")
    lines.append("    type: select")
    lines.append(f"    icon: https://avatars.githubusercontent.com/u/{github_id}?s=128")
    lines.append("    proxies:")
    lines.append("      - REJECT")
    lines.append("      - DIRECT")
    lines.append(f"  - name: {fallback_group}")
    lines.append("    type: select")
    lines.append(f"    icon: https://avatars.githubusercontent.com/u/{github_id}?s=128")
    lines.append("    proxies:")
    lines.append(f"      - {direct_group}")
    lines.append(f"      - {proxy_group}")
    lines.append(f"      - {auto_group}")
    lines.append("")
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
        policy_group = map_policy_group(rule.outbound)
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
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_proxy_group_example(path: Path, github_id: str) -> None:
    lines = [
        "# 可选示例：与订阅站模板同名分组，便于在本地与模板之间保持一致行为。",
        "# 说明：",
        "# 1) 这里的 `🚀 手动选择` / `♻️ 自动选择` 是可启动兜底，请替换为你的真实代理入口。",
        "# 2) `🐟 漏网策略` 作为末尾 MATCH 指向组，可在客户端一键切换直连/代理。",
        "# 3) icon 使用 GitHub 头像，便于在 UI 识别自定义分组。",
        "",
        "proxy-groups:",
        "  - name: 🚀 手动选择",
        "    type: select",
        f"    icon: https://avatars.githubusercontent.com/u/{github_id}?s=128",
        "    proxies:",
        "      - ♻️ 自动选择",
        "      - 🎯 全球直连",
        "",
        "  - name: ♻️ 自动选择",
        "    type: select",
        f"    icon: https://avatars.githubusercontent.com/u/{github_id}?s=128",
        "    proxies:",
        "      - 🎯 全球直连",
        "",
        "  - name: 🎯 全球直连",
        "    type: select",
        f"    icon: https://avatars.githubusercontent.com/u/{github_id}?s=128",
        "    proxies:",
        "      - DIRECT",
        "",
        "  - name: ⛔ 强制阻断",
        "    type: select",
        f"    icon: https://avatars.githubusercontent.com/u/{github_id}?s=128",
        "    proxies:",
        "      - REJECT",
        "      - DIRECT",
        "",
        "  - name: 🐟 漏网策略",
        "    type: select",
        f"    icon: https://avatars.githubusercontent.com/u/{github_id}?s=128",
        "    proxies:",
        "      - 🎯 全球直连",
        "      - 🚀 手动选择",
        "      - ♻️ 自动选择",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_geox_url_snippet(path: Path) -> None:
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
        "- `proxy-groups-custom.example.yaml`：可选分组示例（与模板同名组 + icon）。",
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
        "- 纯 `0-65535` / `1-65535` 全端口兜底规则会自动转换为 `MATCH`。",
        "- 订阅站模板中，末尾 `MATCH` 默认指向“漏网策略”组，便于在客户端一键切换直连/代理。",
        "- `enabled=false` 条目不会生成 provider 文件与 provider 声明，仅保留注释方便回滚。",
        "- remarks 写“拦截”但 outboundTag 为 `direct` 的条目，会按真实行为映射为 `direct`。",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_subscription_template(
    path: Path,
    rules: list[ConvertedRule],
    repo: str,
    branch: str,
    interval: int,
    github_id: str,
) -> None:
    # 模板默认使用固定分组名，确保订阅站渲染前后命名稳定，不影响规则引用。
    proxy_group = "🚀 手动选择"
    auto_group = "♻️ 自动选择"
    direct_group = "🎯 全球直连"
    block_group = "⛔ 强制阻断"
    fallback_group = "🐟 漏网策略"

    def map_policy_group(outbound: str) -> str:
        if outbound == "proxy":
            return proxy_group
        if outbound == "block":
            return block_group
        return direct_group

    lines: list[str] = []
    lines.append("# 订阅站模板：由 scripts/generate_clash_rules.py 自动生成。")
    lines.append("# 说明：")
    lines.append("# 1) `__PROXY_PROVIDERS__` 与 `__PROXY_NODES__` 由订阅站在渲染阶段替换。")
    lines.append("# 2) 自定义规则顺序来自 custom_routing_rules，并按原 enabled 状态输出。")
    lines.append("# 3) 末尾 MATCH 固定使用“漏网策略”组，方便在客户端一键切换直连/代理。")
    lines.append("")
    lines.append("mode: rule")
    lines.append("dns:")
    lines.append("  enable: true")
    lines.append("  enhanced-mode: fake-ip")
    lines.append("  fake-ip-range: 198.18.0.1/16")
    lines.append("  nameserver:")
    lines.append("    - tls://8.8.8.8")
    lines.append("    - tls://1.1.1.1")
    lines.append("  default-nameserver:")
    lines.append("    - 223.5.5.5")
    lines.append("    - 119.29.29.29")
    lines.append("  nameserver-policy:")
    lines.append("    geosite:cn:")
    lines.append("      - 223.5.5.5")
    lines.append("      - 119.29.29.29")
    lines.append("  fake-ip-filter:")
    lines.append("    - +.lan")
    lines.append("    - +.local")
    lines.append("proxies: null")
    lines.append("proxy-groups:")
    lines.append(f"  - name: {proxy_group}")
    lines.append("    type: select")
    lines.append(f"    icon: https://avatars.githubusercontent.com/u/{github_id}?s=128")
    lines.append("    include-all: true")
    lines.append("    include-all-proxies: true")
    lines.append("    include-all-providers: true")
    lines.append("    proxies:")
    lines.append(f"      - {auto_group}")
    lines.append("      - __PROXY_PROVIDERS__")
    lines.append("      - __PROXY_NODES__")
    lines.append(f"  - name: {auto_group}")
    lines.append("    type: url-test")
    lines.append(f"    icon: https://avatars.githubusercontent.com/u/{github_id}?s=128")
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
    lines.append(f"    icon: https://avatars.githubusercontent.com/u/{github_id}?s=128")
    lines.append("    proxies:")
    lines.append("      - DIRECT")
    lines.append(f"  - name: {block_group}")
    lines.append("    type: select")
    lines.append(f"    icon: https://avatars.githubusercontent.com/u/{github_id}?s=128")
    lines.append("    proxies:")
    lines.append("      - REJECT")
    lines.append("      - DIRECT")
    lines.append(f"  - name: {fallback_group}")
    lines.append("    type: select")
    lines.append(f"    icon: https://avatars.githubusercontent.com/u/{github_id}?s=128")
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
            lines.append(
                f"  # - RULE-SET,{rule.provider_name},{map_policy_group(rule.outbound)}"
            )
            continue
        lines.append(f"  - RULE-SET,{rule.provider_name},{map_policy_group(rule.outbound)}")
    if not has_terminal_match:
        lines.append(f"  - MATCH,{fallback_group}")
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
    # 仅清理“序号前缀”的生成产物，避免误删用户手工维护的其它文件。
    pattern = re.compile(r"^\d{2}-.+\.ya?ml$")
    for file_path in rules_dir.glob("*.y*ml"):
        if pattern.match(file_path.name):
            file_path.unlink()


def main() -> int:
    args = parse_args()
    project_root = Path(__file__).resolve().parent.parent
    input_path = (project_root / args.input).resolve()
    output_dir = (project_root / args.output_dir).resolve()

    if not input_path.exists():
        print(f"[ERROR] 找不到输入文件: {input_path}", file=sys.stderr)
        return 1

    repo = args.repo.strip() or infer_repo_slug(project_root)
    if not repo:
        print(
            "[ERROR] 无法从 git remote 推断仓库，请通过 --repo owner/repo 显式传入。",
            file=sys.stderr,
        )
        return 1

    source_rules = load_source_rules(input_path)

    rules_dir = output_dir / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    cleanup_generated_rule_files(rules_dir)

    used_slugs: set[str] = set()
    converted: list[ConvertedRule] = []
    all_warnings: list[str] = []

    for idx, src_rule in enumerate(source_rules, 1):
        rule = convert_rule(idx, src_rule, used_slugs)
        converted.append(rule)
        if rule.enabled and not rule.is_match_all:
            write_rule_file(rules_dir / rule.file_name, rule)
        for warning in rule.warnings:
            all_warnings.append(f"#{idx:02d} {rule.remarks}: {warning}")

    write_main_file(
        path=output_dir / "mihomo-custom-rules.yaml",
        rules=converted,
        repo=repo,
        branch=args.branch,
        interval=args.interval,
        github_id=args.github_id,
    )
    if not args.no_template:
        write_subscription_template(
            path=output_dir / args.template_file,
            rules=converted,
            repo=repo,
            branch=args.branch,
            interval=args.interval,
            github_id=args.github_id,
        )
    write_proxy_group_example(output_dir / "proxy-groups-custom.example.yaml", args.github_id)
    write_geox_url_snippet(output_dir / "geox-url-v2ray-rules-dat.yaml")
    write_readme(output_dir / "README.md")

    print(f"[OK] 已生成 {len(converted)} 条规则到: {output_dir}")
    if all_warnings:
        print("[WARN] 需要人工关注的迁移项：", file=sys.stderr)
        for item in all_warnings:
            print(f"  - {item}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
