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
    # 将 remarks 中的稳定词元映射为 ASCII 片段，保证 provider/file 名可读且跨平台兼容。
    # 未映射词元会在 to_slug 中被忽略；若不同规则退化到同一 slug，会触发序号后缀并增加引用漂移风险。
    "crack": "crack",
    "bt": "bt",
    "ip": "ip",
    "steam": "steam",
    "域名": "domain",
    "类别": "category",
    "区域": "region",
    "直连": "direct",
    "代理": "proxy",
    "拦截": "block",
    "广告": "ads",
    "端口": "port",
    "全部": "all",
}

POLICY_MAP = {
    # 统一保留三类语义标签，便于后续扩展其它输出模板时复用策略映射。
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
    """单条源规则转换后的统一中间结构。

    这里把“生成文件名/provider 名”“规则 payload”“迁移备注和告警”聚合在一起，
    目的是让后续写文件阶段只关心输出，不再重复解析源 JSON。
    """

    index: int
    remarks: str
    enabled: bool
    outbound: str
    provider_name: str
    file_name: str
    payload: list[str]
    policy_group: str | None = None
    is_match_all: bool = False
    notes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def parse_args() -> argparse.Namespace:
    """解析命令行参数。

    参数默认值覆盖了仓库常见用法，保证在项目根目录直接执行即可产出完整文件。
    """

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
    parser.add_argument(
        "--template-profile",
        choices=("compat", "boost"),
        default="compat",
        help="订阅站模板配置档位：compat(兼容优先)/boost(增强优先)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="严格模式：出现任何 warning 即返回非 0",
    )
    return parser.parse_args()


def infer_repo_slug(project_root: Path) -> str:
    """从 git remote 尝试推断 `owner/repo`。

    失败时返回空字符串，由调用方决定是否报错退出，避免在该函数里混入 CLI 交互逻辑。
    """

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
    """从常见 GitHub remote URL 提取 `owner/repo`。

    仅匹配已知格式；未匹配时返回空字符串，避免误解析导致生成错误的 raw URL。
    """

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
    """加载并校验源规则 JSON。

    约束源文件必须是数组；如果结构异常直接抛错，防止后续静默生成不完整规则。
    """

    with path.open("r", encoding="utf-8") as fp:
        data = json.load(fp)
    if not isinstance(data, list):
        raise ValueError("源规则文件不是 JSON 数组")
    return data


def validate_source_rules(source_rules: list[dict]) -> tuple[list[str], list[str]]:
    """校验源规则结构，提前暴露高风险问题。

    这里仅做“结构校验 + 兼容性校验”，不改写输入内容，避免静默修复掩盖问题来源。
    """

    errors: list[str] = []
    warnings: list[str] = []
    remarks_seen: dict[str, int] = {}
    enabled_match_all_indexes: list[int] = []

    for idx, item in enumerate(source_rules, 1):
        if not isinstance(item, dict):
            errors.append(f"#{idx:02d} 规则不是对象，实际类型为 `{type(item).__name__}`。")
            continue

        remarks = str(item.get("remarks", f"rule-{idx}")).strip() or f"rule-{idx}"
        if remarks in remarks_seen:
            warnings.append(
                f"#{idx:02d} 与 #{remarks_seen[remarks]:02d} 的 remarks 同名：`{remarks}`。"
            )
        else:
            remarks_seen[remarks] = idx

        outbound_raw = str(item.get("outboundTag", "direct")).strip()
        outbound = outbound_raw.lower()
        if outbound and outbound not in POLICY_MAP:
            warnings.append(
                f"#{idx:02d} `{remarks}` 的 outboundTag=`{outbound_raw}` 未识别，将回落为 direct。"
            )

        for list_key in ("domain", "ip", "protocol"):
            if list_key in item and item[list_key] is not None and not isinstance(
                item[list_key], list
            ):
                errors.append(
                    f"#{idx:02d} `{remarks}` 的 `{list_key}` 必须是数组或 null。"
                )

        if "policyGroup" in item and item["policyGroup"] is not None and not isinstance(
            item["policyGroup"], str
        ):
            errors.append(f"#{idx:02d} `{remarks}` 的 `policyGroup` 必须是字符串或 null。")

        enabled_raw = item.get("enabled", True)
        if not isinstance(enabled_raw, bool):
            warnings.append(
                f"#{idx:02d} `{remarks}` 的 enabled 非布尔值，将按 Python bool 规则处理。"
            )

        port_raw = item.get("port", "")
        if port_raw is None:
            port = ""
        elif isinstance(port_raw, (str, int)):
            port = str(port_raw).strip()
        else:
            errors.append(f"#{idx:02d} `{remarks}` 的 `port` 必须是字符串/数字/null。")
            port = ""

        has_domain = bool(item.get("domain"))
        has_ip = bool(item.get("ip"))
        has_protocol = bool(item.get("protocol"))
        if bool(enabled_raw) and is_full_port_range(port) and not (
            has_domain or has_ip or has_protocol
        ):
            enabled_match_all_indexes.append(idx)

    if len(enabled_match_all_indexes) > 1:
        warnings.append(
            "存在多条已启用“全端口兜底”规则，后出现的 MATCH 会遮蔽前者："
            + ", ".join(f"#{idx:02d}" for idx in enabled_match_all_indexes)
        )

    return errors, warnings


def to_slug(remarks: str, used: set[str]) -> str:
    """将 remarks 转换为 provider/file 使用的 slug。

    设计目标：
    1) 尽量保留语义可读性，便于排障时从文件名反推来源规则；
    2) 在名称冲突时稳定追加序号，避免覆盖已有生成物。
    """

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

    # 当 remarks 含未知中文词元时，可能得到空/重复 slug；这里保底为 rule 并在冲突时追加序号。
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
    """将 v2ray domain 条目转换为 Clash classical 规则。"""

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
    """将 v2ray IP/geoip 条目转换为 Clash classical 规则。

    解析失败时会降级保留原值并写入 warning，避免因单条脏数据中断整批生成。
    """

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
    """将 v2ray protocol 条目转换为 Clash 可表达的近似规则。"""

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
    """按首次出现顺序去重。

    规则顺序会影响命中行为，因此不能使用会打乱顺序的去重方式。
    """

    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if not item or item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def is_full_port_range(port_expr: str) -> bool:
    """判断端口表达式是否为全端口范围。"""

    compact = port_expr.replace(" ", "")
    return compact in {"0-65535", "1-65535"}


def convert_rule(index: int, source: dict, used_slugs: set[str]) -> ConvertedRule:
    """将单条源规则转换为 `ConvertedRule`。

    这里集中处理 domain/ip/protocol/port 四类匹配项，并产出 notes/warnings，
    让写文件阶段只做纯输出拼装。
    """

    remarks = str(source.get("remarks", f"rule-{index}"))
    enabled = bool(source.get("enabled", True))
    outbound = (str(source.get("outboundTag", "direct")).strip() or "direct").lower()
    notes: list[str] = []
    warnings: list[str] = []
    payload_items: list[str] = []
    is_match_all = False
    policy_group: str | None = None

    # 非预期策略值统一回落到 direct，保证生成配置可加载。
    if outbound not in POLICY_MAP:
        warnings.append(f"未识别的 outboundTag=`{outbound}`，已回落到 direct。")
        outbound = "direct"

    policy_group_raw = source.get("policyGroup")
    if policy_group_raw is not None:
        if isinstance(policy_group_raw, str):
            normalized_group = policy_group_raw.strip()
            if normalized_group:
                policy_group = normalized_group
            else:
                warnings.append("policyGroup 为空字符串，已忽略。")
        else:
            warnings.append("policyGroup 不是字符串，已忽略。")

    # `or []` 用于容错 null，避免历史数据写成 `domain: null` 时抛异常。
    for domain_item in source.get("domain", []) or []:
        payload_items.append(convert_domain(str(domain_item), warnings))

    for ip_item in source.get("ip", []) or []:
        payload_items.append(convert_ip(str(ip_item), warnings))

    for protocol_item in source.get("protocol", []) or []:
        payload_items.append(convert_protocol(str(protocol_item), notes, warnings))

    # 端口规则在 v2ray 与 Clash 的最佳实践不同：全端口兜底统一归一化为 MATCH。
    port = str(source.get("port", "")).strip()
    if port:
        if is_full_port_range(port) and not payload_items:
            # 纯“全端口兜底”在 Clash 中更规范的写法是 MATCH。
            is_match_all = True
            notes.append("全端口兜底规则已规范化转换为 MATCH。")
        else:
            payload_items.append(f"DST-PORT,{port}")

    payload = dedupe_keep_order(payload_items)

    # 显式提示“命名语义”和“真实策略”不一致，降低后续维护误判概率。
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
        policy_group=policy_group,
        is_match_all=is_match_all,
        notes=dedupe_keep_order(notes),
        warnings=dedupe_keep_order(warnings),
    )


def collect_custom_policy_groups(rules: list[ConvertedRule], builtins: set[str]) -> list[str]:
    """收集由 `custom_routing_rules.policyGroup` 声明的扩展分组。

    仅返回“非内置分组且非 direct/proxy/block 别名”的名称，保持首次出现顺序。
    """

    custom_groups: list[str] = []
    seen: set[str] = set()
    alias_keys = {"direct", "proxy", "block"}
    for rule in rules:
        if not rule.policy_group:
            continue
        group_name = rule.policy_group.strip()
        if not group_name:
            continue
        if group_name in builtins:
            continue
        if group_name.lower() in alias_keys:
            continue
        if group_name in seen:
            continue
        seen.add(group_name)
        custom_groups.append(group_name)
    return custom_groups


def resolve_policy_group(
    rule: ConvertedRule,
    proxy_group: str,
    direct_group: str,
    block_group: str,
) -> str:
    """解析单条规则最终映射到的策略组名。"""

    alias_map = {
        "proxy": proxy_group,
        "direct": direct_group,
        "block": block_group,
    }

    if rule.policy_group:
        group_name = rule.policy_group.strip()
        if group_name:
            mapped = alias_map.get(group_name.lower())
            return mapped if mapped else group_name

    if rule.outbound == "proxy":
        return proxy_group
    if rule.outbound == "block":
        return block_group
    return direct_group


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
    lines.append("  fake-ip-filter:")
    lines.append("    - *.lan")
    lines.append("    - localhost")
    lines.append("    - time.windows.com")
    lines.append("    - time.apple.com")
    lines.append("    - time.google.com")


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


def main() -> int:
    """脚本主流程：读取源规则 -> 转换 -> 写入各类产物。"""

    args = parse_args()
    project_root = Path(__file__).resolve().parent.parent
    input_path = (project_root / args.input).resolve()
    output_dir = (project_root / args.output_dir).resolve()

    if not input_path.exists():
        print(f"[ERROR] 找不到输入文件: {input_path}", file=sys.stderr)
        return 1

    # 优先使用显式参数；为空时再回退到 git remote 推断，减少 CI/离线环境失败概率。
    repo = args.repo.strip() or infer_repo_slug(project_root)
    if not repo:
        print(
            "[ERROR] 无法从 git remote 推断仓库，请通过 --repo owner/repo 显式传入。",
            file=sys.stderr,
        )
        return 1

    source_rules = load_source_rules(input_path)
    validation_errors, validation_warnings = validate_source_rules(source_rules)
    if validation_errors:
        print("[ERROR] 源规则校验失败：", file=sys.stderr)
        for item in validation_errors:
            print(f"  - {item}", file=sys.stderr)
        return 1

    used_slugs: set[str] = set()
    converted: list[ConvertedRule] = []
    all_warnings: list[str] = [f"[validate] {item}" for item in validation_warnings]

    for idx, src_rule in enumerate(source_rules, 1):
        rule = convert_rule(idx, src_rule, used_slugs)
        converted.append(rule)
        for warning in rule.warnings:
            all_warnings.append(f"#{idx:02d} {rule.remarks}: {warning}")

    if args.strict and all_warnings:
        print("[ERROR] strict 模式命中 warning，已终止生成：", file=sys.stderr)
        for item in all_warnings:
            print(f"  - {item}", file=sys.stderr)
        return 2

    rules_dir = output_dir / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    # 先删后写可避免重命名后留下“旧 provider 文件”被误引用。
    cleanup_generated_rule_files(rules_dir)
    for rule in converted:
        if rule.enabled and not rule.is_match_all:
            write_rule_file(rules_dir / rule.file_name, rule)

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
            template_profile=args.template_profile,
        )
    write_proxy_group_example(output_dir / "proxy-groups-custom.example.yaml", args.github_id)
    write_geox_url_snippet(output_dir / "geox-url-v2ray-rules-dat.yaml")
    write_readme(output_dir / "README.md")

    print(f"[OK] 已生成 {len(converted)} 条规则到: {output_dir}")
    if all_warnings:
        # warning 输出到 stderr，便于在 CI 中与正常日志分流采集。
        print("[WARN] 需要人工关注的迁移项：", file=sys.stderr)
        for item in all_warnings:
            print(f"  - {item}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
