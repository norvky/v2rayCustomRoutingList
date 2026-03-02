"""源规则到 Clash 规则的转换逻辑。"""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable

from .constants import POLICY_MAP, PROTOCOL_FALLBACK_MAP, REMARK_TOKEN_MAP
from .models import ConvertedRule


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
