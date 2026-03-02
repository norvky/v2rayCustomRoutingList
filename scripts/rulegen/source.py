"""输入源加载与结构校验。"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from .constants import POLICY_MAP
from .convert import is_full_port_range


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
