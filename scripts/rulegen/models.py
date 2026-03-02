"""规则转换过程中的中间模型。"""

from __future__ import annotations

from dataclasses import dataclass, field


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
