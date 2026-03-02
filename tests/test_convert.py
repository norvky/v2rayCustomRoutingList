"""转换层核心行为回归测试。"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from rulegen.convert import (  # noqa: E402
    collect_custom_policy_groups,
    convert_rule,
    is_full_port_range,
    resolve_policy_group,
)
from rulegen.models import ConvertedRule  # noqa: E402


class ConvertBehaviorTests(unittest.TestCase):
    def test_is_full_port_range(self) -> None:
        self.assertTrue(is_full_port_range("0-65535"))
        self.assertTrue(is_full_port_range("1 - 65535"))
        self.assertFalse(is_full_port_range("80"))

    def test_convert_rule_match_all_port(self) -> None:
        rule = convert_rule(
            1,
            {
                "remarks": "端口_全部_直连",
                "enabled": True,
                "outboundTag": "direct",
                "port": "0-65535",
                "domain": [],
                "ip": [],
                "protocol": [],
            },
            set(),
        )
        self.assertTrue(rule.is_match_all)
        self.assertEqual(rule.payload, [])
        self.assertIn("全端口兜底规则已规范化转换为 MATCH。", rule.notes)

    def test_convert_rule_unknown_outbound_fallback_to_direct(self) -> None:
        rule = convert_rule(
            2,
            {
                "remarks": "未知策略",
                "enabled": True,
                "outboundTag": "foo",
                "domain": ["domain:example.com"],
            },
            set(),
        )
        self.assertEqual(rule.outbound, "direct")
        self.assertIn("未识别的 outboundTag=`foo`，已回落到 direct。", rule.warnings)

    def test_collect_custom_policy_groups_filters_alias_and_duplicates(self) -> None:
        rules = [
            ConvertedRule(1, "a", True, "direct", "p1", "f1", [], policy_group="业务A"),
            ConvertedRule(2, "b", True, "direct", "p2", "f2", [], policy_group="业务A"),
            ConvertedRule(3, "c", True, "direct", "p3", "f3", [], policy_group="direct"),
            ConvertedRule(4, "d", True, "direct", "p4", "f4", [], policy_group="   "),
        ]
        groups = collect_custom_policy_groups(rules, builtins={"🐟 漏网策略"})
        self.assertEqual(groups, ["业务A"])

    def test_resolve_policy_group(self) -> None:
        rule = ConvertedRule(1, "a", True, "proxy", "p", "f", [], policy_group="业务A")
        self.assertEqual(
            resolve_policy_group(rule, proxy_group="P", direct_group="D", block_group="B"),
            "业务A",
        )

        alias_rule = ConvertedRule(2, "b", True, "proxy", "p", "f", [], policy_group="direct")
        self.assertEqual(
            resolve_policy_group(alias_rule, proxy_group="P", direct_group="D", block_group="B"),
            "D",
        )


if __name__ == "__main__":
    unittest.main()
