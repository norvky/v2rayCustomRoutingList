"""输入源校验与仓库解析测试。"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from rulegen.source import parse_repo_slug_from_url, validate_source_rules  # noqa: E402


class SourceBehaviorTests(unittest.TestCase):
    def test_parse_repo_slug_from_url(self) -> None:
        self.assertEqual(
            parse_repo_slug_from_url("https://github.com/owner/repo.git"),
            "owner/repo",
        )
        self.assertEqual(
            parse_repo_slug_from_url("git@github.com:owner/repo.git"),
            "owner/repo",
        )
        self.assertEqual(parse_repo_slug_from_url("https://example.com/a/b"), "")

    def test_validate_source_rules_detects_structure_errors(self) -> None:
        rules = [
            {
                "remarks": "bad-domain",
                "outboundTag": "direct",
                "domain": "not-a-list",
            },
            {
                "remarks": "match-all-1",
                "enabled": True,
                "outboundTag": "direct",
                "port": "0-65535",
                "domain": [],
                "ip": [],
                "protocol": [],
            },
            {
                "remarks": "match-all-2",
                "enabled": True,
                "outboundTag": "direct",
                "port": "1-65535",
                "domain": [],
                "ip": [],
                "protocol": [],
            },
        ]
        errors, warnings = validate_source_rules(rules)
        self.assertTrue(any("`domain` 必须是数组或 null" in item for item in errors))
        self.assertTrue(any("全端口兜底" in item for item in warnings))


if __name__ == "__main__":
    unittest.main()
