"""端到端生成流程测试。"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "generate_clash_rules.py"


class PipelineTests(unittest.TestCase):
    def test_generate_with_absolute_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            source = tmp_path / "custom_routing_rules.json"
            out = tmp_path / "out"
            source.write_text(
                json.dumps(
                    [
                        {
                            "remarks": "域名_直连",
                            "enabled": True,
                            "outboundTag": "direct",
                            "domain": ["domain:example.com"],
                        },
                        {
                            "remarks": "端口_全部_直连",
                            "enabled": True,
                            "outboundTag": "direct",
                            "port": "0-65535",
                            "domain": [],
                            "ip": [],
                            "protocol": [],
                        },
                    ],
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--input",
                    str(source),
                    "--output-dir",
                    str(out),
                    "--repo",
                    "owner/repo",
                    "--branch",
                    "main",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertTrue((out / "mihomo-custom-rules.yaml").exists())
            self.assertTrue((out / "template.fake-ip.yaml").exists())
            self.assertTrue((out / "rules" / "01-domain-direct.yaml").exists())

            main_text = (out / "mihomo-custom-rules.yaml").read_text(encoding="utf-8")
            self.assertIn("RULE-SET,custom-01-domain-direct,🎯 全球直连", main_text)
            self.assertIn("MATCH,🐟 漏网策略", main_text)


if __name__ == "__main__":
    unittest.main()
