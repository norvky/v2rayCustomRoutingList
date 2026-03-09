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
    def write_source_rules(self, source: Path) -> None:
        """写入最小可运行的源规则样本。"""

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

    def run_generator(self, source: Path, out: Path, *extra_args: str) -> subprocess.CompletedProcess[str]:
        """执行生成脚本并返回结果。"""

        return subprocess.run(
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
                *extra_args,
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_generate_standard_templates_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            source = tmp_path / "custom_routing_rules.json"
            out = tmp_path / "out"
            self.write_source_rules(source)

            result = self.run_generator(source, out)

            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertTrue((out / "mihomo-custom-rules.yaml").exists())
            self.assertTrue((out / "template.redir-host.yaml").exists())
            self.assertTrue((out / "template.fake-ip.yaml").exists())
            self.assertTrue((out / "rules" / "01-domain-direct.yaml").exists())

            main_text = (out / "mihomo-custom-rules.yaml").read_text(encoding="utf-8")
            redir_host_text = (out / "template.redir-host.yaml").read_text(encoding="utf-8")
            fake_ip_text = (out / "template.fake-ip.yaml").read_text(encoding="utf-8")
            self.assertIn("RULE-SET,custom-01-domain-direct,🎯 全球直连", main_text)
            self.assertIn("MATCH,🐟 漏网策略", main_text)
            self.assertIn("全端口/全流量兜底规则已折叠为 MATCH,🐟 漏网策略", main_text)
            self.assertIn("      - 🚀 手动选择\n      - ♻️ 自动选择\n      - 🎯 全球直连", main_text)
            self.assertIn("enhanced-mode: redir-host", redir_host_text)
            self.assertIn("全端口/全流量兜底规则已折叠为 MATCH,🐟 漏网策略", redir_host_text)
            self.assertIn("force-dns-mapping: true", redir_host_text)
            self.assertIn("direct-nameserver:", redir_host_text)
            self.assertIn("direct-nameserver-follow-policy: true", redir_host_text)
            self.assertIn("    \"+.home.arpa\":\n      - 223.5.5.5\n      - 119.29.29.29", redir_host_text)
            self.assertIn("    \"kubernetes.default.svc\":\n      - 223.5.5.5\n      - 119.29.29.29", redir_host_text)
            self.assertIn("https://dns.cloudflare.com/dns-query", redir_host_text)
            self.assertNotIn("fallback:", redir_host_text)
            self.assertNotIn("fake-ip-filter", redir_host_text)
            self.assertIn("enhanced-mode: fake-ip", fake_ip_text)
            self.assertIn("fake-ip-filter:", fake_ip_text)
            self.assertIn("https://dns.google/dns-query", fake_ip_text)
            self.assertNotIn("force-dns-mapping: true", fake_ip_text)

    def test_generate_custom_fake_ip_template_with_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            source = tmp_path / "custom_routing_rules.json"
            out = tmp_path / "out"
            self.write_source_rules(source)

            result = self.run_generator(
                source,
                out,
                "--template-file",
                "template.custom.yaml",
                "--template-dns-mode",
                "fake-ip",
            )

            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertTrue((out / "template.custom.yaml").exists())
            self.assertFalse((out / "template.redir-host.yaml").exists())
            self.assertFalse((out / "template.fake-ip.yaml").exists())

            template_text = (out / "template.custom.yaml").read_text(encoding="utf-8")
            self.assertIn("enhanced-mode: fake-ip", template_text)
            self.assertIn("fake-ip-filter:", template_text)
            self.assertIn("# 6) 当前 DNS 上游：compat。", template_text)
            self.assertNotIn("force-dns-mapping: true", template_text)

    def test_generate_custom_pure_ip_template_with_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            source = tmp_path / "custom_routing_rules.json"
            out = tmp_path / "out"
            self.write_source_rules(source)

            result = self.run_generator(
                source,
                out,
                "--template-file",
                "template.pure-ip.yaml",
                "--template-dns-upstream",
                "pure-ip",
            )

            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertTrue((out / "template.pure-ip.yaml").exists())

            template_text = (out / "template.pure-ip.yaml").read_text(encoding="utf-8")
            self.assertIn("enhanced-mode: redir-host", template_text)
            self.assertIn("# 6) 当前 DNS 上游：pure-ip。", template_text)
            self.assertIn("  nameserver:\n    - 1.1.1.1\n    - 8.8.8.8", template_text)
            self.assertIn("  proxy-server-nameserver:\n    - 1.1.1.1\n    - 8.8.8.8", template_text)
            self.assertIn("  direct-nameserver:\n    - 223.5.5.5\n    - 119.29.29.29", template_text)
            self.assertNotIn("dns.google/dns-query", template_text)



    def test_merge_local_dns_overrides_into_templates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            source = tmp_path / "custom_routing_rules.json"
            out = tmp_path / "out"
            self.write_source_rules(source)
            out.mkdir()

            # 本地 DNS 文件与模板放在同目录维护，便于仓库重生成后持续复用。
            (out / "template.local-dns-servers.txt").write_text(
                "# comment\n192.168.1.1\n172.16.0.53\n192.168.1.1\n",
                encoding="utf-8",
            )
            (out / "template.local-dns-domains.txt").write_text(
                "# comment\n+.corp.internal\n+.home.arpa\n+.corp.internal\n",
                encoding="utf-8",
            )

            result = self.run_generator(source, out)

            self.assertEqual(result.returncode, 0, msg=result.stderr)
            redir_host_text = (out / "template.redir-host.yaml").read_text(encoding="utf-8")
            fake_ip_text = (out / "template.fake-ip.yaml").read_text(encoding="utf-8")
            self.assertIn(
                "  direct-nameserver:\n    - 192.168.1.1\n    - 172.16.0.53\n    - 223.5.5.5\n    - 119.29.29.29",
                redir_host_text,
            )
            self.assertIn(
                "    \"+.corp.internal\":\n      - 192.168.1.1\n      - 172.16.0.53\n      - 223.5.5.5\n      - 119.29.29.29",
                redir_host_text,
            )
            self.assertIn(
                "    \"+.corp.internal\":\n      - 192.168.1.1\n      - 172.16.0.53\n      - 223.5.5.5\n      - 119.29.29.29",
                fake_ip_text,
            )

    def test_merge_disable_ipv6_domains_into_templates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            source = tmp_path / "custom_routing_rules.json"
            out = tmp_path / "out"
            self.write_source_rules(source)
            out.mkdir()

            (out / "template.disable-ipv6-domains.txt").write_text(
                "# comment\ngemini.google.com\n+.googleapis.com\ngemini.google.com\n",
                encoding="utf-8",
            )

            result = self.run_generator(source, out)

            self.assertEqual(result.returncode, 0, msg=result.stderr)
            redir_host_text = (out / "template.redir-host.yaml").read_text(encoding="utf-8")
            fake_ip_text = (out / "template.fake-ip.yaml").read_text(encoding="utf-8")
            self.assertIn(
                '    "gemini.google.com":\n      - https://dns.cloudflare.com/dns-query#disable-ipv6=true\n      - https://dns.google/dns-query#disable-ipv6=true',
                redir_host_text,
            )
            self.assertIn(
                '    "+.googleapis.com":\n      - https://dns.cloudflare.com/dns-query#disable-ipv6=true\n      - https://dns.google/dns-query#disable-ipv6=true',
                fake_ip_text,
            )

    def test_warn_when_disable_ipv6_domains_overlap_local_dns_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            source = tmp_path / "custom_routing_rules.json"
            out = tmp_path / "out"
            self.write_source_rules(source)
            out.mkdir()

            (out / "template.local-dns-domains.txt").write_text("+.corp.internal\n", encoding="utf-8")
            (out / "template.disable-ipv6-domains.txt").write_text(
                "+.home.arpa\n+.corp.internal\n",
                encoding="utf-8",
            )

            result = self.run_generator(source, out)

            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertIn("template.disable-ipv6-domains.txt", result.stderr)
            self.assertIn("与本地 DNS 直连策略重复", result.stderr)
if __name__ == "__main__":
    unittest.main()
