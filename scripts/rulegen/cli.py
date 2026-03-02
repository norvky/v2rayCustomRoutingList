"""命令行参数解析。"""

from __future__ import annotations

import argparse


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
