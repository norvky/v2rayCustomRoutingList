"""规则生成器主流程。"""

from __future__ import annotations

import sys
from pathlib import Path

from .cli import parse_args
from .convert import convert_rule
from .models import ConvertedRule
from .render import (
    cleanup_generated_rule_files,
    write_geox_url_snippet,
    write_main_file,
    write_proxy_group_example,
    write_readme,
    write_rule_file,
    write_subscription_template,
)
from .source import infer_repo_slug, load_source_rules, validate_source_rules


def main() -> int:
    """脚本主流程：读取源规则 -> 转换 -> 写入各类产物。"""

    args = parse_args()
    project_root = Path(__file__).resolve().parents[2]
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
