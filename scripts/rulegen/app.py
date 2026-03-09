"""规则生成器主流程。"""

from __future__ import annotations

import sys
from pathlib import Path

from .cli import parse_args
from .constants import TEMPLATE_LOCAL_DNS_DOMAINS_FILE, TEMPLATE_LOCAL_DNS_SERVERS_FILE
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


def resolve_template_targets(template_file: str, template_dns_mode: str) -> list[tuple[str, str]]:
    """返回需要输出的模板文件列表。"""

    # 默认同时保留 redir-host / fake-ip 两份标准模板，避免日常重生成时因为模式切换导致
    # 仓库里出现“删除一个模板、再新增另一个模板”的无意义漂移。
    if not template_file.strip():
        return [
            ("template.redir-host.yaml", "redir-host"),
            ("template.fake-ip.yaml", "fake-ip"),
        ]

    # 调用方显式指定输出文件时，按所选 DNS 模式只导出这一份，便于临时产出定制模板。
    return [(template_file.strip(), template_dns_mode)]



def load_optional_template_entries(path: Path) -> list[str]:
    """读取模板旁路补充文件。

    文件采用“一行一条，支持 `#` 注释”的最小格式，便于把少量内网 DNS / 域名模式直接和模板放在一起维护。
    """

    if not path.exists():
        return []

    entries: list[str] = []
    seen: set[str] = set()
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line in seen:
            continue
        seen.add(line)
        entries.append(line)
    return entries

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

    template_local_dns_servers = load_optional_template_entries(output_dir / TEMPLATE_LOCAL_DNS_SERVERS_FILE)
    template_local_dns_domains = load_optional_template_entries(output_dir / TEMPLATE_LOCAL_DNS_DOMAINS_FILE)

    used_slugs: set[str] = set()
    converted: list[ConvertedRule] = []
    all_warnings: list[str] = [f"[validate] {item}" for item in validation_warnings]
    if template_local_dns_domains and not template_local_dns_servers:
        # 仅补域名模式却没有补局域网 DNS 时，这些域名仍会落到默认 direct-nameserver；
        # 对 home.arpa / 自定义内网域名这类场景通常还不够，因此提前给出可操作提示。
        all_warnings.append(
            f"[template] 检测到 {TEMPLATE_LOCAL_DNS_DOMAINS_FILE}，但未检测到 {TEMPLATE_LOCAL_DNS_SERVERS_FILE}；如需解析局域网自定义域名，请补充客户端可达的本地 DNS 服务器。"
        )

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
        for template_name, template_dns_mode in resolve_template_targets(
            args.template_file,
            args.template_dns_mode,
        ):
            write_subscription_template(
                path=output_dir / template_name,
                rules=converted,
                repo=repo,
                branch=args.branch,
                interval=args.interval,
                github_id=args.github_id,
                template_profile=args.template_profile,
                template_dns_mode=template_dns_mode,
                template_dns_upstream=args.template_dns_upstream,
                template_local_dns_servers=template_local_dns_servers,
                template_local_dns_domains=template_local_dns_domains,
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
