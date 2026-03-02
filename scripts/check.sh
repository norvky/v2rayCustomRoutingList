#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python3 -m py_compile scripts/generate_clash_rules.py scripts/rulegen/*.py
python3 -m unittest discover -s tests -p 'test_*.py'
python3 scripts/generate_clash_rules.py
# 生成流程必须是可重复的：运行后不应引入未提交漂移。
git diff --exit-code
