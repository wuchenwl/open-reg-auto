#!/usr/bin/env bash
set -euo pipefail
cd /www/wwwroot/open-reg-auto
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
open-reg-auto "$@"
