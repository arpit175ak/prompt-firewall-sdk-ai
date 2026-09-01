#!/usr/bin/env bash
set -euo pipefail
python -m runner.cli generate --all --count-per-policy 20 --direction all
python -m runner.cli attachments
python -m runner.cli validate
