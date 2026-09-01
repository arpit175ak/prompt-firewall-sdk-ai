#!/usr/bin/env bash
set -euo pipefail
python -m compileall -q app runner tests
python -m unittest discover -s tests -v
python -m runner.cli validate
python -m runner.cli smoke
python -m runner.cli report
