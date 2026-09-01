# Results Directory

This directory is used for generated local and live validation artifacts.

The repository intentionally ignores generated JSONL and SQLite outputs because
they may contain raw SDK responses. Review and sanitize any generated report
before committing it.

Expected generated locations include:

- `results/reports/`
- `results/summaries/`
- `results/*.jsonl`
- `results/*.sqlite`
