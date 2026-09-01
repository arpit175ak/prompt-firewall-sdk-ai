from __future__ import annotations

import json
from pathlib import Path


def generate_report():
    summary=Path("results/summaries"); summary.mkdir(parents=True,exist_ok=True)
    coverage=json.loads((summary/"coverage.json").read_text()) if (summary/"coverage.json").exists() else {}
    smoke=json.loads((summary/"mock_smoke.json").read_text()) if (summary/"mock_smoke.json").exists() else {}
    accounting=json.loads((summary/"live_request_budget.json").read_text())
    text="# Prompt Firewall Reduced Local Validation Report\n\nLOCAL/MOCK VALIDATED\n\nREMOTELY VALIDATED AGAINST ACCUKNOX: NO\n\nAll statuses and latency are simulated locally. Backend tokenization may differ from local token-size estimates. No pricing claim is made.\n\n## Live request accounting\n\nACCUKNOX LIVE REQUEST BUDGET: {budget}\n\nPROMPT SCANS: {prompt_requests}\n\nRESPONSE SCANS: {response_requests}\n\nRETRIES: {retry_requests}\n\nTOTAL LIVE REQUESTS: {used}\n\nBUDGET REMAINING: {remaining}\n\nMASSIVE REMOTE EXECUTION: NOT RUN\n\n## Coverage (uncovered dimensions are explicit)\n\n```json\n".format(**accounting)+json.dumps(coverage.get("coverage",{}),indent=2,ensure_ascii=False)+"\n```\n\n## Mock smoke\n\nPassed: "+str(smoke.get("passed",False))+"\n"
    (summary/"report.md").write_text(text,encoding="utf-8"); return summary/"report.md"
