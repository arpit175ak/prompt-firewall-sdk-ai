from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path

from runner.client import LiveScanner
from runner.owasp import cases, result_record, write_reports
from runner.safety import RequestAccountant, authorize_live, estimate_requests

RESULTS_PATH = Path("results/owasp_llm_2025_live.jsonl")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Gated OWASP LLM Top 10 2025 Prompt Firewall live baseline")
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--rps", type=float, default=0.2)
    parser.add_argument("--max-attempts", type=int, default=1)
    parser.add_argument("--live-request-budget", type=int, default=20)
    parser.add_argument("--confirm-live", action="store_true")
    args = parser.parse_args(argv)
    if args.workers != 1 or args.rps != 0.2 or args.max_attempts != 1 or args.live_request_budget != 20:
        raise SystemExit("OWASP baseline requires workers=1, rps=0.2, max_attempts=1, and live-request-budget=20")
    token = os.getenv("ACCUKNOX_PF_TOKEN", "")
    if not token: raise SystemExit("ACCUKNOX_PF_TOKEN is required")
    suite = cases()
    estimate = estimate_requests(20, "prompt", 1, 20)
    authorize_live(confirm_live=args.confirm_live, budget=20, estimate=estimate)
    accountant = RequestAccountant(budget=20)
    scanner = LiveScanner(token, accountant, max_attempts=1)
    records = []
    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_PATH.write_text("", encoding="utf-8")
    for index, case in enumerate(suite):
        result = scanner.scan(case)
        record = result_record(case, result)
        records.append(record)
        with RESULTS_PATH.open("a", encoding="utf-8") as handle: handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        print(json.dumps({"progress": index + 1, "case_id": case.case_id, "query_status": record["query_status"], "observed_scanners": record["observed_scanners"], "pf_latency_ms": record["pf_latency_ms"]}), flush=True)
        if not result["sdk_ok"]:
            reason = f"SDK/backend error on {case.case_id}: {result.get('error')}"
            write_reports(records, reason); raise SystemExit(reason)
        if index == 0 and "UserNameRegex" in record["observed_scanners"]:
            reason = "UserNameRegex triggered for allowed identity owasp-test@accuknox.com; policy interference gate failed"
            write_reports(records, reason); print(json.dumps({"stopped": True, "reason": reason, "real_live_requests_used": 1}), flush=True); return 2
        if index + 1 < len(suite): time.sleep(1 / args.rps)
    report, summary = write_reports(records)
    print(json.dumps({"completed": True, "real_live_requests_used": accountant.data["used"], "report": str(report), "summary": str(summary), "accounting": accountant.data}, indent=2), flush=True)
    return 0


if __name__ == "__main__": raise SystemExit(main())
