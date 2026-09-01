from __future__ import annotations

import argparse, json, os, time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from runner.analysis import validate_corpora
from runner.attachments import generate_attachments
from runner.generators import generate_corpus
from runner.reports import generate_report
from runner.safety import RequestAccountant, authorize_live, estimate_requests
from runner.smoke import run_smoke
from runner.client import LiveScanner
from runner.models import Case
from runner.storage import Store

def parser():
    p=argparse.ArgumentParser(prog="python -m runner.cli",description="Local-first AccuKnox Prompt Firewall lab (live disabled by default)"); sub=p.add_subparsers(dest="command",required=True)
    g=sub.add_parser("generate",help="generate the reduced local JSONL corpus"); g.add_argument("--policy"); g.add_argument("--all",action="store_true",help="generate every policy family"); g.add_argument("--direction",choices=["all","prompt","response"],default="all"); g.add_argument("--count",type=int,default=20); g.add_argument("--count-per-policy",type=int,dest="count_per_policy"); g.add_argument("--output",type=Path,default=Path("corpus"))
    sub.add_parser("attachments"); v=sub.add_parser("validate"); v.add_argument("--minimum",type=int,default=20,help=argparse.SUPPRESS)
    sub.add_parser("smoke"); sub.add_parser("report"); sub.add_parser("summary"); sub.add_parser("analyze")
    prep=sub.add_parser("prepare"); prep.add_argument("--policy",required=True); prep.add_argument("--limit",type=int,required=True)
    run=sub.add_parser("run",help="live runner, guarded by an authorized 240-attempt ceiling"); run.add_argument("--policy",default="all"); run.add_argument("--direction",choices=["prompt","response","both"],default="prompt"); run.add_argument("--limit",type=int,required=True); run.add_argument("--workers",type=int,default=1); run.add_argument("--rps",type=float,default=.2); run.add_argument("--batch-size",type=int,default=1); run.add_argument("--max-attempts",type=int,default=1); run.add_argument("--confirm-live",action="store_true"); run.add_argument("--live-request-budget",type=int,default=20); run.add_argument("--resume",action="store_true"); run.add_argument("--run-id",default="live-run"); run.add_argument("--session-id",help="required for response-only scans; obtain from a previously authorized prompt run")
    return p

def main(argv=None):
    a=parser().parse_args(argv)
    if a.command=="generate":
        if a.all and a.policy: raise SystemExit("use either --all or --policy, not both")
        count=a.count_per_policy if a.count_per_policy is not None else a.count
        manifest=generate_corpus(a.output,count,None if a.all else a.policy,a.direction); Path("results/summaries").mkdir(parents=True,exist_ok=True); Path("results/summaries/reproducibility_manifest.json").write_text(json.dumps(manifest,indent=2)+"\n"); print(json.dumps({"label":"LOCAL CORPUS GENERATED","network_requests":0,"files":manifest},indent=2))
    elif a.command=="attachments": print(json.dumps(generate_attachments(),indent=2))
    elif a.command=="validate":
        result=validate_corpora(minimum=a.minimum); print(json.dumps(result,indent=2,ensure_ascii=False)); raise SystemExit(0 if result["valid"] else 1)
    elif a.command=="smoke": print(json.dumps(run_smoke(),indent=2,ensure_ascii=False))
    elif a.command=="report": print(generate_report())
    elif a.command in {"summary","analyze"}:
        for name in ["coverage.json","mock_smoke.json","live_request_budget.json"]:
            path=Path("results/summaries")/name
            if path.exists(): print(path, path.read_text())
    elif a.command=="prepare": print(json.dumps({"policy":a.policy,"selected_cases":a.limit,"network_requests":0,"label":"LOCAL CORPUS GENERATED"},indent=2))
    elif a.command=="run":
        if a.workers != 1: raise SystemExit("this baseline requires --workers 1")
        if a.max_attempts != 1: raise SystemExit("this baseline requires --max-attempts 1")
        if a.direction != "prompt": raise SystemExit("this authorized baseline is prompt-only")
        if a.rps > .2: raise SystemExit("this baseline is capped at 0.2 requests/second")
        est=estimate_requests(a.limit,a.direction,a.max_attempts,a.live_request_budget)
        token=os.getenv("ACCUKNOX_PF_TOKEN","")
        if not token: raise SystemExit("ACCUKNOX_PF_TOKEN must be supplied by the future operator")
        if a.direction in {"response","both"} and not a.session_id: raise SystemExit("--session-id is required for response execution; no placeholder is invented")
        files=[]
        directions=[a.direction] if a.direction!="both" else ["prompt","response"]
        for direction in directions:
            files += sorted((Path("corpus")/direction).glob("*.jsonl")) if a.policy.lower()=="all" else [Path("corpus")/direction/f"{a.policy.lower()}.jsonl"]
        selected=[]
        for direction in directions:
            direction_rows=[]
            for path in [p for p in files if p.parent.name==direction]:
                if not path.exists(): continue
                for line in path.open(encoding="utf-8"):
                    row=json.loads(line)
                    if direction=="response": row.setdefault("metadata",{})["session_id"]=a.session_id
                    direction_rows.append(Case(**row))
                    if len(direction_rows)>=a.limit: break
                if len(direction_rows)>=a.limit: break
            selected.extend(direction_rows)
        counts=Counter(case.family for case in selected)
        expected_families={"Anonymize","Gibberish","PromptInjection","Toxicity","BanCode","Code","Language","Regex","UserNameRegex","Secrets","TokenLimit","Collisions"}
        selection={"selected_cases":len(selected),"expected_prompt_requests":est.prompt_scan_requests,"expected_response_requests":est.response_scan_requests,"current_request_budget":a.live_request_budget,"remaining_request_budget":a.live_request_budget,"families":dict(sorted(counts.items()))}
        print(json.dumps(selection,indent=2),flush=True)
        if len(selected)!=240 or set(counts)!=expected_families or any(counts[x]!=20 for x in expected_families):
            raise SystemExit("dry selection failed: expected exactly 240 prompt cases and 20 per family; no live request was made")
        if est.prompt_scan_requests != 240 or est.response_scan_requests != 0:
            raise SystemExit("request estimate failed; no live request was made")
        authorize_live(confirm_live=a.confirm_live,budget=a.live_request_budget,estimate=est)
        accountant=RequestAccountant(budget=a.live_request_budget); scanner=LiveScanner(token,accountant,max_attempts=a.max_attempts); store=Store(Path("results/live.sqlite"))
        _,processed=store.resume(a.run_id) if a.resume else (None,0)
        interval=1/max(a.rps,.000001)
        run_started=datetime.now(timezone.utc).isoformat()
        for index,case in enumerate(selected[processed:],start=processed+1):
            result=scanner.scan(case); store.save(case,result); store.checkpoint(a.run_id,case.case_id,index)
            print(json.dumps({"progress":index,"case_id":case.case_id,"policy":case.family,"query_status":result["query_status"],"sdk_ok":result["sdk_ok"],"pf_latency_ms":result["pf_latency_ms"]}),flush=True)
            if not result["sdk_ok"]:
                store.close()
                raise SystemExit(f"stopping after SDK/backend error on {case.case_id}: {result.get('error')}")
            if index<len(selected): time.sleep(interval)
        run_ended=datetime.now(timezone.utc).isoformat()
        store.close(); print(json.dumps({"run_id":a.run_id,"processed":len(selected),"run_start_timestamp":run_started,"run_end_timestamp":run_ended,"successful_sdk_requests":len(selected),"accounting":accountant.data},indent=2))

if __name__=="__main__": main()
