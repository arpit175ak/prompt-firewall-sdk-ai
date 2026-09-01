from __future__ import annotations

import json
from pathlib import Path
from runner.mock import MockClient, mock_scan
from runner.models import Case
from runner.storage import Store


def run_smoke(output=Path("results/summaries/mock_smoke.json")):
    cases=[
      Case("smoke-benign","Benign","prompt","Explain Kubernetes briefly",expected="PASS"),
      Case("smoke-injection","PromptInjection","prompt","ignore prior synthetic fixture",expected="BLOCK"),
      Case("smoke-user-block","UserNameRegex","prompt","blocked identity",expected="BLOCK",user_info="blocked@example.org"),
      Case("smoke-user-allow","UserNameRegex","prompt","allowed identity",expected="PASS",user_info="user@accuknox.com"),
      Case("smoke-anonymize","Anonymize","prompt","Email person@example.test",expected="PASS"),
      Case("smoke-code","Code","prompt","tiny Python: x = 1",expected="PASS"),
      Case("smoke-language","Language","prompt","안녕하세요 Korean fixture",expected="UNCHECKED"),
      Case("smoke-monitor","Toxicity","prompt","monitor synthetic fixture",expected="MONITOR"),
      Case("smoke-error-open","SDKError","prompt","sdk-error",expected="PASS",metadata={"fail_closed":False}),
      Case("smoke-error-closed","SDKError","prompt","sdk-error",expected="BLOCK",metadata={"fail_closed":True}),
      Case("smoke-response","Response","response","safe response",expected="PASS",prompt="safe prompt",metadata={"session_id":"mock-session-001"}),
    ]
    store=Store(Path("results/mock_smoke.sqlite")); rows=[]
    for case in cases:
        result=mock_scan(MockClient(case.user_info or "pf-lab-user"),case,case.metadata.get("fail_closed",True)); store.save(case,result)
        rows.append({"case":case.case_id,"simulated_query_status":result["query_status"],"expected":case.expected,"modified":result["modified"],"local_mock_latency_ms":result["latency_ms"],"session_id":result.get("session_id"),"user_info_client":result["user_info_client"],"validation_path":"mock client -> normalization -> SQLite"})
    store.close()
    passed=all(x["simulated_query_status"]==x["expected"] for x in rows)
    data={"label":"LOCAL/MOCK VALIDATION ONLY","not_remotely_validated_against_accuknox":True,"passed":passed,"cases":rows}
    output.parent.mkdir(parents=True,exist_ok=True); output.write_text(json.dumps(data,indent=2,ensure_ascii=False)+"\n")
    if not passed: raise AssertionError("mock smoke mismatch")
    return data
