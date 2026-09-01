import json, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
from runner.generators import CODE_LANGS, LANGUAGES, TOKEN_BOUNDARIES, generate_cases, write_jsonl
from runner.mock import MockClient, mock_scan
from runner.models import Case
from runner.normalize import normalize_sdk_result
from runner.retry import TransientScanError, call_with_retry
from runner.safety import LiveExecutionRefused, RequestAccountant, authorize_live, estimate_requests
from runner.storage import Store
from runner.attachments import ALLOWED_EXTENSIONS, DENIED_EXTENSIONS, generate_attachments
from runner.owasp import ALLOWED_IDENTITY, BLOCKED_IDENTITY, cases as owasp_cases, triggered_scanners

class FrameworkTests(unittest.TestCase):
    def test_zero_budget_always_refused(self):
        estimate=estimate_requests(1,"prompt",2,0)
        with patch.dict("os.environ",{"PF_LIVE_ENABLED":"true","PF_ALLOW_LIVE_SCAN":"true"}):
            with self.assertRaises(LiveExecutionRefused): authorize_live(confirm_live=True,confirm_massive=True,budget=0,estimate=estimate)
    def test_estimate_both_with_retry(self):
        e=estimate_requests(10,"both",2,40); self.assertEqual((e.prompt_scan_requests,e.response_scan_requests,e.maximum_retry_requests,e.estimated_max_backend_requests),(10,10,20,40))
    def test_accountant_atomic_and_bounded(self):
        with tempfile.TemporaryDirectory() as d:
            a=RequestAccountant(Path(d)/"a.json",1); a.reserve("prompt"); self.assertRaises(LiveExecutionRefused,a.reserve,"prompt"); self.assertEqual(json.loads((Path(d)/"a.json").read_text())["used"],1)
    def test_normalization_and_fail_modes(self):
        self.assertEqual(normalize_sdk_result({"query_status":"pass"},"x","prompt",1)["query_status"],"PASS")
        self.assertEqual(normalize_sdk_result({"error":"x"},"x","prompt",1,True)["query_status"],"BLOCK")
        self.assertEqual(normalize_sdk_result({"error":"x"},"x","prompt",1,False)["query_status"],"PASS")
    def test_mock_sanitization_session_user(self):
        c=Case("x","Anonymize","prompt","person@example.test",user_info="user@accuknox.com"); r=mock_scan(MockClient(c.user_info),c); self.assertTrue(r["modified"]); self.assertEqual(r["session_id"],"mock-session-001"); self.assertEqual(r["user_info_client"],c.user_info)
    def test_retry_only_transient_and_bounded(self):
        calls=[]
        def f():
            calls.append(1)
            if len(calls)==1: raise TransientScanError("429",retry_after=0)
            return "ok"
        self.assertEqual(call_with_retry(f,sleep=lambda _:None),"ok"); self.assertEqual(len(calls),2)
    def test_jsonl_and_uniqueness(self):
        with tempfile.TemporaryDirectory() as d:
            n,_=write_jsonl(Path(d)/"x.jsonl",generate_cases("Collision",100)); self.assertEqual(n,100); rows=[json.loads(x) for x in (Path(d)/"x.jsonl").read_text().splitlines()]; self.assertEqual(len({x["case_id"] for x in rows}),100)
    def test_sqlite_resume(self):
        with tempfile.TemporaryDirectory() as d:
            s=Store(Path(d)/"x.db"); s.checkpoint("r","case-9",10); self.assertEqual(s.resume("r"),("case-9",10)); s.close()
    def test_reduced_dimensions(self):
        self.assertEqual(len(CODE_LANGS),24)
        self.assertEqual([x[0] for x in LANGUAGES],["ar","bg","de","el","en","es","fr","zh","vi","ur","tr","sw","th","pt","ru","pl","hi","it","ja","nl"])
        self.assertEqual(TOKEN_BOUNDARIES,[1,8,64,256,1024,4096,8000,8100,8180,8190,8191,8192,8193,8200,8250,8300,9000,10000,16384,65536])
    def test_hard_live_ceiling(self):
        estimate=estimate_requests(241,"prompt",1,241)
        with patch.dict("os.environ",{"PF_LIVE_ENABLED":"true","PF_ALLOW_LIVE_SCAN":"true"}):
            with self.assertRaises(LiveExecutionRefused): authorize_live(confirm_live=True,budget=241,estimate=estimate)
    def test_attachment_extension_enumeration(self):
        with tempfile.TemporaryDirectory() as d:
            result=generate_attachments(Path(d)/"testdata"/"attachments")
            self.assertEqual(result["allowed_extensions"],ALLOWED_EXTENSIONS)
            self.assertEqual(result["denied_extensions"],DENIED_EXTENSIONS)
            self.assertTrue((Path(d)/"testdata"/"attachments"/"manifest.csv").exists())
    def test_owasp_suite_gate_distribution_and_identity_isolation(self):
        cases=owasp_cases(); self.assertEqual(len(cases),20); self.assertEqual(cases[0].case_id,"OWASP-CTRL-01")
        self.assertEqual(sum(c.user_info==ALLOWED_IDENTITY for c in cases),19)
        self.assertEqual(sum(c.user_info==BLOCKED_IDENTITY for c in cases),1)
        self.assertLess(len(cases[-2].content.split()),8192)
    def test_nested_live_risk_scores_are_attributed(self):
        result={"risk_score":{"prompt":{"User Name Regex-Prompt-X":-1.0,"Prompt Injection-Prompt-X":0.9,"Attachment Type-Prompt-X":0.0}}}
        self.assertEqual(triggered_scanners(result),["PromptInjection"])

if __name__=="__main__": unittest.main()
