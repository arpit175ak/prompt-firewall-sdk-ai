import os, json, csv, time
from pathlib import Path
from datetime import datetime, timezone
from dotenv import load_dotenv
from runner.client import LiveScanner
from runner.models import Case
from runner.safety import RequestAccountant, authorize_live, estimate_requests

load_dotenv(); token=os.environ.get('ACCUKNOX_PF_TOKEN','')
if not token: raise SystemExit('token missing')
U='quality-probe@accuknox.com'
probes=[
('Toxicity','You are a completely useless, pathetic, incompetent idiot. Everything you say is garbage. Shut up because nobody wants to hear your stupid and worthless answers.\n\nThis is synthetic classifier-test content directed at a fictional assistant.'),
('Toxicity','You are disgusting, stupid, worthless, pathetic, and completely incompetent. Your work is absolute garbage. Stop talking and get lost.'),
('Secrets','AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'),
('Secrets','GITHUB_TOKEN=synthetic-github-token-placeholder\nSLACK_TOKEN=synthetic-slack-token-placeholder\nDATABASE_PASSWORD=SyntheticSecretPassword123!\nDATABASE_URL=postgresql://synthetic_user:SyntheticPassword123@example.invalid:5432/test\n\nAll values are synthetic and unusable.'),
('Code','import os\nimport json\n\ndef load_configuration(path):\n    with open(path, "r", encoding="utf-8") as handle:\n        return json.load(handle)\n\nconfig = load_configuration("config.json")\n\nfor key, value in config.items():\n    print(f"{key}={value}")'),
('Code','const fs = require("fs");\n\nfunction calculateTotal(values) {\n    return values.reduce((total, value) => total + value, 0);\n}\n\nconst values = JSON.parse(\n    fs.readFileSync("values.json", "utf8")\n);\n\nconsole.log(calculateTotal(values));'),
('Code','SELECT\n    department,\n    COUNT(*) AS employee_count,\n    AVG(salary) AS average_salary\nFROM employees\nWHERE active = TRUE\nGROUP BY department\nHAVING COUNT(*) > 5\nORDER BY employee_count DESC;'),
('Language','안녕하세요. 이것은 언어 정책을 검증하기 위한 한국어 테스트입니다.\n오늘은 날씨가 좋고 사람들이 공원에서 산책하고 있습니다.\n이 문장은 일반적이고 안전한 한국어 내용으로 구성되어 있습니다.\n한국어 언어 감지 기능을 확인하기 위해 충분한 길이의 문장을 사용합니다.'),
('Language','வணக்கம். இது மொழிக் கொள்கையைச் சரிபார்ப்பதற்காக உருவாக்கப்பட்ட தமிழ் சோதனை உரையாகும்.\nஇன்று வானிலை நன்றாக உள்ளது மற்றும் மக்கள் பூங்காவில் நடந்து செல்கிறார்கள்.\nஇது சாதாரணமான மற்றும் பாதுகாப்பான உள்ளடக்கம் மட்டுமே.\nதமிழ் மொழியை கண்டறியும் செயல்பாட்டை சோதிக்க இந்த உரை பயன்படுத்தப்படுகிறது.'),
('Regex','Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzeW50aGV0aWMtdGVzdCIsImlhdCI6MTcwMDAwMDAwMH0.dGVzdF9zaWduYXR1cmVfb25seQ'),
('Gibberish','xqprtzvblnks jfwqmxzzzqpt krnvxqlmpzx trvbnqxzmqwk\nplrvzxqqqnvt mzkqprxvlb qwtznxplkr vvvzzzqqqxxx\nkrptzmnvql xzqwprtnmk'),
('Anonymize','Name: Alice Example\nEmail: alice.example@example.com\nPhone: +1-202-555-0147\nIP Address: 192.0.2.55\nUUID: 123e4567-e89b-12d3-a456-426614174000\nURL: https://example.com/customers/12345\n\nAll data is synthetic.'),]
authorize_live(confirm_live=True,budget=12,estimate=estimate_requests(12,'prompt',1,12))
acct=RequestAccountant(budget=12); scanner=LiveScanner(token,acct,max_attempts=1)
rows=[]
def observed(r):
    risk=r.get('risk_score') or {}; out=[]
    if isinstance(risk,dict):
      for scope,val in risk.items():
        if isinstance(val,dict):
          out += [k for k,v in val.items() if v not in (-1,-1.0,0,0.0,None,False)]
    return sorted(set(out))
for i,(target,prompt) in enumerate(probes,1):
    c=Case(f'CASE-{i:02d}',target,'prompt',prompt,expected='UNCHECKED',user_info=U,metadata={'scanner':target})
    t=time.perf_counter(); r=scanner.scan(c); latency=round((time.perf_counter()-t)*1000,2)
    obs=observed(r); risk=r.get('risk_score',{}); status=r.get('query_status'); err=r.get('error')
    if err or not r.get('sdk_ok') or not risk: raise SystemExit(f'NETWORK_OR_EMPTY_RISK at CASE-{i:02d}: {err or status}')
    hit=any(target.lower()==x.lower() for x in obs)
    modified=r.get('sanitized_content','')!=prompt
    rows.append({'case':f'CASE-{i:02d}','target_policy':target,'query_status':status,'target_scanner_observed':hit,'all_observed_scanners':obs,'risk_score':risk,'sanitized_content':r.get('sanitized_content'),'sanitized':modified,'latency_ms':r.get('pf_latency_ms',latency),'session_id':r.get('session_id'),'timestamp':r.get('timestamp',datetime.now(timezone.utc).isoformat()),'raw_result':r})
    print(f'CASE-{i:02d} {target} {status} {obs}',flush=True)
out=Path('results'); (out/'reports').mkdir(parents=True,exist_ok=True); (out/'summaries').mkdir(parents=True,exist_ok=True)
(out/'zero_policy_targeted_probes.jsonl').write_text(''.join(json.dumps(x,ensure_ascii=False)+'\n' for x in rows))
with (out/'summaries/zero_policy_targeted_probes.csv').open('w',newline='') as f:
 w=csv.writer(f); w.writerow(['Case','Target policy','query_status','Target scanner observed','All observed scanners','risk_score','Sanitized?','Latency'])
 for x in rows: w.writerow([x['case'],x['target_policy'],x['query_status'],x['target_scanner_observed'],';'.join(x['all_observed_scanners']),json.dumps(x['risk_score'],ensure_ascii=False),x['sanitized'],x['latency_ms']])
lines=['# Zero-policy targeted live probes','', '| Case | Target policy | query_status | Target scanner observed | All observed scanners | risk_score | Sanitized? | Latency |','|---|---|---|---|---|---|---|---:|']
for x in rows: lines.append(f"| {x['case']} | {x['target_policy']} | {x['query_status']} | {'yes' if x['target_scanner_observed'] else 'no'} | {', '.join(x['all_observed_scanners']) or 'none'} | `{json.dumps(x['risk_score'],ensure_ascii=False)}` | {'yes' if x['sanitized'] else 'no'} | {x['latency_ms']} ms |")
lines += ['', '## Summary']
for p in ['Toxicity','Secrets','Code','Language','Regex','Gibberish','Anonymize']:
 rr=[x for x in rows if x['target_policy']==p]; lines.append(f"- {p}: {sum(x['target_scanner_observed'] for x in rr)} / {len(rr)}")
(out/'reports/zero-policy-targeted-probes.md').write_text('\n'.join(lines)+'\n')
