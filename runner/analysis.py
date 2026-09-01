from __future__ import annotations
import csv, json
from collections import defaultdict
from pathlib import Path
from runner.generators import CODE_LANGS, ENTITIES, INJECTION_TAXONOMY, LANGUAGES, PROMPT_FAMILIES, RESPONSE_FAMILIES, TOKEN_BOUNDARIES
from runner.attachments import ALLOWED_EXTENSIONS, DENIED_EXTENSIONS

def validate_corpora(root=Path("corpus"), minimum=20):
    report={"label":"LOCAL CORPUS GENERATED","expected_cases_per_family":20,"files":{},"coverage":{},"valid":True,"errors":[]}
    seen=set(); meta=defaultdict(set); expected_paths={("prompt",x.lower()) for x in PROMPT_FAMILIES}|{("response",x.lower()) for x in RESPONSE_FAMILIES}
    found=set()
    for path in sorted(root.glob("*/*.jsonl")):
        found.add((path.parent.name,path.stem)); count=0; local_ids=set()
        try:
            for line in path.open(encoding="utf-8"):
                row=json.loads(line); count+=1; cid=row["case_id"]
                if cid in seen or cid in local_ids: report["valid"]=False; report["errors"].append(f"duplicate case_id: {cid}")
                seen.add(cid); local_ids.add(cid)
                for k,v in row.get("metadata",{}).items():
                    if isinstance(v,(str,int,bool)): meta[k].add(v)
        except (json.JSONDecodeError,KeyError) as exc:
            report["valid"]=False; report["errors"].append(f"{path}: {exc}")
        report["files"][str(path)]={"count":count,"unique_ids":len(local_ids)}
        if (path.parent.name,path.stem) in expected_paths and count!=20: report["valid"]=False; report["errors"].append(f"{path}: expected exactly 20, got {count}")
    missing=sorted(expected_paths-found)
    if missing: report["valid"]=False; report["errors"].append(f"missing families: {missing}")
    def dimension(key,configured,label=None):
        covered=sorted(meta[key],key=str); uncovered=sorted(set(configured)-set(covered),key=str)
        return {"covered":covered,"uncovered":uncovered,"complete":not uncovered,"note":label if uncovered and label else None}
    report["coverage"]={
      "anonymize_entities":dimension("entity",ENTITIES,"Representative reduced baseline; not every configured entity was dynamically tested."),
      "code_languages":dimension("code_language",CODE_LANGS,"NOT INCLUDED IN REDUCED 20-CASE BASELINE"),
      "allowed_languages":dimension("language",[x[0] for x in LANGUAGES]),
      "prompt_injection_taxonomies":dimension("taxonomy",INJECTION_TAXONOMY,"Representative reduced baseline; uncovered taxonomies were not dynamically tested."),
      "token_boundaries":dimension("estimated_tokens",TOKEN_BOUNDARIES),
      "username_groups":dimension("expected_group",["allowed","blocked"]),
    }
    report["totals"]={"prompt":sum(x["count"] for p,x in report["files"].items() if Path(p).parent.name=="prompt"),"response":sum(x["count"] for p,x in report["files"].items() if Path(p).parent.name=="response")}
    if report["totals"]!={"prompt":240,"response":120}: report["valid"]=False; report["errors"].append(f"expected 240 prompt and 120 response cases, got {report['totals']}")
    attachment_manifest=Path("testdata/attachments/manifest.csv"); declared=defaultdict(set)
    if attachment_manifest.exists():
        for row in csv.DictReader(attachment_manifest.open(encoding="utf-8")): declared[row["group"]].add(row["declared_extension"].lower())
    report["attachments"]={"manifest":str(attachment_manifest),"allowed_complete":set(ALLOWED_EXTENSIONS)<=declared["allowed"],"denied_complete":set(DENIED_EXTENSIONS)<=declared["denied"]}
    if not report["attachments"]["allowed_complete"] or not report["attachments"]["denied_complete"]: report["valid"]=False; report["errors"].append("attachment extension enumeration incomplete")
    out=Path("results/summaries/coverage.json"); out.parent.mkdir(parents=True,exist_ok=True); out.write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n")
    return report
