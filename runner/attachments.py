from __future__ import annotations
import csv, hashlib, json
from pathlib import Path

ALLOWED_EXTENSIONS=[".txt",".md",".json",".csv",".py",".js",".html",".xml",".yaml",".pdf",".docx",".png",".jpg"]
DENIED_EXTENSIONS=[".exe",".dll",".bat",".cmd",".com",".msi",".scr",".jar",".ps1",".sh",".zip",".rar",".7z"]

def _payload(ext):
    if ext==".pdf": return b"%PDF-1.4\n% safe local specimen\n%%EOF\n"
    if ext==".png": return b"\x89PNG\r\n\x1a\nLOCAL_SAFE_SPECIMEN"
    if ext in {".jpg",".jpeg"}: return b"\xff\xd8\xff\xe0LOCAL_SAFE_SPECIMEN\xff\xd9"
    if ext==".docx": return b"PK\x03\x04LOCAL_SAFE_DOCX_SPECIMEN"
    return f"LOCAL SAFE ATTACHMENT SPECIMEN {ext}\n".encode()

def generate_attachments(root:Path=Path("testdata/attachments")):
    rows=[]
    def write(group,name,data,declared,actual,note):
        path=root/group/name; path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(data)
        rows.append({"path":str(path),"group":group,"declared_extension":declared,"content_shape":actual,"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest(),"note":note})
    for ext in ALLOWED_EXTENSIONS: write("allowed",f"safe{ext}",_payload(ext),ext,ext,"configured allowed extension")
    for ext in DENIED_EXTENSIONS: write("denied",f"safe{ext}",_payload(".txt"),ext,".txt","inert specimen for configured denied extension")
    write("mismatch","claims_pdf.pdf",_payload(".txt"),".pdf",".txt","extension/content mismatch")
    write("mismatch","claims_txt.txt",_payload(".pdf"),".txt",".pdf","extension/content mismatch")
    write("double_extension","invoice.pdf.exe",_payload(".txt"),".exe",".txt","double extension")
    write("double_extension","image.jpg.sh",_payload(".txt"),".sh",".txt","double extension")
    for name in ["SAFE.TXT","mixed.PdF","photo.JpG"]: write("case_variants",name,_payload(Path(name).suffix.lower()),Path(name).suffix,Path(name).suffix.lower(),"case variant")
    manifest=root/"manifest.csv"; manifest.parent.mkdir(parents=True,exist_ok=True)
    with manifest.open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    result={"label":"LOCAL ONLY — SDK ATTACHMENT SUPPORT NOT CONFIRMED","root":str(root),"allowed_extensions":ALLOWED_EXTENSIONS,"denied_extensions":DENIED_EXTENSIONS,"specimens":len(rows),"manifest":str(manifest)}
    out=Path("results/summaries/attachments.json"); out.parent.mkdir(parents=True,exist_ok=True); out.write_text(json.dumps(result,indent=2)+"\n")
    return result
