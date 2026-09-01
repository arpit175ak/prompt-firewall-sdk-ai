from __future__ import annotations

import json, sqlite3
from pathlib import Path

SCHEMA = """CREATE TABLE IF NOT EXISTS results (case_id TEXT PRIMARY KEY, direction TEXT NOT NULL, family TEXT NOT NULL, query_status TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP); CREATE TABLE IF NOT EXISTS checkpoints (run_id TEXT PRIMARY KEY, last_case_id TEXT, processed INTEGER NOT NULL DEFAULT 0, updated_at TEXT DEFAULT CURRENT_TIMESTAMP);"""


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True); self.db = sqlite3.connect(path); self.db.executescript(SCHEMA)
    def save(self, case, result):
        self.db.execute("INSERT OR REPLACE INTO results(case_id,direction,family,query_status,payload) VALUES(?,?,?,?,?)", (case.case_id, case.direction, case.family, result["query_status"], json.dumps(result, ensure_ascii=False))); self.db.commit()
    def checkpoint(self, run_id, case_id, processed):
        self.db.execute("INSERT OR REPLACE INTO checkpoints(run_id,last_case_id,processed,updated_at) VALUES(?,?,?,CURRENT_TIMESTAMP)", (run_id, case_id, processed)); self.db.commit()
    def resume(self, run_id):
        row=self.db.execute("SELECT last_case_id,processed FROM checkpoints WHERE run_id=?",(run_id,)).fetchone(); return row or (None,0)
    def close(self): self.db.close()
