import sqlite3
import hashlib
import json
import time
from typing import List, Dict, Optional
from src.config import DB_PATH

class OSINTStorage:
    def __init__(self):
        self.db_path = DB_PATH
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS raw_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hash TEXT UNIQUE,
                    url TEXT,
                    status INTEGER,
                    content TEXT,
                    target TEXT,
                    source TEXT,
                    timestamp REAL,
                    processed INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hash TEXT UNIQUE,
                    target TEXT,
                    type TEXT,
                    value TEXT,
                    context TEXT,
                    source_url TEXT,
                    timestamp REAL,
                    llm_analysis TEXT,
                    cvss_score REAL DEFAULT 0.0,
                    severity TEXT DEFAULT 'UNKNOWN'
                );

                CREATE INDEX IF NOT EXISTS idx_raw_target ON raw_results(target);
                CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
                CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(type);
            """)

    def _hash(self, content: str) -> str:
        return hashlib.sha256(content.encode()).hexdigest()

    def save_raw(self, result: Dict, target: str, source: str) -> bool:
        content_hash = self._hash(result.get("url", "") + result.get("content", ""))
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR IGNORE INTO raw_results
                    (hash, url, status, content, target, source, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    content_hash,
                    result.get("url", ""),
                    result.get("status", 0),
                    result.get("content", ""),
                    target,
                    source,
                    result.get("timestamp", time.time())
                ))
                return conn.total_changes > 0  # True si no era duplicado
        except sqlite3.Error as e:
            print(f"[DB ERROR] {e}")
            return False

    def save_finding(self, target: str, type: str, value: str,
                     context: str = "", source_url: str = "",
                     llm_analysis: Dict = None,
                     cvss_score: float = 0.0,
                     severity: str = "UNKNOWN") -> bool:
        content_hash = self._hash(target + type + value)
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR IGNORE INTO findings
                    (hash, target, type, value, context, source_url, timestamp, llm_analysis, cvss_score, severity)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    content_hash,
                    target,
                    type,
                    value,
                    context,
                    source_url,
                    time.time(),
                    json.dumps(llm_analysis or {}),
                    cvss_score,
                    severity
                ))
                return conn.total_changes > 0
        except sqlite3.Error as e:
            print(f"[DB ERROR] {e}")
            return False

    def get_unprocessed(self, limit: int = 50) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT * FROM raw_results
                WHERE processed = 0
                LIMIT ?
            """, (limit,)).fetchall()
            return [dict(r) for r in rows]

    def mark_processed(self, raw_id: int):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE raw_results SET processed = 1 WHERE id = ?", (raw_id,))

    def get_findings(self, target: str) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT * FROM findings WHERE target = ?
                ORDER BY cvss_score DESC
            """, (target,)).fetchall()
            return [dict(r) for r in rows]

    def stats(self, target: str) -> Dict:
        with sqlite3.connect(self.db_path) as conn:
            raw_count = conn.execute(
                "SELECT COUNT(*) FROM raw_results WHERE target = ?", (target,)
            ).fetchone()[0]
            findings_count = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE target = ?", (target,)
            ).fetchone()[0]
            duplicates = conn.execute(
                "SELECT COUNT(*) FROM raw_results WHERE target = ? AND processed = 0", (target,)
            ).fetchone()[0]
            return {
                "target": target,
                "raw_results": raw_count,
                "findings": findings_count,
                "pending_processing": duplicates
            }