import sqlite3
import json
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Union

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "rules.db"


@dataclass
class RuleRecord:
    title: str
    query_body: Dict[str, Any] #query
    source_path: str
    rule_type: str = "atomic"
    rule_id: Optional[str] = None
    level: Optional[str] = "unknown"
    rule_tags: List[str] = field(default_factory=list)
    lucene_query: Optional[str] = None
    group_fields: List[str] = field(default_factory=list)
    threshold_count: int = 1
    schema: str = "native"
    enabled: int = 0
    id: Optional[int] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "RuleRecord":
        # deserialize stored json fields into python objects
        query_body = json.loads(row["query_body"]) if row["query_body"] else {}
        rule_tags = json.loads(row["rule_tags"]) if row["rule_tags"] else []
        group_fields = json.loads(row["group_fields"]) if row["group_fields"] else []

        return cls(
            id=row["id"],
            rule_id=row["rule_id"],
            title=row["title"],
            rule_type=row["rule_type"],
            level=row["level"] or "unknown",
            source_path=row["source_path"],
            rule_tags=rule_tags,
            query_body=query_body,
            lucene_query=row["lucene_query"],
            group_fields=group_fields,
            threshold_count=row["threshold_count"] or 1,
            schema=row["schema"] or "native",
            enabled=row["enabled"],
        )

    def to_db_params(self) -> Dict[str, Any]:
        # prepare parameters for database insertion
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "rule_type": self.rule_type,
            "level": self.level,
            "source_path": self.source_path,
            "rule_tags": json.dumps(self.rule_tags, ensure_ascii=False),
            "query_body": json.dumps(self.query_body, ensure_ascii=False),
            "lucene_query": self.lucene_query,
            "group_fields": json.dumps(self.group_fields, ensure_ascii=False),
            "threshold_count": self.threshold_count,
            "schema": self.schema,
            "enabled": self.enabled,
        }


class RulesDB:
    def __init__(self, db_path: Union[str, Path] = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        # creates a connection and guarantees clean closure
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def init_db(self) -> None:
        # creates rules table and active index if not existing
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id TEXT,
                    title TEXT NOT NULL,
                    rule_type TEXT NOT NULL,
                    level TEXT,
                    source_path TEXT NOT NULL,
                    rule_tags TEXT,
                    query_body TEXT NOT NULL,
                    lucene_query TEXT,
                    group_fields TEXT,
                    threshold_count INTEGER DEFAULT 1,
                    schema TEXT DEFAULT 'native',
                    enabled INTEGER DEFAULT 0,
                    UNIQUE(title, source_path, schema)
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled);")
            conn.commit()

    def get_active_rules(self, schema: str = "native") -> List[RuleRecord]:
        # returns only active rules for the given schema
        query = "SELECT * FROM rules WHERE enabled = 1 AND schema = ? ORDER BY id ASC"
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (schema,))
            return [RuleRecord.from_row(row) for row in cursor.fetchall()]

    def upsert_rules(self, rules: List[RuleRecord], preserve_enabled: bool = True) -> int:
        # inserts or updates rules by unique composite key (title, source_path, schema)
        if not rules:
            return 0

        if preserve_enabled:
            sql = """
                INSERT INTO rules (
                    rule_id, title, rule_type, level, source_path, rule_tags,
                    query_body, lucene_query, group_fields, threshold_count,
                    schema, enabled
                ) VALUES (
                    :rule_id, :title, :rule_type, :level, :source_path, :rule_tags,
                    :query_body, :lucene_query, :group_fields, :threshold_count,
                    :schema, :enabled
                )
                ON CONFLICT(title, source_path, schema) DO UPDATE SET
                    rule_id = excluded.rule_id,
                    rule_type = excluded.rule_type,
                    level = excluded.level,
                    rule_tags = excluded.rule_tags,
                    query_body = excluded.query_body,
                    lucene_query = excluded.lucene_query,
                    group_fields = excluded.group_fields,
                    threshold_count = excluded.threshold_count;
            """
        else:
            sql = """
                INSERT INTO rules (
                    rule_id, title, rule_type, level, source_path, rule_tags,
                    query_body, lucene_query, group_fields, threshold_count,
                    schema, enabled
                ) VALUES (
                    :rule_id, :title, :rule_type, :level, :source_path, :rule_tags,
                    :query_body, :lucene_query, :group_fields, :threshold_count,
                    :schema, :enabled
                )
                ON CONFLICT(title, source_path, schema) DO UPDATE SET
                    rule_id = excluded.rule_id,
                    rule_type = excluded.rule_type,
                    level = excluded.level,
                    rule_tags = excluded.rule_tags,
                    query_body = excluded.query_body,
                    lucene_query = excluded.lucene_query,
                    group_fields = excluded.group_fields,
                    threshold_count = excluded.threshold_count,
                    enabled = excluded.enabled;
            """

        params = [r.to_db_params() for r in rules]
        with self._get_connection() as conn:
            conn.executemany(sql, params)
            conn.commit()

        return len(rules)

    # alias for backward compatibility
    upsert_rules_batch = upsert_rules

    def set_rule_status(self, rule_id: Optional[str] = None, schema: str = "native",
        row_id: Optional[int] = None, title: Optional[str] = None, enabled: int = 1,) -> bool:
        # precisely sets rule status by row_id, (rule_id, schema), or (title, schema)
        if enabled:
            val = 1
        else:
            val = 0
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if row_id is not None:
                cursor.execute("UPDATE rules SET enabled = ? WHERE id = ?", (val, row_id))
            elif rule_id is not None:
                cursor.execute("UPDATE rules SET enabled = ? WHERE rule_id = ? AND schema = ?", (val, rule_id, schema),)
            elif title is not None:
                cursor.execute("UPDATE rules SET enabled = ? WHERE title = ? AND schema = ?", (val, title, schema),)
            else:
                return False
            conn.commit()
            return cursor.rowcount > 0

    def get_stats(self, schema: Optional[str] = None) -> Dict[str, Any]:
        # returns count of total, active and inactive rules
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if schema:
                cursor.execute("SELECT COUNT(*) FROM rules WHERE schema = ?", (schema,))
                total = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM rules WHERE enabled = 1 AND schema = ?", (schema,))
                active = cursor.fetchone()[0]
            else:
                cursor.execute("SELECT COUNT(*) FROM rules")
                total = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM rules WHERE enabled = 1")
                active = cursor.fetchone()[0]

            return {"total_rules": total, "active_rules": active, "inactive_rules": total - active,}