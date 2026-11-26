import sqlite3
import json
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Union, Tuple

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
    timespan_seconds: Optional[int] = None

    #my decision as an admin if the rule is active (= 1) or inactive (= 0)
    enabled: int = 0

    logsource_category: Optional[str] = None
    logsource_service: Optional[str] = None
    target_channels: List[str] = field(default_factory=list)
    target_event_ids: List[int] = field(default_factory=list)
    target_source: str = "unknown"
    ref_rules: List[str] = field(default_factory=list)

    id: Optional[int] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "RuleRecord":
        keys = row.keys()
        # deserialize stored json fields into python objects
        query_body = json.loads(row["query_body"]) if row["query_body"] else {}
        rule_tags = json.loads(row["rule_tags"]) if row["rule_tags"] else []
        group_fields = json.loads(row["group_fields"]) if row["group_fields"] else []
        target_channels = (json.loads(row["target_channels"]) if "target_channels" in keys and row["target_channels"] else [])
        target_event_ids = (json.loads(row["target_event_ids"]) if "target_event_ids" in keys and row["target_event_ids"] else [])
        logsource_category = (row["logsource_category"] if "logsource_category" in keys else None)
        logsource_service = (row["logsource_service"] if "logsource_service" in keys else None)
        target_source = (row["target_source"] if "target_source" in keys and row["target_source"] else "unknown")
        ref_rules = (json.loads(row["ref_rules"]) if "ref_rules" in keys and row["ref_rules"] else [])
        timespan_seconds = (row["timespan_seconds"] if "timespan_seconds" in keys else None)
        
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
            logsource_service=logsource_service,
            logsource_category=logsource_category,
            target_channels=target_channels,
            target_event_ids=target_event_ids,
            target_source=target_source,
            ref_rules=ref_rules,
            timespan_seconds = timespan_seconds,
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
            "logsource_category": self.logsource_category,
            "logsource_service": self.logsource_service,
            "target_channels": json.dumps(self.target_channels, ensure_ascii=False),
            "target_event_ids": json.dumps(self.target_event_ids, ensure_ascii=False),
            "target_source": self.target_source,
            "ref_rules": json.dumps(self.ref_rules, ensure_ascii=False),
            "timespan_seconds": self.timespan_seconds,
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
                    logsource_category TEXT,
                    logsource_service TEXT,
                    target_channels TEXT,
                    target_event_ids TEXT,
                    target_source TEXT DEFAULT 'unknown',
                    ref_rules TEXT,
                    timespan_seconds INTEGER,
                    UNIQUE(title, source_path, schema)
                );
                """
            )

            # migrate existing database tables by adding missing columns
            cursor = conn.execute("PRAGMA table_info(rules);")
            existing_cols = {row["name"] for row in cursor.fetchall()}

            migrations = [
                ("logsource_category", "TEXT"),
                ("logsource_service", "TEXT"),
                ("target_channels", "TEXT"),
                ("target_event_ids", "TEXT"),
                ("target_source", "TEXT DEFAULT 'unknown'"),
                ("ref_rules", "TEXT"),
                ("timespan_seconds", "INTEGER"),
            ]
            for col_name, col_def in migrations:
                if col_name not in existing_cols:
                    conn.execute(f"ALTER TABLE rules ADD COLUMN {col_name} {col_def};")

            conn.execute("CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled);")
            conn.commit()

    def get_all_rules(self, schema: Optional[str] = None) -> List[RuleRecord]:
        # return all rules for profiling or inspection, optionally filtered by schema
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if schema:
                cursor.execute("SELECT * FROM rules WHERE schema = ? ORDER BY id ASC", (schema,))
            else:
                cursor.execute("SELECT * FROM rules ORDER BY id ASC")
            return [RuleRecord.from_row(row) for row in cursor.fetchall()]

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
                INSERT INTO rules (rule_id, title, rule_type, level, source_path, rule_tags, query_body, lucene_query, group_fields, threshold_count, schema, enabled, 
                                logsource_category, logsource_service, target_channels, target_event_ids, target_source, ref_rules, timespan_seconds) 
                VALUES (:rule_id, :title, :rule_type, :level, :source_path, :rule_tags, :query_body, :lucene_query, :group_fields, :threshold_count,
                        :schema, :enabled, :logsource_category, :logsource_service, :target_channels, :target_event_ids, :target_source, :ref_rules, :timespan_seconds)
                ON CONFLICT(title, source_path, schema) DO UPDATE SET
                    rule_id = excluded.rule_id,
                    rule_type = excluded.rule_type,
                    level = excluded.level,
                    rule_tags = excluded.rule_tags,
                    query_body = excluded.query_body,
                    lucene_query = excluded.lucene_query,
                    group_fields = excluded.group_fields,
                    threshold_count = excluded.threshold_count,
                    logsource_category = excluded.logsource_category,
                    logsource_service = excluded.logsource_service,
                    target_channels = excluded.target_channels,
                    target_event_ids = excluded.target_event_ids,
                    target_source = excluded.target_source,
                    ref_rules = excluded.ref_rules,
                    timespan_seconds = excluded.timespan_seconds;
            """
        else:
            sql = """
                INSERT INTO rules (rule_id, title, rule_type, level, source_path, rule_tags, query_body, lucene_query, group_fields, threshold_count,
                                   schema, enabled, logsource_category, logsource_service, target_channels, target_event_ids, target_source, ref_rules, timespan_seconds)
                VALUES (:rule_id, :title, :rule_type, :level, :source_path, :rule_tags, :query_body, :lucene_query, :group_fields, :threshold_count,
                    :schema, :enabled, :logsource_category, :logsource_service, :target_channels, :target_event_ids, :target_source, :ref_rules, :timespan_seconds)
                ON CONFLICT(title, source_path, schema) DO UPDATE SET
                    rule_id = excluded.rule_id,
                    rule_type = excluded.rule_type,
                    level = excluded.level,
                    rule_tags = excluded.rule_tags,
                    query_body = excluded.query_body,
                    lucene_query = excluded.lucene_query,
                    group_fields = excluded.group_fields,
                    threshold_count = excluded.threshold_count,
                    enabled = excluded.enabled,
                    logsource_category = excluded.logsource_category,
                    logsource_service = excluded.logsource_service,
                    target_channels = excluded.target_channels,
                    target_event_ids = excluded.target_event_ids,
                    target_source = excluded.target_source,
                    ref_rules = excluded.ref_rules,
                    timespan_seconds = excluded.timespan_seconds;
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


            return {
                "total_rules": total,
                "active_rules": active,
                "inactive_rules": total - active,
                }