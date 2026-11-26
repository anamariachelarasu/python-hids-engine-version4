from pathlib import Path
from modules.parser.rules import load_rules
from modules.parser.correlation_rules import load_correlation_rules
from modules.parser.translator import translate_atomic_rule, translate_correlation_rule
from modules.database.rules_db import RulesDB, RuleRecord
from modules.parser.logsource_mapping import extract_target_metadata
from typing import Optional
import re

_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}

#converts the sigma timespan (ex 5m) to seconds
def timespan_to_seconds(cr) -> Optional[int]:
    ts = getattr(cr, "timespan", None)
    if ts is None:
        return None
    
    #pysigma computes .seconds itself; the manual parse below is only a fallback
    secs = getattr(ts, "seconds", None)
    if isinstance(secs, (int, float)) and secs > 0:
        return int(secs)
    m = re.fullmatch(r"\s*(\d+)\s*([smhdw])\s*", str(getattr(ts, "spec", ts)))
    return int(m.group(1)) * _UNITS[m.group(2)] if m else None
    


def import_rules(rules_dir: str, schema: str = "native") -> int:
    db = RulesDB()
    records = []

    # step 1 -- atomic rules
    atomic, errors = load_rules(rules_dir)
    ref_map = {}  # alias (id / name / title / file stem) -> lucene query
    skipped = 0

    for lr in atomic:
        r = lr.rule
        meta = extract_target_metadata(r)
        body = translate_atomic_rule(r, timeframe="all", schema=schema)
        if body is None:
            skipped += 1
            continue

        lucene = body["query"]["bool"]["filter"][0]["query_string"]["query"]

        # same aliases as in main.py, so correlation references resolve the same way
        for alias in (r.id, getattr(r, "name", None), r.title, Path(lr.source_path).stem):
            if alias:
                ref_map[str(alias).strip().lower()] = lucene

        records.append(RuleRecord(
            title=r.title,
            query_body=body,
            source_path=str(lr.source_path),
            rule_type="atomic",
            rule_id=str(r.id) if r.id else (getattr(r, "name", None) or Path(lr.source_path).stem),
            level=r.level.name.lower() if r.level else "unknown",
            rule_tags=[str(t) for t in getattr(r, "tags", [])],
            lucene_query=lucene,
            schema=schema,
            enabled=0,
            logsource_category=meta["logsource_category"],
            logsource_service=meta["logsource_service"],
            target_channels=meta["target_channels"],
            target_event_ids=meta["target_event_ids"],
            target_source=meta["target_source"],
            ref_rules=[],
        ))

    # step 2 -- correlation rules (need ref_map from step 1)
    corr_rules = load_correlation_rules(Path(rules_dir) / "correlation")
    corr_ok = 0

    for cr in corr_rules:
        ref_rules = []
        ref_queries = []

        for ref_item in (cr.rules or []):
            raw_name = str(getattr(ref_item, "reference", ref_item)).strip()
            if not raw_name:
                continue
            if raw_name not in ref_rules:
                ref_rules.append(raw_name)

            matched_q = ref_map.get(raw_name.lower())
            if matched_q and matched_q not in ref_queries:
                ref_queries.append(matched_q)

        # combine multiple referenced atomic queries with OR if needed
        if not ref_queries:
            ref_query = None
            print(f"warning: no referenced atomic rule found for '{cr.title}'")
        elif len(ref_queries) == 1:
            ref_query = ref_queries[0]
        else:
            ref_query = " OR ".join(f"({q})" for q in ref_queries)

        try:
            body = translate_correlation_rule(cr, ref_query=ref_query, timeframe="all", schema=schema)
        except Exception as e:
            print(f"correlation translation error ({cr.title}): {e}")
            continue

        records.append(RuleRecord(
            title=cr.title,
            query_body=body,
            # fallback, because correlation objects may not carry a source path
            source_path=str(getattr(cr, "source_path", None) or f"correlation/{cr.title}"),
            rule_type="correlation",
            rule_id=str(cr.id) if cr.id else cr.title,
            level=cr.level.name.lower() if getattr(cr, "level", None) else "high",
            rule_tags=[str(t) for t in getattr(cr, "tags", [])],
            lucene_query=ref_query,
            group_fields=list(cr.group_by or []),
            threshold_count=int(cr.condition.count) if (cr.condition and cr.condition.count is not None) else 1,
            schema=schema,
            enabled=0,
            target_source="correlation",
            ref_rules=ref_rules,
            timespan_seconds=timespan_to_seconds(cr),
        ))
        corr_ok += 1

    count = db.upsert_rules(records, preserve_enabled=True)
    print(f"imported: {count} (correlation: {corr_ok}) | atomic skipped: {skipped} | load errors: {len(errors)}")
    return count

if __name__ == "__main__":
    import sys
    import_rules(sys.argv[1], schema=sys.argv[2] if len(sys.argv) > 2 else "native")
    print(RulesDB().get_stats())