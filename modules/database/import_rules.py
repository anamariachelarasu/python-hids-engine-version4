from pathlib import Path
from modules.parser.rules import load_rules
from modules.parser.correlation_rules import load_correlation_rules
from modules.parser.translator import translate_atomic_rule, translate_correlation_rule
from modules.database.rules_db import RulesDB, RuleRecord


def import_rules(rules_dir: str, schema: str = "native") -> int:
    db = RulesDB()
    records = []

    # step 1 -- atomic rules
    atomic, errors = load_rules(rules_dir)
    ref_map = {}  # alias (id / name / title / file stem) -> lucene query
    skipped = 0

    for lr in atomic:
        r = lr.rule
        body = translate_atomic_rule(r, timeframe="all", schema=schema)
        if body is None:
            skipped += 1
            continue

        lucene = body["query"]["bool"]["filter"][0]["query_string"]["query"]

        # same aliases as in main.py, so correlation references resolve the same way
        for alias in (r.id, getattr(r, "name", None), r.title, Path(lr.source_path).stem):
            if alias:
                ref_map[str(alias)] = lucene

        records.append(RuleRecord(
            title=r.title,
            query_body=body,
            source_path=str(lr.source_path),
            rule_type="atomic",
            rule_id=str(r.id) if r.id else Path(lr.source_path).stem,
            level=r.level.name.lower() if r.level else "unknown",
            rule_tags=[str(t) for t in getattr(r, "tags", [])],
            lucene_query=lucene,
            schema=schema,
            enabled=0,
        ))

    # step 2 -- correlation rules (need ref_map from step 1)
    corr_rules = load_correlation_rules(Path(rules_dir) / "correlation")
    corr_ok = 0

    for cr in corr_rules:
        ref_query = None
        for ref_item in (cr.rules or []):
            name = str(ref_item.reference)
            if name in ref_map:
                ref_query = ref_map[name]
                break

        if ref_query is None:
            print(f"warning: no referenced atomic rule found for '{cr.title}'")

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
        ))
        corr_ok += 1

    count = db.upsert_rules(records, preserve_enabled=True)
    print(f"imported: {count} (correlation: {corr_ok}) | atomic skipped: {skipped} | load errors: {len(errors)}")
    return count


if __name__ == "__main__":
    import sys
    import_rules(sys.argv[1], schema=sys.argv[2] if len(sys.argv) > 2 else "native")
    print(RulesDB().get_stats())