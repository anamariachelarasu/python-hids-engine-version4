import json
import time
from pathlib import Path
from typing import Any, Dict, List
from modules.parser.correlation_rules import load_correlation_rules
from modules.parser.translator import translate_correlation_rule, map_field

def export_translated_correlations(
    corr_dir: str = "rules/sigma/correlation",
    output_file: str = "data/translated_correlation_queries.json",
    timeframe: str = "now-15m"
):
    start = time.perf_counter()
    print(f"Loading correlation rules from: {corr_dir} ...")
    rules = load_correlation_rules(corr_dir)
    print(f"Loaded: {len(rules)} correlation rules")

    results: List[Dict[str, Any]] = []

    for i in range(len(rules)):
        r = rules[i]
        
        # Query for all data (no timestamp constraint)
        query_all = translate_correlation_rule(r, timeframe="all")
        # Query with native timeframe from rule (e.g. now-5m)
        query_timespan = translate_correlation_rule(r, timeframe=None)

        # Extract rule references
        rule_refs: List[str] = []
        if r.rules:
            for j in range(len(r.rules)):
                rule_refs.append(str(r.rules[j].reference))

        # Extract group by fields and their ECS mappings
        group_fields = r.group_by or []
        group_by_mapping: Dict[str, str] = {}
        for k in range(len(group_fields)):
            f_orig = group_fields[k]
            group_by_mapping[f_orig] = map_field(f_orig)

        results.append({
            "title": r.title,
            "id": str(r.id) if r.id else None,
            "name": getattr(r, "name", None),
            "level": r.level.name.lower() if r.level else "high",
            "correlation_type": r.type.name.lower() if hasattr(r.type, "name") else str(r.type),
            "timespan": str(r.timespan.spec) if r.timespan else "5m",
            "threshold_count": int(r.condition.count) if r.condition and r.condition.count else 1,
            "rule_references": rule_refs,
            "group_by": group_fields,
            "group_by_ecs_mapping": group_by_mapping,
            "source_path": getattr(r, "source_path", None),
            "query": query_all,
            "query_with_timespan": query_timespan
        })

    out_path = Path(output_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "summary": {
            "total_loaded": len(rules),
            "translated_count": len(results),
            "timeframe_exported": timeframe
        },
        "translated_correlation_rules": results
    }

    out_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    elapsed = time.perf_counter() - start
    print(f"Successfully exported {len(results)} translated correlation rules to '{out_path.resolve()}'.")
    print(f"Time taken: {elapsed:.2f}s")

if __name__ == "__main__":
    export_translated_correlations()
