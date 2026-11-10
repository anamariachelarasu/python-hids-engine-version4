import json
import time
from pathlib import Path
from modules.parser.rules import load_rules
from modules.parser.translator import translate_atomic_rule

def export_translated_rules(
    rules_dir: str = "rules/sigma",
    output_file: str = "data/translated_atomic_queries.json",
    timeframe: str = "now-15m"
):
    start = time.perf_counter()
    print(f"Loading rules from: {rules_dir} ...")
    loaded, errors = load_rules(rules_dir)
    print(f"Loaded: {len(loaded)} rules | Errors: {len(errors)}")

    results = []
    skipped = 0

    for i in range(len(loaded)):
        lr = loaded[i]
        query = translate_atomic_rule(lr.rule, timeframe=timeframe)
        if query is not None:
            results.append({
                "title": lr.rule.title,
                "id": str(lr.rule.id) if lr.rule.id else None,
                "level": lr.rule.level.name.lower() if lr.rule.level else "unknown",
                "source_path": lr.source_path,
                "query": query
            })
        else:
            skipped += 1

    out_path = Path(output_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "summary": {
            "total_loaded": len(loaded),
            "translated_count": len(results),
            "skipped_count": skipped,
            "timeframe": timeframe
        },
        "translated_rules": results
    }

    out_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    elapsed = time.perf_counter() - start
    print(f"Successfully exported {len(results)} translated rules to '{out_path.resolve()}'.")
    print(f"Skipped (no valid condition): {skipped}")
    print(f"Time taken: {elapsed:.2f}s")

if __name__ == "__main__":
    export_translated_rules()
