from dataclasses import dataclass, field
from typing import List
from pathlib import Path
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule

def load_correlation_rules(directory: str|Path) -> List[SigmaCorrelationRule]:
    rules: List[SigmaCorrelationRule] = []
    root = Path(directory)

    if not root.exists():
        return rules

    #collect candidate yaml files
    files: List[Path] = []
    if root.is_file():
        files.append(root)
    else:
        for ext in ("*.yml", "*.yaml"):
            for p in root.rglob(ext):
                files.append(p)
    files.sort()

    #imperative loop for each file
    for i in range(len(files)):
        curr_path = files[i]
        try:
            raw_text = curr_path.read_text(encoding="utf-8")

            #do not resolve references immediately to avoid failure on missing bare rules
            collection = SigmaCollection.from_yaml(raw_text, resolve_references=False)

            for j in range(len(collection.rules)):
                rule_obj = collection.rules[j]
                if isinstance(rule_obj, SigmaCorrelationRule):
                    rule_obj.source_path = str(curr_path)
                    rules.append(rule_obj)
        except Exception:
            #ignore files that cannot be parsed
            continue
    return rules
        