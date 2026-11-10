from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule
import json

@dataclass
class LoadedRule:
    rule: SigmaRule
    asts: List[Any]
    source_path: str

def compile_rule(rule: SigmaRule, source_path: str = "") -> LoadedRule:
    asts = [cond.parsed for cond in rule.detection.parsed_condition]
    return LoadedRule(rule=rule, asts=asts, source_path=source_path)

def load_rules(directory: str | Path) -> Tuple[List[LoadedRule], List[Tuple[str, str]]]:
    loaded: List[LoadedRule] = []
    errors: List[Tuple[str, str]] = []

    root = Path(directory)
    if not root.exists():
        return loaded, errors

    if root.is_file():
        paths = [root]
    else:
        paths = sorted(list(root.rglob("*.yml")) + list(root.rglob("*.yaml")))

    for i in range(len(paths)):
        path = paths[i]
        try:
            text = path.read_text(encoding="utf-8")
            collection = SigmaCollection.from_yaml(text, resolve_references=False)
            for rule in collection.rules:
                #if jump over the correlated rules (the ones that do not have detection)
                if isinstance(rule, SigmaRule):
                    loaded.append(compile_rule(rule, str(path)))
        except Exception as e:
            errors.append((str(path), f"{type(e).__name__}: {e}"))

    return loaded, errors

