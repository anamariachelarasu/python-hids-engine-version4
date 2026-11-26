import json
import sys
import collections as C


def load(path, grouped):
    c = C.Counter()
    for line in open(path, encoding="utf-8"):
        a = json.loads(line)
        if a["alert_type"] != "atomic":
            continue
        #grouped alerts carry event_count; old per-event alerts count as 1 each
        c[a["rule_title"]] += (a.get("event_count") or 1) if grouped else 1
    return c


old = load(sys.argv[1], grouped=False)
new = load(sys.argv[2], grouped=True)

for title in sorted(set(old) | set(new)):
    if old[title] != new[title]:
        print(f"{old[title]:>5} -> {new[title]:>5}  {title}")
print("old total:", sum(old.values()), "| new total:", sum(new.values()))