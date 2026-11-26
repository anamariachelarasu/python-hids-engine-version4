import io
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from modules.database.rules_db import RuleRecord
from modules.parser.main import run_window


class FakeOS:
    #minimal stand-in for OpenSearchConnector: every search returns one group above the threshold,
    #as if admin@WIN-DC01 kept having 5 failed logons in the lookback window
    def __init__(self):
        self.bodies = []
        self.buffered = []

    def search(self, index, body):
        self.bodies.append(body)
        return {"aggregations": {"correlation_buckets": {
            "buckets": [{"key": ["admin", "WIN-DC01"], "doc_count": 5}]}}}

    def buffer_alert(self, alert_dict):
        self.buffered.append(alert_dict)

    def flush(self):
        return 0


rule = RuleRecord(
    title="Multiple Failed Logons",
    query_body={"size": 0, "query": {"bool": {"filter": []}}, "aggs": {}},
    source_path="correlation/test.yml",
    rule_type="correlation",
    rule_id="r1",
    level="high",
    group_fields=["TargetUserName", "Hostname"],
    threshold_count=5,
    timespan_seconds=300,  # 5 minutes
)

os_fake = FakeOS()
cooldowns = {}
executor = ThreadPoolExecutor(max_workers=1)
start = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)

#seven consecutive 1-minute scheduler windows
for i in range(7):
    window = ("@timestamp", start + timedelta(minutes=i), start + timedelta(minutes=i + 1))
    stats, ok = run_window(os_fake, "windows-events", executor, [], [rule], window, io.BytesIO(), cooldowns)
    print(f"window {i + 1}: alerts={stats['corr']} suppressed={stats['suppressed']}")

#the range filter of the first query shows the lookback (5 minutes, not 1)
rng = os_fake.bodies[0]["query"]["bool"]["filter"][-1]["range"]["@timestamp"]
print("first query range:", rng)

executor.shutdown()