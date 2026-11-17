import copy
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.opensearch.opensearch import OpenSearchConnector
from modules.parser.alerts import Alert
from modules.parser.config import load_config
from modules.database.rules_db import RuleRecord, RulesDB


#builds an atomic alert from a hit returned by opensearch
def make_atomic_alert(rule: RuleRecord, source: Dict[str, Any]) -> Alert:
    ts = (source.get("@timestamp") or source.get("EventTime") or source.get("UtcTime") or source.get("TimeCreated"))

    host = (source.get("Hostname") or source.get("ComputerName"))
    if not host:
        val = source.get("host")
        if isinstance(val, dict):
            host = val.get("name")
        elif isinstance(val, str):
            host = val

    #extract the group_info for later for correlation
    user = source.get("TargetUserName") or source.get("UserName") or source.get("AccountName")
    group_info = {}
    if user:
        group_info["TargetUserName"] = user
    if host:
        group_info["Hostname"] = host

    return Alert(
        rule_title=rule.title,
        alert_type="atomic",
        rule_id=rule.rule_id,
        rule_level=rule.level,
        source_path=rule.source_path,
        timestamp=str(ts) if ts else None,
        hostname=host,
        group_key=group_info if group_info else None,
        rule_tags=rule.rule_tags,
    )


#builds a correlation alert from an aggregation bucket
def make_correlation_alert(rule: RuleRecord, bucket: Dict[str, Any]) -> Alert:
    keys = bucket.get("key", [])
    if not isinstance(keys, (list, tuple)):
        keys = [keys]

    group_info: Dict[str, Any] = {}
    for idx, field_name in enumerate(rule.group_fields):
        if idx < len(keys):
            group_info[field_name] = keys[idx]

    host = (
        group_info.get("Hostname")
        or group_info.get("ComputerName")
        or group_info.get("host.name")
        or group_info.get("host")
    )

    event_count = int(bucket.get("doc_count", 0))
    return Alert(
        rule_title=rule.title,
        alert_type="correlation",
        rule_id=rule.rule_id,
        rule_level=rule.level,
        source_path=rule.source_path,
        event_count=event_count,
        group_key=group_info,
        hostname=str(host) if host else None,
        description=getattr(rule, "description", None),
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        rule_tags=rule.rule_tags,
    )


#the stored query has no time filter, so it is added here at run time
def query(rule: RuleRecord, timeframe: str = "all") -> Dict[str, Any]:
    #deepcopy so the record is not modified between runs
    body = copy.deepcopy(rule.query_body)
    if timeframe and timeframe.lower() != "all":
        filters = body.setdefault("query", {}).setdefault("bool", {}).setdefault("filter", [])
        filters.append({"range": {"@timestamp": {"gte": timeframe, "lte": "now"}}})
    return body


def main(output_dir: str | Path,
         events_index: str = "windows-events",
         timeframe: str = "all",
         schema: str = "native",
         use_opensearch: bool = False,
         ingest_file_path: Optional[str | Path] = None,
         rule_limit: Optional[int] = None,
         workers: int = 10,
         db_path: Optional[str | Path] = None,
        ):
    start = time.perf_counter()

    #step 1 -- load the active rules from the database (no yaml loading, no translation)
    db = RulesDB(db_path) if db_path else RulesDB()
    active_rules = db.get_active_rules(schema=schema)
    atomic_rules = [r for r in active_rules if r.rule_type == "atomic"]
    correlation_rules = [r for r in active_rules if r.rule_type == "correlation"]
    print(f"active rules loaded: {len(active_rules)} (atomic: {len(atomic_rules)}, correlation: {len(correlation_rules)}) | schema: {schema}")

    #nothing to run, so we exit before connecting to opensearch
    if not active_rules:
        print("no active rules in the database (enabled = 1). exiting.")
        return

    if rule_limit is not None and rule_limit < len(atomic_rules):
        atomic_rules = atomic_rules[:rule_limit]
        print(f"Limiting execution to first {rule_limit} atomic rules.")

    #step 2 -- load opensearch configuration from config.json
    cfg = load_config()
    enable_os = use_opensearch or cfg.enabled
    os_connector: Optional[OpenSearchConnector] = None
    os_online = False

    if enable_os:
        os_connector = (OpenSearchConnector(url=cfg.url, index_name=cfg.alerts_index, username=cfg.username,password=cfg.password, bearer_token=cfg.bearer_token, pool_size=max(50, workers*2), ))

        if os_connector.ping():
            os_online  = True
            os_connector.init_index()
            print(f"Connected to OpenSearch ({cfg.url}) | Alert Index: {cfg.alerts_index}")
        else:
            print(f"Warning: Opensearch doesn't respond.")

    #abort execution if opensearch is disabled or unreachable
    if not os_online or os_connector is None:
        print("Requirement unsatisfied: an active opensearch connection")
        if os_connector is not None:
            os_connector.close()
        return

    #step 3 -- ingest raw events file if requested
    if ingest_file_path and os_connector:
        p = Path(ingest_file_path)
        ingest = os_connector.ingest_file(events_index, p)
        print(f"ingested {ingest} events into {events_index}")
        #useful for allowing opensearch to refresh
        time.sleep(1)

    #output file, with a timestamp for each run
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    run_timestamp = time.strftime("%Y%m%d_%H%M%S")
    output_file = out_dir / f"alerts_{run_timestamp}.jsonl"

    alerts_count = 0
    atomic_alerts_count = 0
    corr_alerts_count = 0
    rules_queried = 0
    rules_failed = 0

    #step 4 -- for each active rule --> query opensearch in parallel and emit alerts
    def execute_search(rule: RuleRecord, query_body: Dict[str, Any]) -> Tuple[RuleRecord, Optional[Dict[str, Any]], Optional[Exception]]:
        #worker performs pure network i/o against opensearch
        try:
            resp = os_connector.search(events_index, query_body)
            return rule, resp, None
        except Exception as e:
            return rule, None, e

    with open(output_file, "wb") as out:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            #atomic rules (the time filter is added here)
            atomic_futures = [executor.submit(execute_search, r, query(r, timeframe)) for r in atomic_rules]

            for f in as_completed(atomic_futures):
                rule, resp, err = f.result()
                if err is not None or resp is None:
                    rules_failed += 1
                    print(f"failed: {rule.title} | {str(err)[:150]}")
                    continue
                rules_queried += 1

                hits = resp.get("hits", {}).get("hits", [])
                for hit in hits:
                    source = hit.get("_source", {})
                    alert = make_atomic_alert(rule, source)
                    atomic_alerts_count += 1
                    alerts_count += 1

                    out.write(alert.to_json())
                    os_connector.buffer_alert(alert.to_dict())

            # flush atomic alerts buffer before starting correlation queries
            os_connector.flush()

            #correlation rules
            corr_futures = [executor.submit(execute_search, r, query(r, timeframe)) for r in correlation_rules]

            for f in as_completed(corr_futures):
                rule, resp, err = f.result()
                if err is not None or resp is None:
                    rules_failed += 1
                    print(f"failed: {rule.title} | {str(err)[:150]}")
                    continue
                rules_queried += 1

                min_limit = rule.threshold_count or 1
                agg_data = resp.get("aggregations", {}).get("correlation_buckets", {})

                # handle both grouped aggregations ('buckets') and ungrouped value_count ('value')
                if "buckets" in agg_data:
                    buckets = agg_data["buckets"]
                elif "value" in agg_data and int(agg_data["value"]) >= min_limit:
                    buckets = [{"key": [], "doc_count": int(agg_data["value"])}]
                else:
                    buckets = []

                for b in buckets:
                    corr_alert = make_correlation_alert(rule, b)
                    corr_alerts_count += 1
                    alerts_count += 1

                    out.write(corr_alert.to_json())
                    os_connector.buffer_alert(corr_alert.to_dict())

            # flush remaining correlation alerts
            os_connector.flush()
    os_connector.close()

    elapsed = time.perf_counter() - start
    print("======================================================")
    print(f"rules_queried = {rules_queried}")
    print(f"rules_failed = {rules_failed}")
    print(f"atomic_alerts_count = {atomic_alerts_count}")
    print(f"correlated_alerts = {corr_alerts_count}")
    print(f"alerts_count = {alerts_count}")
    print(f"time = {elapsed:.2f}s")
    print("======================================================")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="hids detection engine")
    parser.add_argument("output_dir", help="path to alerts directory")
    parser.add_argument("--opensearch", action="store_true", help="activates the alert export in opensearch( settings read in config.json)")
    parser.add_argument("--events-index", default="windows-events", help="OpenSearch index with log events (default: windows-events)")
    parser.add_argument("--timeframe", default="all", help="Timeframe filter: 'all', 'now-15m', 'now-24h', etc.")
    parser.add_argument("--ingest-file", default=None, help="Path to .jsonl file to ingest into events index first")
    parser.add_argument("--limit", type=int, default=None, help="limit number of atomic rules to run")
    parser.add_argument("--schema", choices=["native", "ecs"], default="native")
    parser.add_argument("--workers", type=int, default=4, help="number of parallel query workers (default: 4)")
    parser.add_argument("--db-path", default=None, help="path to sqlite rules database (default: data/rules.db)")

    args = parser.parse_args()

    main(output_dir=args.output_dir,
         events_index=args.events_index,
         timeframe=args.timeframe,
         schema=args.schema,
         use_opensearch=args.opensearch,
         ingest_file_path=args.ingest_file,
         rule_limit=args.limit,
         workers=args.workers,
         db_path=args.db_path,
         )