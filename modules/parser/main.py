import time
from pathlib import Path
from typing import Any, Dict, Optional, List, Tuple
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from sigma.correlations import SigmaCorrelationRule
from modules.opensearch.opensearch import OpenSearchConnector
from modules.parser.alerts import Alert
from modules.parser.rules import LoadedRule, load_rules
from modules.parser.config import load_config
from modules.parser.translator import translate_atomic_rule, translate_correlation_rule
from modules.parser.correlation_rules import load_correlation_rules

#builds an atomic alert from a hit returned by opensearch
def make_atomic_alert(lr: LoadedRule, source: Dict[str, Any]) -> Alert:
    r = lr.rule
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
        rule_title=r.title,
        alert_type="atomic",
        rule_id=str(r.id) if r.id else None,
        rule_level=r.level.name.lower() if r.level else "unknown",
        source_path=r.source,
        timestamp=str(ts) if ts else None,
        hostname=host,
        group_key=group_info if group_info else None,
        rule_tags=[str(t) for t in getattr(r, "tags", [])],
    )

def make_correlation_alert(
    corr_rule: SigmaCorrelationRule, 
    bucket: Dict[str, Any], 
    group_fields: List[str]
) -> Alert:
    keys = bucket.get("key", [])
    if not isinstance(keys, (list, tuple)):
        keys = [keys]

    group_info: Dict[str, Any] = {}
    for idx, field_name in enumerate(group_fields):
        if idx < len(keys):
            group_info[field_name] = keys[idx]

    host = (
        group_info.get("Hostname") 
        or group_info.get("ComputerName") 
        or group_info.get("host.name")
        or group_info.get("host")
    )

    event_count = int(bucket.get("doc_count", 0))
    rule_level = corr_rule.level.name.lower() if getattr(corr_rule, "level", None) else "high"

    return Alert(
        rule_title=corr_rule.title,
        alert_type="correlation",
        rule_id=str(corr_rule.id) if corr_rule.id else None,
        rule_level=rule_level,
        source_path=getattr(corr_rule, "source_path", None),
        event_count=event_count,
        group_key=group_info,
        hostname=str(host) if host else None,
        description=getattr(corr_rule, "description", None),
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        rule_tags=[str(t) for t in getattr(corr_rule, "tags", [])],
    )

def main(rules_dir: str | Path, 
         output_dir: str | Path, 
         events_index: str = "windows-events", 
         timeframe: str = "all",
         schema: str = "native",
         use_opensearch: bool = False,
         ingest_file_path: Optional[str | Path] = None,
         rule_limit: Optional[int] = None,
         workers: int = 10,
        ):
    corr_rules_dir = Path(rules_dir) / "correlation"
    correlation_rules = load_correlation_rules(corr_rules_dir)
    print(f"correlation rules loaded: {len(correlation_rules)}.")

    start = time.perf_counter()

    #step 1 -- load opensearch configuration from config.json
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

    
    #step 2 -- ingest raw events file if requested
    if ingest_file_path and os_connector:
        p = Path(ingest_file_path)
        ingest = os_connector.ingest_file(events_index, p)
        print(f"ingested {ingest} events into {events_index}")
        #useful for allowing opensearch to refresh
        time.sleep(1)
    
    #step 3 - load the rules and build the router
    atomic_rules, errors = load_rules(rules_dir)
    print(f"atomic rules loaded: {len(atomic_rules)} | errors: {len(errors)}")
    num_to_run = len(atomic_rules)
    if rule_limit is not None and rule_limit < num_to_run:
        num_to_run = rule_limit
        print(f"Limiting execution to first {num_to_run} rules.")

    
    #output file, with a timestamp for each run
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    run_timestamp = time.strftime("%Y%m%d_%H%M%S")
    output_file = out_dir / f"alerts_{run_timestamp}.jsonl" 

    alerts_count = 0
    atomic_alerts_count = 0
    rules_queried = 0
    rules_skipped = 0
    rules_failed = 0
    corr_alerts_count = 0

    #step 4 -- pretranslate all rules on the main thread (keeps pySigma single-threaded and avoids double conversion)
    rule_query_map: Dict[str, str] = {}
    prepared_atomic: List[Tuple[LoadedRule, Dict[str, Any]]] = []

    for idx, lr in enumerate(atomic_rules):
        r = lr.rule
        query_body = translate_atomic_rule(r, timeframe=timeframe, schema=schema)

        if query_body is None:
            if idx < num_to_run:
                rules_skipped += 1
            continue

        # extract the compiled lucene query string for correlation rule lookups
        q_str = query_body["query"]["bool"]["filter"][0]["query_string"]["query"]
        if r.id:
            rule_query_map[str(r.id)] = q_str
        if getattr(r, "name", None):
            rule_query_map[str(r.name)] = q_str
        rule_query_map[r.title] = q_str
        rule_query_map[Path(lr.source_path).stem] = q_str

        # queue only up to rule_limit for execution
        if idx < num_to_run:
            prepared_atomic.append((lr, query_body))
    
    #pretranslate correlation rules using the populated rule_query_map
    prepared_corr: List[Tuple[SigmaCorrelationRule, Dict[str, Any]]] = []
    for cr in correlation_rules:
        ref_query = None
        if cr.rules:
            for ref_item in cr.rules:
                ref_name = str(ref_item.reference)
                if ref_name in rule_query_map:
                    ref_query = rule_query_map[ref_name]
                    break
        try:
            corr_query_body = translate_correlation_rule(corr_rule=cr, ref_query=ref_query, timeframe=timeframe, schema=schema,)
            prepared_corr.append((cr, corr_query_body))
        except Exception as e:
            print(f"correlation translation error ({cr.title}): {e}")

    #step 5 -- for each rule --> query opensearch in parallel and emit alerts
    def execute_search(rule_obj: Any, query_body: Dict[str, Any]) -> Tuple[Any, Optional[Dict[str, Any]], Optional[Exception]]:
        #worker performs pure network i/o against opensearch
        try:
            resp = os_connector.search(events_index, query_body)
            return rule_obj, resp, None
        except Exception as e:
            title = getattr(getattr(rule_obj, "rule", rule_obj), "title", "unknown")
            print(f"{title} failed: query_len={len(str(query_body))}")
            return rule_obj, None, e

    with open(output_file, "wb") as out:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            #atomic rules
            atomic_futures = [executor.submit(execute_search, lr, q_body) for lr, q_body in prepared_atomic]

            for f in as_completed(atomic_futures):
                lr, resp, err = f.result()
                if err is not None or resp is None:
                    rules_failed += 1
                    continue
                rules_queried += 1

                hits = resp.get("hits", {}).get("hits", [])
                for hit in hits:
                    source = hit.get("_source", {})
                    alert = make_atomic_alert(lr, source)
                    atomic_alerts_count += 1
                    alerts_count += 1

                    out.write(alert.to_json())
                    os_connector.buffer_alert(alert.to_dict())

            # flush atomic alerts buffer before starting correlation queries
            os_connector.flush()

            #correlation rules
            corr_futures = [executor.submit(execute_search, cr, q_body) for cr, q_body in prepared_corr]

            for f in as_completed(corr_futures):
                cr, resp, err = f.result()
                if err is not None or resp is None:
                    rules_failed += 1
                    continue

                min_limit = int(cr.condition.count) if (cr.condition and cr.condition.count is not None) else 1
                agg_data = resp.get("aggregations", {}).get("correlation_buckets", {})
                group_fields = cr.group_by or []

                # handle both grouped aggregations ('buckets') and ungrouped value_count ('value')
                if "buckets" in agg_data:
                    buckets = agg_data["buckets"]
                elif "value" in agg_data and int(agg_data["value"]) >= min_limit:
                    buckets = [{"key": [], "doc_count": int(agg_data["value"])}]
                else:
                    buckets = []

                for b in buckets:
                    corr_alert = make_correlation_alert(cr, b, group_fields)
                    corr_alerts_count += 1
                    alerts_count += 1

                    #print(f" correlation detected: {corr_alert.rule_title} | group: {corr_alert.group_key} | trigger count: {corr_alert.event_count} (limit: >= {min_limit})")

                    out.write(corr_alert.to_json())
                    os_connector.buffer_alert(corr_alert.to_dict())

            # flush remaining correlation alerts
            os_connector.flush()
    os_connector.close()



    ok = time.perf_counter() - start
    print("======================================================")
    print(f"rules_queried = {rules_queried}")
    print(f"rules_skipped = {rules_skipped}")
    print(f"atomic_alerts_count = {atomic_alerts_count}")
    print(f"correlated_alerts = {corr_alerts_count}")
    print(f"alerts_count = {alerts_count}")
    print(f"time = {ok}")
    print("======================================================")
 
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="hids detection engine")
    parser.add_argument("rules_dir", help="path to rules directory")
    parser.add_argument("output_dir", help="path to alerts directory")
    parser.add_argument("--opensearch", action="store_true", help="activates the alert export in opensearch( settings read in config.json)")
    parser.add_argument("--events-index", default="windows-events", help="OpenSearch index with log events (default: windows-events)")
    parser.add_argument("--timeframe", default="all", help="Timeframe filter: 'all', 'now-15m', 'now-24h', etc.")
    parser.add_argument("--ingest-file", default=None, help="Path to .jsonl file to ingest into events index first")
    parser.add_argument("--limit", type=int, default=None, help="limit number of rules to run")
    parser.add_argument("--schema", choices=["native", "ecs"], default="native")
    parser.add_argument("--workers", type=int, default=4, help="number of parallel query workers (default: 10)")

    args = parser.parse_args()

    main(rules_dir=args.rules_dir, 
         output_dir=args.output_dir, 
         events_index=args.events_index, 
         timeframe=args.timeframe,
         schema=args.schema,
         use_opensearch=args.opensearch, 
         ingest_file_path=args.ingest_file,
         rule_limit=args.limit,
         workers=args.workers
         )