import copy
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, List
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.opensearch.opensearch import OpenSearchConnector
from modules.parser.alerts import Alert
from modules.parser.config import load_config
from modules.database.rules_db import RuleRecord, RulesDB
from modules.parser.checkpoint import load_checkpoint, save_checkpoint
from datetime import datetime, timezone, timedelta

#utc datetime -> iso string in ms
def to_iso(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

#iso string -> timezone-aware utc datetime 
def parse_ts(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

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

#host, user and timestamp are extracted in one place
def extract_fields(source: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
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
    return ts, host, user

def save_parse(value: Any) -> Optional[datetime]:
    try:
        return parse_ts(str(value))
    except (ValueError, TypeError):
        return None

def make_atomic_alerts_grouped(rule: RuleRecord, hits: List[Dict[str, Any]]) -> List[Alert]:
    groups: Dict[Tuple[Optional[str], Optional[str], Dict[str, Any]]] = {}
    
    for hit in hits:
        ts, host, user = extract_fields(hit.get("_source", {}))
        g = groups.setdefault((host, user), {"count": 0, "first": None, "last": None, "ids": []})
        g["count"] += 1
        #we add the first 10 ids in for guidance
        if len(g["ids"]) < 10:
            g["ids"].append(hit.get("_id"))
        dt = save_parse(ts) if ts else None
        if dt:
            if g["first"] is None or dt < g["first"]:
                g["first"] = dt
            if g["last"] is None or dt > g["last"]:
                g["last"] = dt
        
    alerts: List[Alert] = []
    for (host, user), g in groups.items():
        group_info: Dict[str, Any] = {}
        if user:
            group_info["TargetUserName"] = user
        if host:
            group_info["Hostname"] = host
    
        alerts.append(Alert(
            rule_title=rule.title,
            alert_type="atomic",
            rule_id=rule.rule_id,
            rule_level=rule.level,
            source_path=rule.source_path,
            timestamp=to_iso(g["last"]) if g["last"] else None,
            hostname=host,
            group_key=group_info if group_info else None,
            rule_tags=rule.rule_tags,
            event_count=g["count"],
            time_window_start=to_iso(g["first"]) if g["first"] else None,
            time_window_end=to_iso(g["last"]) if g["last"] else None,
            summary_data={"sample_event_ids": g["ids"]},
        ))
    return alerts

#builds a correlation alert from an aggregation bucket
def make_correlation_alert(rule: RuleRecord, bucket: Dict[str, Any], time_window_start: Optional[str] = None, time_window_end: Optional[str] = None,) -> Alert:
    keys = bucket.get("key", [])
    if not isinstance(keys, (list, tuple)):
        keys = [keys]

    group_info: Dict[str, Any] = {}
    for idx, field_name in enumerate(rule.group_fields):
        if idx < len(keys):
            group_info[field_name] = keys[idx]

    host = (group_info.get("Hostname") or group_info.get("ComputerName") or group_info.get("host.name") or group_info.get("host"))

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
        time_window_start=time_window_start,
        time_window_end=time_window_end,
        rule_tags=rule.rule_tags,
    )

#how far back a correlation must look
def loopback_seconds(rule: RuleRecord, window: Tuple[str, datetime, datetime]) ->int:
    _, start, end = window
    scheduler_window = int((end-start).total_seconds())
    #return its own timespan but never less than the scheduler window
    return max(rule.timespan_seconds or 0, scheduler_window)

#the window used for a correlation rule: [end - lookback, end)
def correlation_windows(rule: RuleRecord, window: Tuple[str, datetime, datetime]) -> int:
    time_field, _, end = window
    return (time_field, end - timedelta(seconds=loopback_seconds(rule, window)), end)


#the stored query has no time filter, so it is added here at run time
def query(rule: RuleRecord, window: Optional[Tuple[str, datetime, datetime]] = None) -> Dict[str, Any]:
    #deepcopy so the record is not modified between runs
    body = copy.deepcopy(rule.query_body)
    if window:
        time_field, start, end = window
        filters = body.setdefault("query", {}).setdefault("bool", {}).setdefault("filter", [])
        filters.append({
            "range": {
                time_field: {
                    "gte": to_iso(start),
                    "lt": to_iso(end)
                }
            }
        })
    return body

def execute_search(os_connector: OpenSearchConnector, events_index: str, rule: RuleRecord, query_body: Dict[str, Any]) -> Tuple[RuleRecord, Optional[Dict[str, Any]], Optional[Exception]]:
    for attempt in range(2):    
        #worker performs pure network i/o against opensearch
        try:
            resp = os_connector.search(events_index, query_body)
            return rule, resp, None
        except Exception as e:
            if attempt == 1:
                return rule, None, e
            time.sleep(0.5) #break before attempting again

#evaluates all given rules on one time window: returns (stats, ok)
def run_window(os_connector: OpenSearchConnector, events_index: str, executor: ThreadPoolExecutor, atomic_rules: List[RuleRecord], correlation_rules: List[RuleRecord],
               window: Tuple[str, datetime, datetime], out, cooldown: Dict[str, datetime]) -> Tuple[Dict[str, int], bool]:
    stats = {"queried": 0, "failed": 0, "atomic": 0, "corr": 0, "suppressed": 0}

    #atomic rules (the time filter is added here)
    atomic_futures = [executor.submit(execute_search, os_connector, events_index, r, query(r, window)) for r in atomic_rules]

    for f in as_completed(atomic_futures):
        rule, resp, err = f.result()
        if err is not None or resp is None:
            stats["failed"] += 1
            print(f"failed: {rule.title} | {str(err)[:150]}")
            continue
        stats["queried"] += 1
        hits = resp.get("hits", {}).get("hits", [])

        '''
        #for make_atomic_alert()
        for hit in hits:
            source = hit.get("_source", {})
            alert = make_atomic_alert(rule, source)
            stats["atomic"] += 1
            out.write(alert.to_json())
            os_connector.buffer_alert(alert.to_dict())
        '''
        #for make_atomic_alert_grouped()
        for alert in make_atomic_alerts_grouped(rule, hits):
            stats["atomic"] += 1
            out.write(alert.to_json())
            os_connector.buffer_alert(alert.to_dict())
        
    # flush atomic alerts buffer before starting correlation queries
    os_connector.flush()

    #correlation rules
    w_end = window[2] #end

    expired_keys = []
    for k, expires in cooldown.items():
        if expires <= w_end:
            expired_keys.append(k)

    for k in expired_keys:
        del cooldown[k]

    corr_futures = [executor.submit(execute_search, os_connector, events_index, r, query(r, correlation_windows(r, window))) for r in correlation_rules]

    for f in as_completed(corr_futures):
        rule, resp, err = f.result()
        if err is not None or resp is None:
            stats["failed"] += 1
            print(f"failed: {rule.title} | {str(err)[:150]}")
            continue
        stats["queried"] += 1

        min_limit = rule.threshold_count or 1
        agg_data = resp.get("aggregations", {}).get("correlation_buckets", {})

        # handle both grouped aggregations ('buckets') and ungrouped value_count ('value')
        if "buckets" in agg_data:
            buckets = agg_data["buckets"]
        elif "value" in agg_data and int(agg_data["value"]) >= min_limit:
            buckets = [{"key": [], "doc_count": int(agg_data["value"])}]
        else:
            buckets = []

        lookback = loopback_seconds(rule, window)

        for b in buckets:
            corr_alert = make_correlation_alert(rule, b, time_window_start=window[1], time_window_end=window[2])

            #the same group stays above the threshold on the next ticks (the lookback windows overlap)
            #so it is alerted once and then silenced until its events leave the lookback window
            rule_identifier = rule.rule_id if rule.rule_id else rule.title
            group_items = []
            if corr_alert.group_key:
                for k, v in corr_alert.group_key.items():
                    group_items.append((k, str(v)))
            group_items.sort()
            key = (rule_identifier, tuple(group_items))    
            
            expires = cooldown.get(key)
            if expires is not None and w_end < expires:
                stats["suppressed"] += 1
                continue
            cooldown[key] = w_end + timedelta(seconds=lookback)

            
            stats["corr"] += 1
            out.write(corr_alert.to_json())
            os_connector.buffer_alert(corr_alert.to_dict())

    # flush remaining correlation alerts
    os_connector.flush()

    if stats["queried"] == 0 and stats["failed"] > 0:
        ok = False
    else:
        ok = True
    return stats, ok

def main(output_dir: str | Path,
         events_index: str = "windows-events",
         schema: str = "native",
         interval: int = 60,
         lag: int = 5,
         start_from: str = "now",
         checkpoint_path: str | Path = "data/checkpoint.json",
         time_field: str = "@timestamp",
         once: bool = False,
         use_opensearch: bool = False,
         ingest_file_path: Optional[str | Path] = None,
         rule_limit: Optional[int] = None,
         workers: int = 10,
         db_path: Optional[str | Path] = None,
        ):
    step = timedelta(seconds=interval)
    lag_delta = timedelta(seconds=lag)
    db = RulesDB(db_path) if db_path else RulesDB()

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
            print("Warning: Opensearch doesn't respond.")

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

    cursor = load_checkpoint(checkpoint_path)
    if cursor is None:
        if start_from.lower() == "now":
            cursor = datetime.now(timezone.utc) - lag_delta
        else:
            cursor = parse_ts(start_from)

        save_checkpoint(cursor, checkpoint_path)
        print(f"no checkpoint found, starting from {to_iso(cursor)}")
    else:
        print(f"resuming from checkpoint {to_iso(cursor)}")

    #output file, with a timestamp for each run
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    run_timestamp = time.strftime("%Y%m%d_%H%M%S")
    output_path = out_dir / f"alerts_{run_timestamp}.jsonl"

    executor = ThreadPoolExecutor(max_workers=workers)
    cooldowns: Dict[Tuple, datetime] = {}

    #step 4 -- scheduler loop
    try:
        while True:
            #events newer than (low-lag) are not processed yet
            h = datetime.now(timezone.utc) - lag_delta

            #rules are reloaded every tick, so enabling/disabling a rule takes effect without a restart
            active_rules = db.get_active_rules(schema=schema)

            atomic_rules = []
            correlation_rules = []

            for r in active_rules:
                if r.rule_type == "atomic":
                    atomic_rules.append(r)
                elif r.rule_type == "correlation":
                    correlation_rules.append(r)

            if rule_limit is not None:
                atomic_rules = atomic_rules[:rule_limit]
            ok = True

            with open(output_path, "ab") as out:
            #catch-up: process every complete window between the checkpoint and the horizon, in order
                while cursor + step <= h:
                    window = (time_field, cursor, cursor + step)
                    t0 = time.perf_counter()

                    stats, ok = run_window(os_connector, events_index, executor, atomic_rules, correlation_rules, window, out, cooldowns)

                    if not ok:
                        print(f"window [{to_iso(window[1])}, {to_iso(window[2])}) not processed (opensearch unreachable?), will retry")
                        break

                    #the checkpoint moves only after the window was fully processed and its alerts were flushed
                    cursor = cursor + step
                    save_checkpoint(cursor, checkpoint_path)
                    print(f"[{to_iso(window[1])} -> {to_iso(window[2])}) rules={stats['queried']} failed={stats['failed']} "
                          f"atomic_alerts={stats['atomic']} correlated_alerts={stats['corr']} time={time.perf_counter() - t0:.2f}s")
            if once:
                break

            if not ok:
                #back off a little, so an outage does not turn into a busy loop
                time.sleep(min(30, interval))
                continue

            #sleep until the next window is complete
            due = cursor + step + lag_delta
            time.sleep(max(0.0, (due - datetime.now(timezone.utc)).total_seconds()))

    except KeyboardInterrupt:
        print("stopped by user")
    finally:
        executor.shutdown(wait=True)
        os_connector.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="hids detection engine")
    parser.add_argument("output_dir", help="path to alerts directory")
    parser.add_argument("--opensearch", action="store_true", help="activates the alert export in opensearch( settings read in config.json)")
    parser.add_argument("--events-index", default="windows-events", help="OpenSearch index with log events (default: windows-events)")
    parser.add_argument("--ingest-file", default=None, help="Path to .jsonl file to ingest into events index first")
    parser.add_argument("--limit", type=int, default=None, help="limit number of atomic rules to run")
    parser.add_argument("--schema", choices=["native", "ecs"], default="native")
    parser.add_argument("--workers", type=int, default=4, help="number of parallel query workers (default: 4)")
    parser.add_argument("--db-path", default=None, help="path to sqlite rules database (default: data/rules.db)")
    parser.add_argument("--interval", type=int, default=60, help="window size and schedule period in seconds")
    parser.add_argument("--lag", type=int, default=5, help="safety delay in seconds: window end at (now-lag)")
    parser.add_argument("--checkpoint", default="data/checkpoint.json", help="path to the checkpoint file")
    parser.add_argument("--time-field", default="@timestamp", help="field used for the time window")
    parser.add_argument("--once", action="store_true", help="process all pending windows once and exit")

    #one time used
    parser.add_argument("--start-from", default="now", help="only used when there is no checkpoint")

    args = parser.parse_args()

    main(output_dir=args.output_dir,
         events_index=args.events_index,
         schema=args.schema,
         interval=args.interval,
         lag=args.lag,
         start_from=args.start_from,
         checkpoint_path=args.checkpoint,
         time_field=args.time_field,
         once=args.once,
         use_opensearch=args.opensearch,
         ingest_file_path=args.ingest_file,
         rule_limit=args.limit,
         workers=args.workers,
         db_path=args.db_path,
         )