import time
from pathlib import Path
from typing import Any, Dict, Optional, Iterator
import argparse
from modules.opensearch.opensearch import OpenSearchConnector
from modules.parser.alerts import Alert
from modules.parser.rules import LoadedRule, load_rules
from modules.parser.config import load_config
from modules.parser.translator import translate_atomic_rule

#builds an atomic alert from a hit returneb by opensearch
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

    return Alert(
        rule_title=r.title,
        alert_type="atomic",
        rule_id=str(r.id) if r.id else None,
        rule_level=r.level.name.lower() if r.level else "unknown",
        source_path=r.source,
        timestamp=str(ts) if ts else None,
        hostname=host,
        rule_tags=[str(t) for t in getattr(r, "tags", [])],
    )

def main(rules_dir: str | Path, 
         output_dir: str | Path, 
         events_index: str = "windows-events", 
         timeframe: str = "all",
         schema: str = "native",
         use_opensearch: bool = False,
         ingest_file_path: Optional[str | Path] = None,
         rule_limit: Optional[int] = None
        ):
    start = time.perf_counter()

    #step 1 -- load opensearch configuration from config.json
    cfg = load_config()
    enable_os = use_opensearch or cfg.enabled
    os_connector: Optional[OpenSearchConnector] = None
    os_online = False

    if enable_os:
        os_connector = (OpenSearchConnector(url=cfg.url, index_name=cfg.alerts_index, username=cfg.username,password=cfg.password, bearer_token=cfg.bearer_token))

        if os_connector is not None:
            if os_connector.ping():
                os_online  = True
                os_connector.init_index()
                print(f"Connected to OpenSearch ({cfg.url}) | Alert Index: {cfg.alerts_index}")
            else:
                print(f"Warning: Opensearch doesn't respond.")

        if not os_online:
            print("Requirement unsatisfied: an active opensearch connection")
    
    #step 2 -- ingest raw events file if requested
    if ingest_file_path and os_connector:
        p = Path(ingest_file_path)
        ingest = os_connector.ingest_file(events_index, p)
        print(f"ingested {ingest} events into {events_index}")
        #useful for allowing opensearch to refresh
        time.sleep(1)

    #step 3 - load the rules and build the router
    loaded_rules, errors = load_rules(rules_dir)
    print(f"rules loaded: {len(loaded_rules)} | errors: {len(errors)}")
    num_to_run = len(loaded_rules)
    if rule_limit is not None and rule_limit < num_to_run:
        num_to_run = rule_limit
        print(f"Limiting execution to first {num_to_run} rules.")

    
    #output file, with a timestamp for each run
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    run_timestamp = time.strftime("%Y%m%d_%H%M%S")
    output_file = out_dir / f"alerts_{run_timestamp}.jsonl" 

    alerts_count = 0
    rules_queried = 0
    rules_skipped = 0

    #step 5 -- for each rule --> query opensearch and emit alerts
    with open(output_file, "wb") as out:
        for i in range(num_to_run):
            lr = loaded_rules[i]

            try:
                #translates sigma rule in opensearch query dsl
                query_body = translate_atomic_rule(lr.rule, timeframe=timeframe, schema=schema)
                if query_body is None:
                    rules_skipped += 1
                    continue
                rules_queried += 1

                #exectute search against opensearch
                resp = os_connector.search(events_index, query_body)
                if resp is None:
                    continue
            except Exception as e:
                print(f"ERROR: {e}")

            #process hits
            hits = resp.get("hits", {}).get("hits", [])
            for j in range(len(hits)):
                hit = hits[j]
                source = hit.get("_source", {})
                alert = make_atomic_alert(lr, source)
                alerts_count += 1
                level = (alert.rule_level or "unknown").upper()

                out.write(alert.to_json())
                os_connector.buffer_alert(alert.to_dict())
    
    #close connection
    if os_connector and os_online:
        os_connector.close()

    ok = time.perf_counter() - start
    print("======================================================")
    print(f"rules_queried = {rules_queried}")
    print(f"rules_skipped = {rules_skipped}")
    print(f"alerts_count = {alerts_count}")
    print(f"time = {ok}")
 
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="hids detection engine")
    parser.add_argument("rules_dir", help="path to rules directory")
    parser.add_argument("output_dir", help="path to alerts directory")
    parser.add_argument("--opensearch", "--os", action="store_true", help="activates the alert export in opensearch( settings read in config.json)")
    parser.add_argument("--events-index", default="windows-events", help="OpenSearch index with log events (default: windows-events)")
    parser.add_argument("--timeframe", default="all", help="Timeframe filter: 'all', 'now-15m', 'now-24h', etc.")
    parser.add_argument("--ingest-file", default=None, help="Path to .jsonl file to ingest into events index first")
    parser.add_argument("--limit", type=int, default=None, help="limit number of rules to run")
    parser.add_argument("--schema", choices=["native", "ecs"], default="native")


    args = parser.parse_args()

    main(rules_dir=args.rules_dir, 
         output_dir=args.output_dir, 
         events_index=args.events_index, 
         timeframe=args.timeframe,
         schema=args.schema,
         use_opensearch=args.opensearch, 
         ingest_file_path=args.ingest_file,
         rule_limit=args.limit
         )