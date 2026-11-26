from modules.opensearch.opensearch import OpenSearchConnector
from typing import Any, Dict, List, Tuple, Set, Optional
from modules.database.rules_db import RuleRecord, RulesDB
from pathlib import Path
from modules.parser.config import load_config
import argparse

#query opensearch to extract all existing (channel, event_id) combinations
def fetch_available_telemetry(os_connector: OpenSearchConnector, events_index: str = "windows-events", schema: str = "native") -> Tuple[Set[Tuple[str, int]], Set[str], Set[int]]:
    if schema == "native":
        channel_candidates = ["Channel.keyword", "Channel"]
        event_id_field = "EventID"
    else:
        channel_candidates = ["winlog.channel.keyword","winlog.channel","Channel.keyword","Channel",]
        event_id_field = "winlog.event_id"

    buckets: List[Dict[str, Any]] = []
    for ch_field in channel_candidates:
        agg_query = {
            "size": 0,
            "aggs": {
                "by_channel": {
                    "terms": {
                        "field": ch_field,
                        "size": 50
                    },
                    "aggs": {
                        "by_event_id": {
                            "terms": {
                                "field": event_id_field,
                                "size": 100
                            }
                        }
                    },
                }
            },
        }

        try:
            resp = os_connector.search(events_index, agg_query)
            candidate_buckets = (resp.get("aggregations", {}).get("by_channel", {}).get("buckets", []))
            if candidate_buckets:
                buckets = candidate_buckets
                print(f"aggregated using channel='{ch_field}', event_id='{event_id_field}'")
                break
        except RuntimeError:
            # fallback to the next candidate field if opensearch rejects the mapping
            continue

    available_pairs: Set[Tuple[str, int]] = set()
    available_channels: Set[str] = set()
    available_event_ids: Set[int] = set()

    for ch_bucket in buckets:
        ch_name = str(ch_bucket.get("key", "")).strip()
        if not ch_name:
            continue
        available_channels.add(ch_name)

        eid_buckets = ch_bucket.get("by_event_id", {}).get("buckets", [])
        for eid_bucket in eid_buckets:
            raw_eid = eid_bucket.get("key")
            try:
                eid_int = int(str(raw_eid).strip())
                available_pairs.add((ch_name, eid_int))
                available_event_ids.add(eid_int)
            except (ValueError, TypeError):
                continue

    return available_pairs, available_channels, available_event_ids

def evaluate_atomic_compatibility(rule: RuleRecord, available_pairs: Set[Tuple[str, int]], available_channels: Set[str], available_event_ids: Set[int],) -> int:
    # determine if an atomic rule can match any telemetry present in opensearch
    src = (rule.target_source or "unknown").lower().strip()

    # fallback rules are never automatically disabled so we do not miss alerts
    if src == "unknown":
        return 1

    channels = rule.target_channels or []
    eids = rule.target_event_ids or []

    # priority 3 (service): any event id is valid as long as the channel exists
    if src == "service":
        if not channels:
            return 1
        return 1 if any(ch in available_channels for ch in channels) else 0

    # priority 1 (detection) and priority 2 (logsource): check exact (channel, event_id) pairs
    if channels and eids:
        for ch in channels:
            for eid in eids:
                if (ch, eid) in available_pairs:
                    return 1
        return 0

    # edge case: detection rule specified an event id without any inferred channel
    if not channels and eids:
        return 1 if any(eid in available_event_ids for eid in eids) else 0

    # edge case: rule specified channels without event ids
    if channels and not eids:
        return 1 if any(ch in available_channels for ch in channels) else 0

    return 1

def profile_rules(events_index: str = "windows-events", schema: str = "native", db_path: Optional[str | Path] = None, dry_run: bool = False,) -> None:
    # load opensearch settings and verify cluster connectivity
    cfg = load_config()
    os_connector = OpenSearchConnector(url=cfg.url, index_name=cfg.alerts_index, username=cfg.username, password=cfg.password, bearer_token=cfg.bearer_token,)

    if not os_connector.ping():
        print("error: cannot connect to opensearch. aborting profiling.")
        os_connector.close()
        return

    try:
        available_pairs, available_channels, available_event_ids = fetch_available_telemetry(os_connector, events_index=events_index, schema=schema)
    finally:
        os_connector.close()

    print(f"discovered {len(available_channels)} channels and {len(available_pairs)} unique (channel, event_id) pairs.")
    for ch, eid in sorted(available_pairs):
        print(f"   -> ({ch!r}, {eid})")

    # safety guard: prevent marking all rules incompatible if the index is empty
    if not available_pairs and not available_channels:
        print("warning: index appears empty or fields could not be resolved. no changes applied.")
        return

    # load all rules for the target schema from sqlite
    db = RulesDB(db_path) if db_path else RulesDB()
    all_rules = db.get_all_rules(schema=schema)

    atomic_rules = [r for r in all_rules if r.rule_type == "atomic"]
    correlation_rules = [r for r in all_rules if r.rule_type == "correlation"]

    # lookup map of lowercased atomic aliases (rule_id, title, file stem) -> compatible flag
    atomic_compat_map: Dict[str, int] = {}

    updates: List[Tuple[int, int]] = []
    changed_records: List[Tuple[RuleRecord, int]] = []

    compat_atomic = 0
    incompat_atomic = 0

    # step 1 -- evaluate atomic rules
    for r in atomic_rules:
        new_compat = evaluate_atomic_compatibility(
            r, available_pairs, available_channels, available_event_ids
        )
        if new_compat == 1:
            compat_atomic += 1
        else:
            incompat_atomic += 1

        # register aliases matching import_rules.py; if two rules share a title, 1 takes precedence
        aliases = [r.rule_id, r.title, Path(r.source_path).stem if r.source_path else None]
        for alias in aliases:
            if alias:
                key = str(alias).strip().lower()
                atomic_compat_map[key] = max(atomic_compat_map.get(key, 0), new_compat)

        if r.id is not None and r.compatible != new_compat:
            updates.append((new_compat, r.id))
            changed_records.append((r, new_compat))

    # step 2 -- propagate compatibility to correlation rules via ref_rules
    compat_corr = 0
    incompat_corr = 0

    for cr in correlation_rules:
        refs = cr.ref_rules or []
        if not refs:
            # keep unreferenced correlation rules compatible by default
            new_compat = 1
        else:
            # compatible if at least one referenced atomic rule is compatible
            any_ref_compat = any(
                atomic_compat_map.get(str(ref).strip().lower(), 0) == 1
                for ref in refs
            )
            new_compat = 1 if any_ref_compat else 0

        if new_compat == 1:
            compat_corr += 1
        else:
            incompat_corr += 1

        if cr.id is not None and cr.compatible != new_compat:
            updates.append((new_compat, cr.id))
            changed_records.append((cr, new_compat))

    print("\n======================================================")
    print(f"atomic rules : {compat_atomic} compatible | {incompat_atomic} incompatible")
    print(f"correlation rules : {compat_corr} compatible | {incompat_corr} incompatible")
    print(f"state transitions : {len(updates)} rules would change compatibility")
    print("======================================================")

    if dry_run:
        for rec, new_val in changed_records[:50]:
            print(
                f"[dry-run] [{rec.rule_type}] id={rec.id} | title='{rec.title}' | "
                f"source={rec.target_source} | compatible: {rec.compatible} -> {new_val}"
            )
        if len(changed_records) > 50:
            print(f"... and {len(changed_records) - 50} more changes.")
    else:
        db.update_compatibility_batch(updates)
        print(f"database updated successfully ({len(updates)} rows modified).")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="profile opensearch telemetry and update rule compatibility")
    parser.add_argument("--events-index", default="windows-events", help="opensearch index with log events (default: windows-events)",)
    parser.add_argument("--schema", choices=["native", "ecs"], default="native", help="field schema to profile (default: native)",)
    parser.add_argument("--db-path", default=None, help="path to sqlite rules database (default: data/rules.db)",)
    parser.add_argument("--dry-run", action="store_true", help="preview compatibility changes without modifying the database",)
    args = parser.parse_args()
    profile_rules(events_index=args.events_index, schema=args.schema, db_path=args.db_path, dry_run=args.dry_run,)