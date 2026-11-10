from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import orjson

@dataclass
class Alert:
    rule_title: str
    alert_type: str = "atomic"
    time_window_start: Optional[str] = None
    time_window_end: Optional[str] = None
    rule_id: Optional[str] = None
    source_path: Optional[str] = None
    hostname: Optional[str] = None
    event_count: int = 1
    timestamp: Optional[str] = None
    group_key: Optional[Dict[str, Any]] = None
    rule_level: Optional[str] = None
    summary_data: Dict[str, Any] = field(default_factory=dict)
    description: Optional[str] = None
    rule_tags: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "alert_type": self.alert_type,
            "rule_title": self.rule_title,
            "event_count": self.event_count
        }
        d["rule_title"] = self.rule_title

        if self.rule_id:
            d["rule_id"] = self.rule_id
        if self.rule_level:
            d["rule_level"] = self.rule_level
        if self.source_path:
            d["source_path"] = self.source_path
        ts = self.time_window_end or self.timestamp
        if ts:
            d["@timestamp"] = ts

        if self.hostname:
            d["hostname"] = self.hostname

        if self.time_window_start:
            d["time_window_start"] = self.time_window_start
        if self.time_window_end:
            d["time_window_end"] = self.time_window_end

        if self.group_key:
            d["group_key"] = self.group_key
        if self.summary_data:
            d["summary_data"] = self.summary_data

        if self.description:
            d["description"] = self.description

        if self.rule_tags:
            d["rule_tags"] = self.rule_tags
        if self.extra:
            d["extra"] = self.extra

        return d

    def to_json(self) -> bytes:
        #append the line at the end of the returned output
        return orjson.dumps(self.to_dict(), option=orjson.OPT_APPEND_NEWLINE)