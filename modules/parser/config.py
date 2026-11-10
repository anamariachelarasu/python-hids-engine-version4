from dataclasses import dataclass
from pathlib import Path
import json
from typing import Optional

@dataclass
class OpenSearchConfig:
    enabled: bool = False
    url: str = "http://localhost:9200"
    alerts_index: str = "hids-alerts"
    username: Optional[str] = None
    password: Optional[str] = None
    bearer_token: Optional[str] = None
    input_index: Optional[str] = None
    slices: int = 2

def load_config() -> OpenSearchConfig:
    config_file = Path(__file__).resolve().parent / "config.json"
    if config_file.is_file():
        try:
            raw = json.loads(config_file.read_text(encoding="utf-8"))
            os_data = raw.get("opensearch", {})
            return OpenSearchConfig(enabled=os_data.get("enabled", False),
                                    url=os_data.get("url", "http://localhost:9200"),
                                    alerts_index=os_data.get("alerts_index", "hids-alerts"),
                                    username=os_data.get("username"),
                                    password=os_data.get("password"),
                                    bearer_token=os_data.get("bearer_token"),
                                    input_index=os_data.get("input_index"),
                                    slices=os_data.get("slices",2),
                                    )
        except Exception:
            pass
    return OpenSearchConfig()