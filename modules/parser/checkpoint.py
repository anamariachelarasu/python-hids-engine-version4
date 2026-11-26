import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

CHECKPOINT = Path("data/checkpoint.json")

#returns the last processed boundary (everything before it is done)
#no checkpoint --> None
def load_checkpoint(path: str | Path = CHECKPOINT) -> Optional[datetime]:
    p = Path(path)
    if not p.is_file():
        return None
    try:
        text = p.read_text(encoding="utf-8")
        data = json.loads(text)
        return datetime.fromisoformat(data["last_processed_to"])
    except (ValueError, KeyError) as e:
        #a corrupted checkpoint must not silently reset the position, because the events will be lost
        raise ValueError(f"checkpoint file {p} is corrupted: {e}") from e

def save_checkpoint(ts: datetime, path: str | Path = CHECKPOINT) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps({"last_processed_to": ts.astimezone(timezone.utc).isoformat()}), encoding="utf-8")
    os.replace(tmp, p)
    