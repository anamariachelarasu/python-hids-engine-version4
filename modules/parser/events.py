#main purpose of this file is to parse the event using orjson and to print the fields 
import sys
from typing import Any, Dict, Iterator
from pathlib import Path
import time
import logging

log = logging.getLogger(__name__)

import orjson

def read_events(path: str | Path) -> Iterator[Dict[str, Any]]:
    path = Path(path)

    with open(path, "rb") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                event = orjson.loads(line)
            except orjson.JSONDecodeError as e:
                log.warning(f"{line_num} event: {e}")
                continue
            
            if not isinstance(event, dict):
                log.warning(f"{line_num} event: event not an object")
                continue
            yield event