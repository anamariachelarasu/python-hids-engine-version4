import logging
from typing import Any, Dict, List, Optional, Iterator
from modules.parser.events import read_events
import orjson
import requests
from requests.auth import HTTPBasicAuth

import queue
from concurrent.futures import ThreadPoolExecutor

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

#https://docs.opensearch.org/latest/mappings/
HIDS_ALERTS_MAPPING = {
    "mappings": {
        "properties": {
            "@timestamp": {"type": "date"},
            "alert_type": {"type": "keyword"},
            "rule_title": {"type": "keyword"},
            "rule_id": {"type": "keyword"},
            "rule_level": {"type": "keyword"},
            "source_path": {"type": "keyword"},
            "hostname": {"type": "keyword"},
            "rule_tags": {"type": "keyword"},
            "description": {"type": "text"},
            "event_count": {"type": "integer"},
            "time_window_start": {"type": "date"},
            "time_window_end": {"type": "date"},
            "group_key": {
                "type": "object",
                "dynamic": True
            },
            "summary_data": {
                "type": "object",
                "dynamic": True
            }
        }
    },
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0
    }
}

#connectivity check and opensearch node identification    -- ping
class OpenSearchConnector:
    def __init__(self, url: str = "http://localhost:9200", index_name: str = "hids-alerts", username: Optional[str] = None,
                 password: Optional[str] = None, bearer_token: Optional[str] = None, client_cert: Optional[str] = None,
                 client_key: Optional[str] = None, verify_ssl: bool = False, timeout: int = 60):
        
        self.url = url.rstrip("/")
        self.index_name = index_name
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = verify_ssl

        if bearer_token:
            self.session.headers.update({"Authorization": f"Bearer {bearer_token}"})
        elif username and password:
            self.session.auth = HTTPBasicAuth(username, password)

        if client_cert and client_key:
            self.session.cert = (client_cert, client_key)

        self.session.headers.update({"Content-Type": "application/json"})
        self.buffer: List[Dict[str, Any]] = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def close(self):
        self.flush()
        self.session.close()

    def ping(self) -> bool:
        try:
            res = self.session.get(f"{self.url}/", timeout=self.timeout)
            if res.status_code == 200:
                log.info("Connected to OpenSearch.")
                return True
            return False
        except requests.RequestException:
            return False

    #open a PIT point in time 
    #POST /{index_pattern}/_search/point_in_time?keep_alive={keep_alive}
    def open_pit(self, index_pattern:str, keep_alive: str="2m") -> Optional[str]:
        url = f"{self.url}/{index_pattern}/_search/point_in_time?keep_alive={keep_alive}"
        try:
            res = self.session.post(url, timeout=self.timeout)
            if res.status_code == 200:
                data = res.json()
                pit_id = data.get("pit_id")
                return pit_id
            else:
                log.error(f"error: opensearch pit CREATE on: POST {self.url}/{index_pattern}/_search/point_in_time?keep_alive={keep_alive} : {res.text}")
                return None
        except requests.RequestException as e:
            log.error(f"error: opensearch pit OPEN on: POST {self.url}/{index_pattern}/_search/point_in_time?keep_alive={keep_alive} : {e}")
            return None

    #close a pit for freeing data resources from opensearch cluster
    def close_pit(self, pit_id: str) -> bool:
        url = f"{self.url}/_search/point_in_time"
        try:
            res = self.session.delete(url, data = orjson.dumps({"pit_id": [pit_id]}), timeout=self.timeout)
            return res.status_code == 200
        
        except requests.RequestException as e:
            log.error(f"error: opensearch pit CLOSE: {pit_id} : {e}")
            return False

    #alert index needs to exists before writing in it, having my mapping
    def init_index(self) -> bool:
        try:
            head = self.session.head(f"{self.url}/{self.index_name}", timeout=self.timeout)
            #returns 200 if the index exists, 404 if not
            if head.status_code == 200:
                return True
            #if index doesn't exists PUT /{index} having HIDS_ELRTS_MAPPING as body
            res = self.session.put(f"{self.url}/{self.index_name}", data=orjson.dumps(HIDS_ALERTS_MAPPING), timeout=self.timeout,)
            return res.status_code in (200, 201)
        except requests.RequestException as e:
            log.warning(f"init_index failed: {e}")
            return False

    #append the alert in the list and checks if the list is full
    #returns number of successfully sent alerts
    def buffer_alert(self, alert_dict: Dict[str, Any], batch_size: int = 100) -> int:
        self.buffer.append(alert_dict)
        if len(self.buffer) >= batch_size:
            return self.flush()
        return 0

    def flush(self) -> int:
        #empty buffer
        if not self.buffer:
            return 0

        #build the NDJSON body --> doing this because _bulk doen't accept a normal JSON
        action_header = orjson.dumps({"index": {"_index": self.index_name}})
        lines: List[bytes] = []
        for alert in self.buffer:
            lines.append(action_header)
            lines.append(orjson.dumps(alert))

        #adds \newline between lines and at the end of request you need to add the newline, otherwise _bulk rejects the request
        bulk_data = b"\n".join(lines) + b"\n"

        #we send the request
        count = len(self.buffer)
        try:
            #we overwrite the ({"Content-Type": "application/json"})
            res = self.session.post(f"{self.url}/_bulk", data=bulk_data, headers={"Content-Type": "application/x-ndjson"}, timeout=self.timeout,)
        except requests.RequestException as e:
            log.error(f"flush: network error, buffer has {count} alerts: {e}")
            return 0

        if res.status_code != 200:
            log.error(f"flush: received from _bulk {res.status_code} : {res.text}")
            return 0

        #check the answer we receive
        #_bulk returns HTTP 200 even if some documents failed. 200 means only that the "request was processed"
        #individual errors are in the response
        resp = res.json()
        #if its true
        if resp.get("errors"):
            #count how many error we have
            failed = [it for it in resp["items"] if it["index"].get("error")]
            log.warning(f"{len(failed)}/{count} documents failed. First document to fail: {failed[0]['index']['error']}")
            ok = count - len(failed)
        else:
            ok = count

        self.buffer.clear()
        return ok

    def query_events(self, index_pattern: str="winlogbeat-*", query: Optional[Dict[str, Any]] = None, size: int = 500,
                     num_slices: int = 2, max_workers: Optional[int] = None, keep_alive: str = "2m",) -> Iterator[Dict[str, Any]]:
        pit_id = self.open_pit(index_pattern, keep_alive=keep_alive)
        if not pit_id:
            log.error(f"Could not open PIT for {index_pattern}")
            return

        search_query = query or {"match_all": {}}

        #the reason i i have chosen to use a queue instead of a dedicated broker like Redis or rabbitmq is because i still have a local dataset (my data isn't coming from more agents)
        #and a queue guarantees me a minimal latency     
        out_queue: queue.Queue = queue.Queue(maxsize=size*num_slices*2)
        sentinel = object()

        #produces --> every thread request from opensearch pages and puts the documentsin the queue
        def _fetch_slice(slice_id: int):
            search_after = None

            try:
                while True:
                    body = {
                        "size": size,
                        "query": search_query,
                        "pit": {"id": pit_id, "keep_alive": keep_alive},
                        "sort": [{"_id": "asc"}],
                    }

                    #if we have more slices
                    if num_slices > 1:
                        body["slice"] = {"id": slice_id, "max": num_slices}

                    #if we have only one slice
                    if search_after is not None:
                        body["search_after"] = search_after
    
                    res = self.session.post(f"{self.url}/_search", data=orjson.dumps(body), timeout=60)
    
                    if res.status_code != 200:
                        log.error(f"slice {slice_id}: {res.status_code} - {res.text}")
                        break

                    hits = res.json()["hits"]["hits"]
                    if not hits:
                        break
    
                    for hit in hits:
                        out_queue.put(hit["_source"])
    
                    search_after = hits[-1]["sort"]
            except requests.RequestException as e:
                log.error(f"slice {slice_id}: {e}")
            except Exception as e:
                log.exception(f"_fetch_slice unknown exception: {e}")
            finally:
                out_queue.put(sentinel)

        #the orchestrator --> 
        executor = ThreadPoolExecutor(max_workers=max_workers or num_slices)
        try:
            for sid in range(num_slices):
                executor.submit(_fetch_slice, sid)

            done = 0
            while done < num_slices:
                item = out_queue.get()

                if item is sentinel:
                    done += 1
                else:
                    yield item
        finally:
            executor.shutdown(wait=True)
            self.close_pit(pit_id)

    #POST /{index}/_search
    #sends the generated query and receives hits(for atomic rules) and aggregations(for correlation rules)
    def search(self, index_name: str, query_body: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        url = f"{self.url}/{index_name}/_search"
        try:
            res = self.session.post(url, data=orjson.dumps(query_body), timeout=self.timeout)
            if res.status_code == 200:
                return res.json()
            else:
                log.error(f"Search failed on {index_name} (HTTP {res.status_code}): {res.text}")
                return None
        except requests.RequestException as e:
            log.error(f"Search network error on {index_name}: {e}")
            return None

    #POST {self.url}/_bulk
    #loads through _bulk a local dataset file in event index in opensearch (windows-events for example)
    def ingest_file(self, index_name: str, file_path: Any, batch_size: int = 500) -> int:
        header = orjson.dumps({"index": {"_index": index_name}})
        lines: List[bytes] = []
        total = 0

        for event in read_events(file_path):
            lines.append(header)
            lines.append(orjson.dumps(event))

            if len(lines) >= batch_size * 2:
                bulk_data = b"\n".join(lines) + b"\n"

                try: 
                    self.session.post(f"{self.url}/_bulk", data=bulk_data, headers={"Content-Type": "application/x-ndjson"}, timeout=self.timeout)
                    total += len(lines) // 2
                except Exception as e:
                    log.error(f"Ingest batch failed: {e}")
                lines.clear()
            if lines:
                bulk_data = b"\n".join(lines) + b"\n"
                try:
                    self.session.post(f"{self.url}/_bulk", data=bulk_data, headers={"Content-Type": "application/x-ndjson"}, timeout=self.timeout)
                    total += len(lines) // 2
                except Exception as e:
                    log.error(f"Ingest batch failed: {e}")
                lines.clear()
        return total
