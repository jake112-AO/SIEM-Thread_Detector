import hashlib
import json

from elasticsearch import Elasticsearch
from datetime import datetime, timezone
from elasticsearch.helpers import bulk

ES_HOST = "http://localhost:9200"

def make_event_id(event: dict) -> str:
    """
    Creates a stable, repeatable ID from an event's content, so sending
    the same event twice (e.g. after re-processing a log line) updates
    the same document instead of creating a duplicate.
    """
    event_str = json.dumps(event, sort_keys=True)
    return hashlib.sha256(event_str.encode()).hexdigest()

def get_client():
    return Elasticsearch(ES_HOST)

def send_event(es_client, event: dict):
    log_source = event.get("log_source", "unknown")
    date_str = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    index_name = f"siem-parsed-{log_source}-{date_str}"

    response = es_client.index(index=index_name, id=make_event_id(event), document=event)
    return response

def send_events_bulk(es_client, events: list[dict], batch_size: int = 500):
    def generate_actions():
        for event in events:
            log_source = event.get("log_source", "unknown")
            date_str = datetime.now(timezone.utc).strftime("%Y.%m.%d")
            index_name = f"siem-parsed-{log_source}-{date_str}"
            yield {
                "_index": index_name,
                "_id": make_event_id(event),
                "_source": event,
            }

    success_count, errors = bulk(es_client, generate_actions(), chunk_size=batch_size, raise_on_error=False)
    return success_count, errors

if __name__ == "__main__":
    client = get_client()
    print("Connected:", client.info()["cluster_name"])

    test_event = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "log_source": "auth",
        "event": {"outcome": "success", "action": "ssh_login"},
        "user": {"name": "test_connection"},
        "source": {"ip": "127.0.0.1"},
    }
    result = send_event(client, test_event)
    print("Indexed:", result["result"], "into", result["_index"])
