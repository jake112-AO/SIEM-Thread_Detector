from elasticsearch import Elasticsearch
from datetime import datetime, timezone
from elasticsearch.helpers import bulk

ES_HOST = "http://localhost:9200"

def get_client():
    return Elasticsearch(ES_HOST)

def send_event(es_client, event: dict):
    """
    Sends one normalized ECS event into Elasticsearch, into an index
    named by log_source and today's date - matching the same naming
    pattern Logstash already uses (siem-<source>-YYYY.MM.dd), but with
    a "parsed" marker so it never collides with the raw Filebeat data.
    """
    log_source = event.get("log_source", "unknown")
    date_str = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    index_name = f"siem-parsed-{log_source}-{date_str}"

    response = es_client.index(index=index_name, document=event)
    return response

def send_events_bulk(es_client, events: list[dict], batch_size: int = 500):
    """
    Sends many events to Elasticsearch efficiently using the bulk API.
    Groups events by log_source + date into the right index automatically,
    same naming convention as send_event().
    """
    def generate_actions():
        for event in events:
            log_source = event.get("log_source", "unknown")
            date_str = datetime.now(timezone.utc).strftime("%Y.%m.%d")
            index_name = f"siem-parsed-{log_source}-{date_str}"
            yield {
                "_index": index_name,
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
