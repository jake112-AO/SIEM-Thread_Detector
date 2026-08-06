from elasticsearch import Elasticsearch
from datetime import datetime, timezone

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
