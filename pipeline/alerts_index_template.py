from elasticsearch import Elasticsearch

ES_HOST = "http://localhost:9200"

MAPPINGS = {
    "properties": {
        "@timestamp": {"type": "date"},
        "rule.name": {"type": "keyword"},
        "severity": {"type": "keyword"},
        "severity_rank": {"type": "integer"},
        "source.ip": {"type": "ip"},
        "source.is_internal": {"type": "boolean"},
        "description": {"type": "text"},
        "mitre.technique": {"type": "keyword"},
        "mitre.tactic": {"type": "keyword"},
        "status": {"type": "keyword"},
        "match_count": {"type": "integer"},
        "failure_count": {"type": "integer"},
        "distinct_ports_scanned": {"type": "integer"},
        "failed_login_attempts": {"type": "integer"},
        "matched_log_source": {"type": "keyword"},
        "ioc.source_feeds": {"type": "keyword"},
        "ioc.type": {"type": "keyword"},
        "ioc.corroborated": {"type": "boolean"},
    }
}


def register_template(es_client):
    template_body = {
        "index_patterns": ["siem-alerts-*"],
        "template": {"mappings": MAPPINGS},
        "priority": 200,
    }
    response = es_client.indices.put_index_template(
        name="siem-alerts-template",
        body=template_body,
    )
    return response


if __name__ == "__main__":
    client = Elasticsearch(ES_HOST)
    result = register_template(client)
    print("Alerts template registered:", result)