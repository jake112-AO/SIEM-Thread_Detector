from elasticsearch import Elasticsearch

ES_HOST = "http://localhost:9200"

# This defines the exact type for each field we know we'll use across
# all 3 parsers. Anything not listed here, Elasticsearch still guesses
# on its own - we only need to be explicit about the fields where
# guessing wrong would actually hurt us (IPs, ports, dates).
MAPPINGS = {
    "properties": {
        "@timestamp": {"type": "date"},
        "log_source": {"type": "keyword"},
        "host": {
            "properties": {
                "name": {"type": "keyword"}
            }
        },
        "user": {
            "properties": {
                "name": {"type": "keyword"}
            }
        },
        "source": {
            "properties": {
                "ip": {"type": "ip"},
                "port": {"type": "integer"},
                "bytes": {"type": "long"},
            }
        },
        "destination": {
            "properties": {
                "ip": {"type": "ip"},
                "port": {"type": "integer"},
                "bytes": {"type": "long"},
            }
        },
        "event": {
            "properties": {
                "outcome": {"type": "keyword"},
                "action": {"type": "keyword"},
                "duration": {"type": "float"},
            }
        },
        "network": {
            "properties": {
                "transport": {"type": "keyword"},
                "protocol": {"type": "keyword"},
                "bytes": {"type": "long"},
            }
        },
        "process": {
            "properties": {
                "pid": {"type": "integer"}
            }
        },
        "rule": {
            "properties": {
                "name": {"type": "keyword"}
            }
        },
        "geo": {
            "properties": {
                "location": {"type": "geo_point"},
                "country_name": {"type": "keyword"},
                "city_name": {"type": "keyword"},
                "isp": {"type": "keyword"},
            }
        },
    }
}

def register_template(es_client):
    template_body = {
        "index_patterns": ["siem-parsed-*"],
        "template": {
            "mappings": MAPPINGS
        },
        "priority": 200,  # higher priority than Elastic's built-in defaults
    }
    response = es_client.indices.put_index_template(
        name="siem-parsed-template",
        body=template_body,
    )
    return response


if __name__ == "__main__":
    client = Elasticsearch(ES_HOST)
    result = register_template(client)
    print("Template registered:", result)
