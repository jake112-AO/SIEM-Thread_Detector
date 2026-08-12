import json
import time
from datetime import datetime, timezone, timedelta
from elasticsearch import Elasticsearch

ES_HOST = "http://localhost:9200"
COMPILED_RULES_FILE = "pipeline/compiled_rules.json"
POLL_INTERVAL_SECONDS = 60

# Map each rule to which index pattern it should search - based on the
# log_source each rule's query targets.
RULE_INDEX_MAP = {
    "auth": "siem-parsed-auth-*",
    "iptables": "siem-parsed-iptables-*",
    "zeek": "siem-parsed-zeek-*",
    "cicids": "siem-cicids-*",
}

def load_rules():
    with open(COMPILED_RULES_FILE) as f:
        return json.load(f)

def guess_index(query: str) -> str:
    for source, index in RULE_INDEX_MAP.items():
        if f"log_source:{source}" in query:
            return index
    return "siem-*"  # fallback, shouldn't normally hit this

def run_rule(client, rule_id, rule, since_time):
    index = guess_index(rule["query"])
    full_query = f"{rule['query']} AND @timestamp:[{since_time} TO now]"

    response = client.search(
        index=index,
        q=full_query,
        size=20,   # cap how many raw matching docs we pull back per run
    )

    total = response["hits"]["total"]["value"]
    if total > 0:
        print(f"🚨 [{rule['level'].upper()}] {rule['title']} — {total} matches in last {POLL_INTERVAL_SECONDS}s")
    return total


if __name__ == "__main__":
    client = Elasticsearch(ES_HOST)
    rules = load_rules()
    print(f"Loaded {len(rules)} rules. Polling every {POLL_INTERVAL_SECONDS}s. Ctrl+C to stop.")

    while True:
        since = (datetime.now(timezone.utc) - timedelta(seconds=POLL_INTERVAL_SECONDS)).isoformat()
        for rule_id, rule in rules.items():
            try:
                run_rule(client, rule_id, rule, since)
            except Exception as e:
                print(f"Error running rule {rule['title']}: {e}")
        time.sleep(POLL_INTERVAL_SECONDS)
