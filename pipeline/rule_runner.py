import json
import time
import sys
import re
sys.path.append("pipeline")
from alerting import build_alert, write_alert
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

def extract_technique_id(tags: list[str]) -> str:
    """
    Pulls a MITRE technique ID out of Sigma-style tags like
    'attack.t1110.001' -> 'T1110.001'. Ignores non-technique tags
    like 'attack.credential_access' (tactic-style tags, not IDs).
    """
    for tag in tags:
        match = re.match(r"attack\.t(\d{4}(?:\.\d{3})?)$", tag, re.IGNORECASE)
        if match:
            return f"T{match.group(1)}"
    return "unknown"

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
        size=20,
    )

    total = response["hits"]["total"]["value"]
    if total > 0:
        print(f"🚨 [{rule['level'].upper()}] {rule['title']} — {total} matches in last {POLL_INTERVAL_SECONDS}s")

        # Grab the source.ip from the first matching doc, if it has one,
        # so the alert carries real context instead of being IP-less.
        source_ip = "unknown"
        if response["hits"]["hits"]:
            hit_source = response["hits"]["hits"][0]["_source"]
            source_ip = hit_source.get("source", {}).get("ip", "unknown")

        alert = build_alert(
            rule_name=rule["title"],
            severity=rule["level"],
            source_ip=source_ip,
            description=f"{total} events matched '{rule['title']}' in the last {POLL_INTERVAL_SECONDS} seconds",
            mitre_technique=extract_technique_id(rule.get("tags", [])),
            extra={"match_count": total},
        )
        write_alert(client, alert)

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
