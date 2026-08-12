from collections import defaultdict
from datetime import datetime, timezone, timedelta
from elasticsearch import Elasticsearch

def count_by_field(client, index: str, query: str, group_field: str, window_seconds: int, threshold: int):
    """
    Runs a query over the last `window_seconds`, groups matching events
    by `group_field` (e.g. source.ip), and returns only the groups whose
    count meets or exceeds `threshold` - the actual "is this suspicious"
    logic that a bare event count alone can't tell you.
    """
    since_time = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
    full_query = f"{query} AND @timestamp:[{since_time} TO now]"

    # Elasticsearch can do this grouping natively via an aggregation,
    # instead of us pulling every raw document back and counting in
    # Python - much more efficient, especially as data grows.
    response = client.search(
        index=index,
        query={"query_string": {"query": full_query}},
        size=0,  # we don't need the actual documents, just the counts
        aggs={
            "grouped": {
                "terms": {
                    "field": f"{group_field}.keyword" if not group_field.endswith((".ip",)) else group_field,
                    "size": 100,
                }
            }
        },
    )

    buckets = response["aggregations"]["grouped"]["buckets"]
    suspicious_groups = [
        {"key": bucket["key"], "count": bucket["doc_count"]}
        for bucket in buckets
        if bucket["doc_count"] >= threshold
    ]
    return suspicious_groups


if __name__ == "__main__":
    client = Elasticsearch("http://localhost:9200")

    # Test: how many failed SSH logins per source IP, in the last 5 minutes?
    results = count_by_field(
        client,
        index="siem-parsed-auth-*",
        query="log_source:auth AND event.action:ssh_login AND event.outcome:failure",
        group_field="source.ip",
        window_seconds=60,
        threshold=8,
    )

    print(f"Source IPs with 8+ failed logins in last 60 seconds:") 
    for r in results:
        print(f"  {r['key']}: {r['count']} failures")
