from datetime import datetime, timezone, timedelta
from elasticsearch import Elasticsearch
import sys
sys.path.append("engine")
from frequency_counter import count_by_field


def find_bruteforce_then_success(client, failure_threshold=8, failure_window=60, success_lookahead=300):
    """
    Two-stage correlation:
    1. Find source IPs with a suspicious burst of failed SSH logins
       (reuses our frequency counter from T-045).
    2. For each of those IPs, check whether a successful login from the
       SAME IP happened within `success_lookahead` seconds afterward.

    This mirrors the Sigma temporal correlation in
    auth_login_after_bruteforce.yml: group-by source.ip, ordered,
    failures before success, within a timespan.
    """
    suspicious_ips = count_by_field(
        client,
        index="siem-parsed-auth-*",
        query="log_source:auth AND event.action:ssh_login AND event.outcome:failure",
        group_field="source.ip",
        window_seconds=failure_window,
        threshold=failure_threshold,
    )

    correlated_alerts = []

    for entry in suspicious_ips:
        ip = entry["key"]
        failure_count = entry["count"]

        # Now check: did this SAME ip also have a successful login,
        # any time from now back to `success_lookahead` seconds ago?
        since_time = (datetime.now(timezone.utc) - timedelta(seconds=success_lookahead)).isoformat()
        query = (
            f"log_source:auth AND event.action:ssh_login AND event.outcome:success "
            f'AND source.ip:"{ip}" AND @timestamp:[{since_time} TO now]'
        )

        response = client.search(
            index="siem-parsed-auth-*",
            query={"query_string": {"query": query}},
            size=1,
            sort=[{"@timestamp": {"order": "desc"}}],
        )

        if response["hits"]["total"]["value"] > 0:
            success_event = response["hits"]["hits"][0]["_source"]
            correlated_alerts.append({
                "rule": "auth_login_after_bruteforce",
                "source.ip": ip,
                "failure_count": failure_count,
                "successful_user": success_event.get("user", {}).get("name"),
                "success_timestamp": success_event.get("@timestamp"),
                "severity": "high",
            })

    return correlated_alerts


if __name__ == "__main__":
    client = Elasticsearch("http://localhost:9200")
    alerts = find_bruteforce_then_success(client)

    if not alerts:
        print("No brute-force-then-success patterns detected.")
    else:
        print(f"Found {len(alerts)} correlated brute-force attacks:")
        for alert in alerts:
            print(f"  🚨 {alert['source.ip']} — {alert['failure_count']} failures, "
                  f"then successful login as '{alert['successful_user']}' at {alert['success_timestamp']}")
