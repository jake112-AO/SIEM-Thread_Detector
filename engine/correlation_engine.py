import sys
sys.path.append("engine")
sys.path.append("pipeline")

from datetime import datetime, timezone, timedelta
from elasticsearch import Elasticsearch
from frequency_counter import count_by_field
from alerting import build_alert, write_alert


def find_bruteforce_then_success(client, failure_threshold=8, failure_window=60, success_lookahead=300):
    """
    Two-stage correlation:
    1. Find source IPs with a suspicious burst of failed SSH logins.
    2. For each of those IPs, check whether a successful login from the
       SAME IP happened within `success_lookahead` seconds afterward.
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
        for a in alerts:
            alert = build_alert(
                rule_name="auth_login_after_bruteforce",
                severity="high",
                source_ip=a["source.ip"],
                description=f"{a['failure_count']} failed SSH logins followed by successful login as '{a['successful_user']}'",
                mitre_technique="T1110",
                extra={"failure_count": a["failure_count"], "user.name": a["successful_user"]},
            )
            write_alert(client, alert)
            print(f"  🚨 Alert written: {a['source.ip']} — {a['failure_count']} failures then success")