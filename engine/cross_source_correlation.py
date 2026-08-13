import sys
sys.path.append("engine")
sys.path.append("pipeline")

from datetime import datetime, timezone, timedelta
from elasticsearch import Elasticsearch
from frequency_counter import count_by_field
from alerting import build_alert, write_alert


def find_portscan_ips(client, window_seconds=90, distinct_port_threshold=10):
    """
    Finds source IPs that hit many DISTINCT destination ports within
    the window - the real signature of a port scan, not just a raw
    event count (which could also mean one chatty legitimate client).
    """
    since_time = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
    query = f"log_source:iptables AND event.outcome:failure AND @timestamp:[{since_time} TO now]"

    response = client.search(
        index="siem-parsed-iptables-*",
        query={"query_string": {"query": query}},
        size=0,
        aggs={
            "by_source_ip": {
                "terms": {"field": "source.ip", "size": 100},
                "aggs": {
                    "distinct_ports": {"cardinality": {"field": "destination.port"}}
                }
            }
        },
    )

    buckets = response["aggregations"]["by_source_ip"]["buckets"]
    return {
        b["key"]: b["distinct_ports"]["value"]
        for b in buckets
        if b["distinct_ports"]["value"] >= distinct_port_threshold
    }


def find_cross_source_attacks(client, window_seconds=90, failure_threshold=8, distinct_port_threshold=10):
    """
    Cross-source correlation: finds source IPs that show up in BOTH
    the port-scan list AND the SSH brute-force list within the same
    time window - a strong recon-then-attack signal.
    """
    portscan_ips = find_portscan_ips(client, window_seconds, distinct_port_threshold)

    bruteforce_ips = count_by_field(
        client,
        index="siem-parsed-auth-*",
        query="log_source:auth AND event.action:ssh_login AND event.outcome:failure",
        group_field="source.ip",
        window_seconds=window_seconds,
        threshold=failure_threshold,
    )
    bruteforce_ip_set = {entry["key"]: entry["count"] for entry in bruteforce_ips}

    cross_source_alerts = []
    for ip, port_count in portscan_ips.items():
        if ip in bruteforce_ip_set:
            cross_source_alerts.append({
                "rule": "cross_source_portscan_then_bruteforce",
                "source.ip": ip,
                "distinct_ports_scanned": port_count,
                "failed_login_attempts": bruteforce_ip_set[ip],
                "severity": "critical",
            })

    return cross_source_alerts


if __name__ == "__main__":
    client = Elasticsearch("http://localhost:9200")
    alerts = find_cross_source_attacks(client)

    if not alerts:
        print("No cross-source (port scan + brute force) attacks detected.")
    else:
        for a in alerts:
            alert = build_alert(
                rule_name="cross_source_portscan_then_bruteforce",
                severity="critical",
                source_ip=a["source.ip"],
                description=f"Port scan ({a['distinct_ports_scanned']} ports) followed by SSH brute force ({a['failed_login_attempts']} failures) from same source",
                mitre_technique="T1046,T1110.001",
                extra={"distinct_ports_scanned": a["distinct_ports_scanned"], "failed_login_attempts": a["failed_login_attempts"]},
            )
            write_alert(client, alert)
            print(f"  🚨 Alert written: {a['source.ip']} — CRITICAL cross-source attack")