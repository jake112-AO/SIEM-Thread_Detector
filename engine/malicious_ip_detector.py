import sys
sys.path.append("pipeline")
sys.path.append(".")

from datetime import datetime, timezone, timedelta
from elasticsearch import Elasticsearch
from otx_client import load_cached_ips as load_otx_ips
from threatfox_client import load_cached_ips as load_threatfox_ips
from alerting import build_alert, write_alert


def get_combined_ioc_list():
    """
    Merges both threat intel sources, but instead of a flat set, keeps
    track of which feed(s) flagged each IP - this becomes IOC match
    metadata attached to the alert (T-053), so an analyst can see
    whether an IP was flagged by one source or corroborated by both.
    """
    otx_ips = load_otx_ips()
    threatfox_ips = load_threatfox_ips()

    ip_sources = {}
    for ip in otx_ips:
        ip_sources.setdefault(ip, []).append("AlienVault OTX")
    for ip in threatfox_ips:
        ip_sources.setdefault(ip, []).append("Abuse.ch ThreatFox")

    return ip_sources


def find_malicious_ip_connections(client, window_seconds=300):
    ioc_ip_sources = get_combined_ioc_list()
    if not ioc_ip_sources:
        print("No cached threat intel IPs available - run otx_client.py / threatfox_client.py first.")
        return []

    since_time = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
    matches = []

    for index in ["siem-parsed-auth-*", "siem-parsed-iptables-*"]:
        response = client.search(
            index=index,
            query={
                "bool": {
                    "must": [
                        {"terms": {"source.ip": list(ioc_ip_sources.keys())}},
                        {"range": {"@timestamp": {"gte": since_time}}},
                    ]
                }
            },
            size=50,
        )

        for hit in response["hits"]["hits"]:
            source = hit["_source"]
            ip = source.get("source", {}).get("ip")
            matches.append({
                "source.ip": ip,
                "log_source": source.get("log_source"),
                "timestamp": source.get("@timestamp"),
                "ioc_sources": ioc_ip_sources.get(ip, []),
            })

    return matches


if __name__ == "__main__":
    client = Elasticsearch("http://localhost:9200")
    matches = find_malicious_ip_connections(client)

    if not matches:
        print("No connections from known malicious IPs detected.")
    else:
        for m in matches:
            corroborated = len(m["ioc_sources"]) > 1
            alert = build_alert(
                rule_name="connection_to_known_malicious_ip",
                severity="critical",
                source_ip=m["source.ip"],
                description=f"Traffic observed from IP {m['source.ip']}, flagged by: {', '.join(m['ioc_sources'])}"
                             + (" (corroborated by multiple feeds)" if corroborated else ""),
                mitre_technique="T1071",
                extra={
                    "matched_log_source": m["log_source"],
                    "ioc.source_feeds": m["ioc_sources"],
                    "ioc.type": "ip",
                    "ioc.corroborated": corroborated,
                },
            )
            write_alert(client, alert)
            print(f"  🚨 Alert written: {m['source.ip']} — flagged by {', '.join(m['ioc_sources'])}")
			