import sys
sys.path.append("pipeline")
sys.path.append(".")

from datetime import datetime, timezone, timedelta
from elasticsearch import Elasticsearch
from otx_client import load_cached_ips as load_otx_ips
from threatfox_client import load_cached_ips as load_threatfox_ips
from alerting import build_alert, write_alert


def get_combined_ioc_list():
    """Merges both threat intel sources into one set of known-bad IPs."""
    otx_ips = load_otx_ips()
    threatfox_ips = load_threatfox_ips()
    return otx_ips | threatfox_ips  # set union - either source counts


def find_malicious_ip_connections(client, window_seconds=300):
    """
    Checks recent traffic (both auth and iptables sources) for any
    connection involving a source.ip that appears in our combined
    threat intel list.
    """
    ioc_ips = get_combined_ioc_list()
    if not ioc_ips:
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
                        {"terms": {"source.ip": list(ioc_ips)}},
                        {"range": {"@timestamp": {"gte": since_time}}},
                    ]
                }
            },
            size=50,
        )

        for hit in response["hits"]["hits"]:
            source = hit["_source"]
            matches.append({
                "source.ip": source.get("source", {}).get("ip"),
                "log_source": source.get("log_source"),
                "timestamp": source.get("@timestamp"),
            })

    return matches


if __name__ == "__main__":
    client = Elasticsearch("http://localhost:9200")
    matches = find_malicious_ip_connections(client)

    if not matches:
        print("No connections from known malicious IPs detected.")
    else:
        for m in matches:
            alert = build_alert(
                rule_name="connection_to_known_malicious_ip",
                severity="critical",
                source_ip=m["source.ip"],
                description=f"Traffic observed from IP {m['source.ip']}, which appears in AlienVault OTX / ThreatFox threat intel feeds",
                mitre_technique="T1071",
                extra={"matched_log_source": m["log_source"]},
            )
            write_alert(client, alert)
            print(f"  🚨 Alert written: {m['source.ip']} (seen in {m['log_source']} logs)")
			