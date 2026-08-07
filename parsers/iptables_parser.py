import re
import json
import sys
sys.path.append("pipeline")
from es_writer import get_client, send_event
from datetime import datetime
from ecs_normalizer import normalize_to_ecs

# The syslog wrapper (timestamp, hostname, kernel prefix) stays
# consistent, so we grab that with one regex...
LINE_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+kernel:\s+\[[\d.]+\]\s+"
    r"IPTABLES-(?P<action>DROP|ACCEPT):\s+(?P<kv_data>.+)$"
)

# ...and then parse the KEY=value part separately, since it's a
# flexible list (not always the same fields/order in real firewalls).
KV_PATTERN = re.compile(r"(\w+)=(\S*)")

def parse_line(line, current_year=2026):
    match = LINE_PATTERN.match(line.strip())
    if not match:
        return None

    parts = match.groupdict()

    # Turn "SRC=1.2.3.4 DST=5.6.7.8 SPT=1234 ..." into a dict
    kv_pairs = dict(KV_PATTERN.findall(parts["kv_data"]))

    ts = datetime.strptime(f"{current_year} {parts['timestamp']}", "%Y %b %d %H:%M:%S")

    event = {
        "@timestamp": ts.isoformat(),
        "host.name": parts["hostname"],
        "event.outcome": "success" if parts["action"] == "ACCEPT" else "failure",
        "event.action": "firewall_rule",
        "rule.name": f"IPTABLES-{parts['action']}",
        "source.ip": kv_pairs.get("SRC"),
        "source.port": int(kv_pairs["SPT"]) if "SPT" in kv_pairs else None,
        "destination.ip": kv_pairs.get("DST"),
        "destination.port": int(kv_pairs["DPT"]) if "DPT" in kv_pairs else None,
        "network.transport": kv_pairs.get("PROTO"),
        "network.bytes": int(kv_pairs["LEN"]) if "LEN" in kv_pairs else None,
        "log_source": "iptables",
    }
    return normalize_to_ecs(event)

if __name__ == "__main__":
    from es_writer import send_events_bulk
    client = get_client()

    events = []
    with open("logs/iptables.log") as f:
        for line in f:
            event = parse_line(line)
            if event:
                events.append(event)

    success, errors = send_events_bulk(client, events)
    print(f"Bulk sent {success} iptables events ({len(errors)} errors)")
