import re
import json
from datetime import datetime

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
    return event


if __name__ == "__main__":
    test_lines = [
        "Aug  6 20:34:29 firewall01 kernel: [1.370000] IPTABLES-DROP: IN=eth0 OUT= SRC=203.0.113.27 DST=10.0.0.50 LEN=60 TTL=64 PROTO=TCP SPT=58128 DPT=23 SYN",
        "Aug  6 20:34:31 firewall01 kernel: [4.110000] IPTABLES-ACCEPT: IN=eth0 OUT= SRC=203.0.113.132 DST=10.0.0.30 LEN=60 TTL=64 PROTO=TCP SPT=56070 DPT=80 SYN",
        "garbage line here",
    ]
    for line in test_lines:
        result = parse_line(line)
        print(json.dumps(result, indent=2) if result else f"NO MATCH: {line}")
