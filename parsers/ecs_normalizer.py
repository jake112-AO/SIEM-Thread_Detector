import sys
sys.path.append("pipeline")
from geoip import lookup_ip

def normalize_to_ecs(flat_event: dict) -> dict:
    """
    Takes a flat dict with dotted keys like {"source.ip": "1.2.3.4"}
    and converts it into a properly nested ECS structure:
    {"source": {"ip": "1.2.3.4"}}

    @timestamp and log_source stay at the top level - that's correct
    per the real ECS spec, not every field gets nested.
    """
    TOP_LEVEL_KEYS = {"@timestamp", "log_source"}

    nested = {}
    for key, value in flat_event.items():
        if value is None:
            continue  # don't store empty/missing fields at all

        if key in TOP_LEVEL_KEYS or "." not in key:
            nested[key] = value
            continue

        # Split "source.ip" into ["source", "ip"] and build the nesting
        parts = key.split(".")
        current = nested
        for part in parts[:-1]:
            current = current.setdefault(part, {})
        current[parts[-1]] = value
    
    # Figure out once whether this is an internal (private network) or
    # external (public internet) source IP - both the tagging below and
    # the GeoIP lookup need this same answer.
    source_ip = nested.get("source", {}).get("ip")
    is_internal = None
    if source_ip:
        is_internal = (
            source_ip.startswith("10.") or
            source_ip.startswith("192.168.") or
            source_ip.startswith("172.16.") or
            source_ip.startswith("127.")
        )
        nested.setdefault("source", {})["is_internal"] = is_internal

    # Only look up GeoIP for external IPs - internal/private addresses
    # have no real-world location and would just waste an API call.
    if source_ip and is_internal is False:
        geo_data = lookup_ip(source_ip)
        if geo_data:
            for key, value in geo_data.items():
                parts = key.split(".")
                current = nested
                for part in parts[:-1]:
                    current = current.setdefault(part, {})
                current[parts[-1]] = value
	
    return nested

if __name__ == "__main__":
    import json
    sample = {
        "@timestamp": "2026-08-06T20:34:29",
        "log_source": "iptables",
        "event.outcome": "failure",
        "event.action": "firewall_rule",
        "source.ip": "8.8.8.8",   # real public IP, to prove GeoIP wiring works
        "source.port": 58128,
        "destination.ip": "10.0.0.50",
        "destination.port": 23,
    }
    print(json.dumps(normalize_to_ecs(sample), indent=2))
