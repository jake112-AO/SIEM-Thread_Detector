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

    # A couple of standard ECS bookkeeping fields every event should carry
    nested.setdefault("ecs", {})["version"] = "8.11.0"

    return nested


if __name__ == "__main__":
    import json
    sample = {
        "@timestamp": "2026-08-06T20:34:29",
        "log_source": "iptables",
        "event.outcome": "failure",
        "event.action": "firewall_rule",
        "source.ip": "203.0.113.27",
        "source.port": 58128,
        "destination.ip": "10.0.0.50",
        "destination.port": 23,
    }
    print(json.dumps(normalize_to_ecs(sample), indent=2))
