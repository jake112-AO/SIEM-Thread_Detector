import json
from datetime import datetime, timezone

LOG_FILE = "logs/zeek/bruteforce/conn.log"

# Only Zeek columns we actually care about get mapped to ECS names.
# Anything not in this dict just gets dropped.
FIELD_MAP = {
    "ts": "@timestamp",
    "id.orig_h": "source.ip",
    "id.orig_p": "source.port",
    "id.resp_h": "destination.ip",
    "id.resp_p": "destination.port",
    "proto": "network.transport",
    "service": "network.protocol",
    "duration": "event.duration",
    "orig_bytes": "source.bytes",
    "resp_bytes": "destination.bytes",
    "conn_state": "zeek.conn_state",
}

def parse_zeek_log(path):
    events = []
    field_names = []

    with open(path, "r") as f:
        for line in f:
            line = line.rstrip("\n")

            if line.startswith("#fields"):
                # This line looks like: "#fields\tts\tuid\tid.orig_h\t..."
                # Split on tabs, drop the "#fields" label itself
                field_names = line.split("\t")[1:]
                continue

            if line.startswith("#"):
                continue  # skip all other header/comment lines

            if not field_names:
                continue  # haven't seen #fields yet, can't parse safely

            values = line.split("\t")
            raw_row = dict(zip(field_names, values))

            event = {"log_source": "zeek", "event.action": "network_connection"}
            for zeek_field, ecs_field in FIELD_MAP.items():
                if zeek_field in raw_row and raw_row[zeek_field] != "-":
                    event[ecs_field] = raw_row[zeek_field]

            # Zeek "ts" is unix epoch seconds (e.g. 1389721044.82) -
            # convert it into a real ISO timestamp for consistency
            # with our other 2 parsers.
            if "@timestamp" in event:
                epoch = float(event["@timestamp"])
                event["@timestamp"] = datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()

            events.append(event)

    return events


if __name__ == "__main__":
    results = parse_zeek_log(LOG_FILE)
    print(f"Parsed {len(results)} connection events\n")
    for event in results[:3]:
        print(json.dumps(event, indent=2))
