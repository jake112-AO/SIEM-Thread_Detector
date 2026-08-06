import json
import sys
sys.path.append("pipeline")
from es_writer import get_client, send_event
from datetime import datetime, timezone
from ecs_normalizer import normalize_to_ecs

LOG_FILE = "logs/zeek/bruteforce/conn.log"

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
                field_names = line.split("\t")[1:]
                continue

            if line.startswith("#"):
                continue

            if not field_names:
                continue

            values = line.split("\t")
            raw_row = dict(zip(field_names, values))

            NUMERIC_FIELDS = {"source.port", "destination.port", "source.bytes", "destination.bytes"}

            event = {"log_source": "zeek", "event.action": "network_connection"}
            for zeek_field, ecs_field in FIELD_MAP.items():
                if zeek_field in raw_row and raw_row[zeek_field] != "-":
                    value = raw_row[zeek_field]
                    if ecs_field in NUMERIC_FIELDS:
                        value = int(value)
                    event[ecs_field] = value

            if "@timestamp" in event:
                epoch = float(event["@timestamp"])
                event["@timestamp"] = datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()

            events.append(normalize_to_ecs(event))   # <-- normalize BEFORE appending, list stays a list

    return events

if __name__ == "__main__":
    client = get_client()
    results = parse_zeek_log(LOG_FILE)
    sent = 0
    for event in results:
        send_event(client, event)
        sent += 1
    print(f"Sent {sent} zeek events to Elasticsearch")
