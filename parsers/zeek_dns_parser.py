import json
import sys
sys.path.append("pipeline")
from datetime import datetime, timezone
from ecs_normalizer import normalize_to_ecs
from es_writer import get_client, send_events_bulk

def parse_zeek_dns_log(path):
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

            query = raw_row.get("query", "")
            if query == "-" or not query:
                continue

            # The subdomain is everything before the actual registered
            # domain - a rough approximation good enough for our purposes:
            # just measure the length of the full query name.
            subdomain_length = len(query.split(".")[0]) if "." in query else len(query)

            event = {
                "log_source": "zeek",
                "event.action": "dns_query",
                "source.ip": raw_row.get("id.orig_h"),
                "destination.ip": raw_row.get("id.resp_h"),
                "dns.question.name": query,
                "dns.question.subdomain_length": subdomain_length,
            }

            if "ts" in raw_row:
                epoch = float(raw_row["ts"])
                event["@timestamp"] = datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()

            events.append(normalize_to_ecs(event))

    return events


if __name__ == "__main__":
    LOG_FILE = "logs/zeek/dns_tunneling/dns.log"
    client = get_client()
    results = parse_zeek_dns_log(LOG_FILE)
    success, errors = send_events_bulk(client, results)
    print(f"Bulk sent {success} DNS events ({len(errors)} errors)")
