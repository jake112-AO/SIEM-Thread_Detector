import re
import json
import sys
sys.path.append("pipeline")
from es_writer import get_client, send_event
from datetime import datetime
from ecs_normalizer import normalize_to_ecs

# This regex is the actual "translator" — it looks for the exact
# pattern of a real sshd log line and captures the important parts
# into named groups.
LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"sshd\[(?P<pid>\d+)\]:\s+"
    r"(?P<result>Accepted|Failed)\spassword\sfor\s"
    r"(?:invalid user\s)?(?P<user>\S+)\sfrom\s"
    r"(?P<src_ip>[\d.]+)\sport\s(?P<src_port>\d+)\sssh2$"
)

def parse_line(line, current_year=2026):
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None  # line didn't match our expected format - skip it

    fields = match.groupdict()

    # Real syslog timestamps have no year in them ("Aug  6 19:37:30"),
    # so we assume the current year - a well-known syslog quirk.
    ts = datetime.strptime(f"{current_year} {fields['timestamp']}", "%Y %b %d %H:%M:%S")

    event = {
        "@timestamp": ts.isoformat(),
        "host.name": fields["hostname"],
        "process.pid": int(fields["pid"]),
        "event.outcome": "success" if fields["result"] == "Accepted" else "failure",
        "user.name": fields["user"],
        "source.ip": fields["src_ip"],
        "source.port": int(fields["src_port"]),
        "event.action": "ssh_login",
        "log_source": "auth",
    }
    return normalize_to_ecs(event)

if __name__ == "__main__":
    client = get_client()
    sent = 0
    with open("logs/auth.log") as f:
        for line in f:
            event = parse_line(line)
            if event:
                send_event(client, event)
                sent += 1
    print(f"Sent {sent} auth events to Elasticsearch")
