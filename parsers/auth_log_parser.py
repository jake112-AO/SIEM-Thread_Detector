import re
import json
from datetime import datetime

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
    return event


if __name__ == "__main__":
    test_lines = [
        "Aug  6 19:37:30 webserver01 sshd[1001]: Accepted password for svc_backup from 10.0.0.7 port 59215 ssh2",
        "Aug  6 19:37:31 webserver01 sshd[1002]: Failed password for invalid user admin from 203.0.113.7 port 51422 ssh2",
        "this is not a valid log line at all",
    ]
    for line in test_lines:
        result = parse_line(line)
        print(json.dumps(result, indent=2) if result else f"NO MATCH: {line}")
