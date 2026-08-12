import re
import json
import sys
sys.path.append("pipeline")
from es_writer import get_client, send_event
from datetime import datetime
from ecs_normalizer import normalize_to_ecs

LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"sshd\[(?P<pid>\d+)\]:\s+"
    r"(?P<result>Accepted|Failed)\spassword\sfor\s"
    r"(?:invalid user\s)?(?P<user>\S+)\sfrom\s"
    r"(?P<src_ip>[\d.]+)\sport\s(?P<src_port>\d+)\sssh2$"
)

USERADD_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+useradd\[(?P<pid>\d+)\]:\s+"
    r"new user:\s+name=(?P<user>\S+?),\s+UID=(?P<uid>\d+)"
)

SUDO_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+sudo:\s+(?P<user>\S+)\s+:\s+.*"
    r"COMMAND=(?P<command>.+)$"
)


def parse_line(line, current_year=2026):
    line = line.strip()

    match = LOG_PATTERN.match(line)
    if match:
        fields = match.groupdict()
        ts = datetime.strptime(f"{current_year} {fields['timestamp']}", "%Y %b %d %H:%M:%S")
        return normalize_to_ecs({
            "@timestamp": ts.isoformat(),
            "host.name": fields["hostname"],
            "process.pid": int(fields["pid"]),
            "event.outcome": "success" if fields["result"] == "Accepted" else "failure",
            "user.name": fields["user"],
            "source.ip": fields["src_ip"],
            "source.port": int(fields["src_port"]),
            "event.action": "ssh_login",
            "log_source": "auth",
        })

    match = USERADD_PATTERN.match(line)
    if match:
        fields = match.groupdict()
        ts = datetime.strptime(f"{current_year} {fields['timestamp']}", "%Y %b %d %H:%M:%S")
        return normalize_to_ecs({
            "@timestamp": ts.isoformat(),
            "host.name": fields["hostname"],
            "process.pid": int(fields["pid"]),
            "user.name": fields["user"],
            "user.id": fields["uid"],
            "event.action": "user_account_created",
            "event.outcome": "success",
            "log_source": "auth",
        })

    match = SUDO_PATTERN.match(line)
    if match:
        fields = match.groupdict()
        ts = datetime.strptime(f"{current_year} {fields['timestamp']}", "%Y %b %d %H:%M:%S")
        return normalize_to_ecs({
            "@timestamp": ts.isoformat(),
            "host.name": fields["hostname"],
            "user.name": fields["user"],
            "process.command_line": fields["command"],
            "event.action": "sudo_command",
            "event.outcome": "success",
            "log_source": "auth",
        })

    return None


if __name__ == "__main__":
    test_lines = [
        "Aug  6 19:37:30 webserver01 sshd[1001]: Accepted password for svc_backup from 10.0.0.7 port 59215 ssh2",
        "Aug 10 15:42:11 webserver01 useradd[2345]: new user: name=hacker, UID=1001, GID=1001, home=/home/hacker, shell=/bin/bash",
        "Aug 10 15:43:02 webserver01 sudo: jiahao : TTY=pts/0 ; PWD=/home/jiahao ; USER=root ; COMMAND=/bin/bash",
        "this is not a valid log line at all",
    ]
    for line in test_lines:
        result = parse_line(line)
        print(json.dumps(result, indent=2) if result else f"NO MATCH: {line}")