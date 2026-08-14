import sys
import time
sys.path.append("parsers")
sys.path.append("pipeline")

from state import get_last_position, save_last_position
from es_writer import get_client, send_events_bulk
from auth_log_parser import parse_line as parse_auth_line
from iptables_parser import parse_line as parse_iptables_line

# Each entry: (name used for bookmark + index, file path, parser function)
WATCHED_LOGS = [
    ("auth", "logs/auth.log", parse_auth_line),
    ("iptables", "logs/iptables.log", parse_iptables_line),
]

POLL_INTERVAL_SECONDS = 5

def check_for_new_lines(client, name, path, parser_fn):
    last_offset = get_last_position(name)

    with open(path, "r") as f:
        f.seek(last_offset)          # jump straight to where we left off
        new_lines = f.readlines()    # only reads from here to end of file
        new_offset = f.tell()        # remember exactly how far we read

    if not new_lines:
        return 0

    events = [parser_fn(line) for line in new_lines]
    events = [e for e in events if e]

    if events:
        success, errors = send_events_bulk(client, events)
        print(f"[{name}] sent {success} new events ({len(errors)} errors)")

    save_last_position(name, new_offset)
    return len(events)


if __name__ == "__main__":
    client = get_client()
    print(f"Watching {len(WATCHED_LOGS)} log files, checking every {POLL_INTERVAL_SECONDS}s. Ctrl+C to stop.")

    while True:
        for name, path, parser_fn in WATCHED_LOGS:
            try:
                check_for_new_lines(client, name, path, parser_fn)
            except FileNotFoundError:
                print(f"[{name}] file not found yet: {path}")
        time.sleep(POLL_INTERVAL_SECONDS)
