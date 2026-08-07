import json
import os

STATE_DIR = "pipeline/.state"

def get_last_position(log_name: str) -> int:
    """Returns the last line number we've already processed for this log."""
    path = os.path.join(STATE_DIR, f"{log_name}.json")
    if not os.path.exists(path):
        return 0
    with open(path) as f:
        return json.load(f).get("last_line", 0)

def save_last_position(log_name: str, line_number: int):
    os.makedirs(STATE_DIR, exist_ok=True)
    path = os.path.join(STATE_DIR, f"{log_name}.json")
    with open(path, "w") as f:
        json.dump({"last_line": line_number}, f)
