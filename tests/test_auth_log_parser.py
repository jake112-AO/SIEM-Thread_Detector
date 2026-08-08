import sys
sys.path.append("parsers")
from auth_log_parser import parse_line


def test_accepted_login_parses_correctly():
    line = "Aug  6 19:37:30 webserver01 sshd[1001]: Accepted password for svc_backup from 10.0.0.7 port 59215 ssh2"
    event = parse_line(line)

    assert event is not None
    assert event["event"]["outcome"] == "success"
    assert event["user"]["name"] == "svc_backup"
    assert event["source"]["ip"] == "10.0.0.7"
    assert event["source"]["port"] == 59215


def test_failed_login_with_invalid_user_parses_correctly():
    line = "Aug  6 19:37:31 webserver01 sshd[1002]: Failed password for invalid user admin from 203.0.113.7 port 51422 ssh2"
    event = parse_line(line)

    assert event is not None
    assert event["event"]["outcome"] == "failure"
    assert event["user"]["name"] == "admin"  # should NOT include "invalid user" literally


def test_garbage_line_returns_none():
    line = "this is not a valid log line at all"
    event = parse_line(line)

    assert event is None


def test_result_is_valid_outcome_value():
    line = "Aug  6 19:37:30 webserver01 sshd[1001]: Accepted password for bob from 10.0.0.5 port 12345 ssh2"
    event = parse_line(line)

    assert event["event"]["outcome"] in ("success", "failure")
