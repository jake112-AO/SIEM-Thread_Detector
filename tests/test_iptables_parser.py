import sys
sys.path.append("parsers")
from iptables_parser import parse_line


def test_drop_action_parses_as_failure():
    line = "Aug  6 20:34:29 firewall01 kernel: [1.370000] IPTABLES-DROP: IN=eth0 OUT= SRC=203.0.113.27 DST=10.0.0.50 LEN=60 TTL=64 PROTO=TCP SPT=58128 DPT=23 SYN"
    event = parse_line(line)

    assert event is not None
    assert event["event"]["outcome"] == "failure"
    assert event["source"]["ip"] == "203.0.113.27"
    assert event["source"]["port"] == 58128


def test_accept_action_parses_as_success():
    line = "Aug  6 20:34:31 firewall01 kernel: [4.110000] IPTABLES-ACCEPT: IN=eth0 OUT= SRC=203.0.113.132 DST=10.0.0.30 LEN=60 TTL=64 PROTO=TCP SPT=56070 DPT=80 SYN"
    event = parse_line(line)

    assert event["event"]["outcome"] == "success"


def test_garbage_line_returns_none():
    line = "not a real firewall log line"
    event = parse_line(line)

    assert event is None


def test_ports_and_bytes_are_integers():
    line = "Aug  6 20:34:29 firewall01 kernel: [1.370000] IPTABLES-DROP: IN=eth0 OUT= SRC=203.0.113.27 DST=10.0.0.50 LEN=60 TTL=64 PROTO=TCP SPT=58128 DPT=23 SYN"
    event = parse_line(line)

    assert isinstance(event["source"]["port"], int)
    assert isinstance(event["network"]["bytes"], int)
