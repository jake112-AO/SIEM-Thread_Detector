import sys
sys.path.append("parsers")
from zeek_conn_parser import parse_zeek_log

# We use the real sample file we already have, since Zeek's format
# needs the #fields header line to know column order - can't easily
# test a single fake line in isolation like we did for auth.log.
TEST_LOG = "logs/zeek/bruteforce/conn.log"


def test_parses_expected_number_of_events():
    events = parse_zeek_log(TEST_LOG)
    assert len(events) == 30  # known count from our real sample pcap


def test_events_have_required_ecs_fields():
    events = parse_zeek_log(TEST_LOG)
    first_event = events[0]

    assert "@timestamp" in first_event
    assert "source" in first_event
    assert "ip" in first_event["source"]
    assert "destination" in first_event


def test_ports_are_integers_not_strings():
    events = parse_zeek_log(TEST_LOG)
    first_event = events[0]

    assert isinstance(first_event["source"]["port"], int)
    assert isinstance(first_event["destination"]["port"], int)
