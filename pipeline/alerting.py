import hashlib
import json
import sys
sys.path.append("pipeline")
from mitre_mapping import get_tactics
from datetime import datetime, timezone, timedelta
from elasticsearch import Elasticsearch

ES_HOST = "http://localhost:9200"
ALERTS_INDEX_PREFIX = "siem-alerts"
DEDUP_COOLDOWN_MINUTES = 15

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def make_alert_id(rule_name: str, source_ip: str, window_bucket: str) -> str:
    """
    Stable ID based on rule + IP + a coarse time bucket (not exact
    timestamp) - this is what makes dedup work: the SAME attack seen
    across multiple 60s poll cycles produces the SAME alert ID, so
    re-indexing just overwrites instead of creating a new alert.
    """
    raw = f"{rule_name}:{source_ip}:{window_bucket}"
    return hashlib.sha256(raw.encode()).hexdigest()


def get_time_bucket(minutes: int = DEDUP_COOLDOWN_MINUTES) -> str:
    """Rounds the current time down to the nearest `minutes`-minute bucket."""
    now = datetime.now(timezone.utc)
    bucket_minute = (now.minute // minutes) * minutes
    bucket_time = now.replace(minute=0, second=0, microsecond=0) + timedelta(minutes=bucket_minute)
    return bucket_time.isoformat()


def build_alert(rule_name: str, severity: str, source_ip: str, description: str, mitre_technique: str, extra: dict = None):
    # mitre_technique can be a single ID or comma-joined (e.g. our
    # cross-source rule) - split into a real array so it's aggregatable
    # in Kibana, and look up the real tactic(s) it belongs to.
    technique_ids = [t.strip() for t in mitre_technique.split(",")]
    tactics = get_tactics(technique_ids)

    return {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "rule.name": rule_name,
        "severity": severity,
        "severity_rank": SEVERITY_RANK.get(severity, 0),
        "source.ip": source_ip,
        "description": description,
        "mitre.technique": technique_ids,
        "mitre.tactic": tactics,
        "status": "open",
        **(extra or {}),
    }

def write_alert(client: Elasticsearch, alert: dict):
    """
    Writes an alert to today's alerts index, using a dedup-aware ID -
    the same real attack seen across multiple poll cycles within the
    same cooldown window overwrites the same document instead of
    spamming duplicate alerts.
    """
    date_str = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    index_name = f"{ALERTS_INDEX_PREFIX}-{date_str}"

    bucket = get_time_bucket()
    alert_id = make_alert_id(alert["rule.name"], alert["source.ip"], bucket)

    response = client.index(index=index_name, id=alert_id, document=alert)
    return response


if __name__ == "__main__":
    client = Elasticsearch(ES_HOST)
    test_alert = build_alert(
        rule_name="test_rule",
        severity="high",
        source_ip="203.0.113.99",
        description="Test alert to verify schema and indexing",
        mitre_technique="T1110.001",
    )
    result = write_alert(client, test_alert)
    print("Alert written:", result["result"], "->", result["_index"])
    print(json.dumps(test_alert, indent=2))