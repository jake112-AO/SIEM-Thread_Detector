import json
from datetime import datetime, timezone
from elasticsearch import Elasticsearch

ES_HOST = "http://localhost:9200"
OUTPUT_FILE = "docs/mitre_navigator_layer.json"


def get_technique_counts(client):
    """
    Aggregates real alert data by MITRE technique ID, giving us an
    actual count of how many times each technique fired - this becomes
    the 'score' that colors each box in Navigator.
    """
    response = client.search(
        index="siem-alerts-*",
        size=0,
        aggs={
            "by_technique": {
                "terms": {"field": "mitre.technique.keyword", "size": 100}
            }
        },
    )
    buckets = response["aggregations"]["by_technique"]["buckets"]
    return {b["key"]: b["doc_count"] for b in buckets if b["key"] != "unknown"}


def build_navigator_layer(technique_counts: dict):
    """
    Builds a Navigator v4.5-compatible layer JSON. Each technique we've
    actually detected gets a colored box scored by real fire count;
    everything else stays default (uncolored) - an honest coverage map,
    not a fabricated "we detect everything" claim.
    """
    max_count = max(technique_counts.values()) if technique_counts else 1

    techniques = []
    for technique_id, count in technique_counts.items():
        techniques.append({
            "techniqueID": technique_id,
            "score": count,
            "color": "",
            "comment": f"Detected {count} time(s) by this SIEM's detection rules",
            "enabled": True,
            "metadata": [],
            "showSubtechniques": False,
        })

    layer = {
        "name": "SIEM Detection Coverage",
        "versions": {"attack": "15", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Real detection coverage generated from live alert data on {datetime.now(timezone.utc).strftime('%Y-%m-%d')}. Score = number of times each technique fired in this SIEM's testing.",
        "filters": {"platforms": ["Linux"]},
        "sorting": 3,  # sort by score descending
        "layout": {
 "			layout": "side",
            "showID": True,
            "showName": True,
            "expandedSubtechniques": "all",
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#66b1ff", "#0d4a90"],
            "minValue": 0,
            "maxValue": max_count,
        },
        "legendItems": [],
        "metadata": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }
    return layer


if __name__ == "__main__":
    client = Elasticsearch(ES_HOST)
    counts = get_technique_counts(client)

    print(f"Found {len(counts)} distinct techniques detected:")
    for tid, count in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"  {tid}: {count} detections")

    layer = build_navigator_layer(counts)

    import os
    os.makedirs("docs", exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(layer, f, indent=2)

    print(f"\nNavigator layer saved to {OUTPUT_FILE}")