import json
import os

MAPPING_FILE = "pipeline/mitre_technique_tactic_map.json"
_mapping_cache = None


def _load_mapping():
    global _mapping_cache
    if _mapping_cache is None:
        if not os.path.exists(MAPPING_FILE):
            raise FileNotFoundError(
                f"{MAPPING_FILE} not found - run pipeline/build_mitre_mapping.py first"
            )
        with open(MAPPING_FILE) as f:
            _mapping_cache = json.load(f)
    return _mapping_cache


def get_tactics(technique_ids: list[str]) -> list[str]:
    """
    Takes a list of technique IDs (an alert can map to more than one,
    e.g. our cross-source rule) and returns the unique, sorted set of
    real MITRE tactics they belong to, using the official ATT&CK data.
    """
    mapping = _load_mapping()
    tactics = set()
    for tid in technique_ids:
        tactics.update(mapping.get(tid.strip(), []))
    return sorted(tactics)


if __name__ == "__main__":
    print(get_tactics(["T1110.001"]))
    print(get_tactics(["T1046", "T1110.001"]))
    print(get_tactics(["T9999.999"]))  # unknown technique - should return empty
    