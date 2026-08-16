import json
import requests

# Pinned to a specific stable release rather than "latest" (master),
# so this mapping doesn't silently change on a future re-run.
STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-15.1.json"
OUTPUT_FILE = "pipeline/mitre_technique_tactic_map.json"

# STIX uses lowercase-hyphenated tactic names internally
# (e.g. "credential-access") - map those to the readable names
# ATT&CK's own website and Navigator use.
TACTIC_DISPLAY_NAMES = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


def build_mapping():
    print(f"Downloading MITRE ATT&CK STIX data (this is ~50MB, may take a moment)...")
    response = requests.get(STIX_URL, timeout=60)
    stix_data = response.json()

    mapping = {}

    for obj in stix_data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        # Pull the real technique ID (e.g. "T1110.001") from external_references
        technique_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                break
        if not technique_id:
            continue

        tactics = [
            TACTIC_DISPLAY_NAMES.get(phase["phase_name"], phase["phase_name"])
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]

        if tactics:
            mapping[technique_id] = tactics

    with open(OUTPUT_FILE, "w") as f:
        json.dump(mapping, f, indent=2, sort_keys=True)

    print(f"Built mapping for {len(mapping)} techniques -> {OUTPUT_FILE}")
    return mapping


if __name__ == "__main__":
    mapping = build_mapping()
    # Sanity check against the specific techniques our rules actually use
    our_techniques = ["T1110.001", "T1046", "T1041", "T1110", "T1136.001",
                       "T1548.003", "T1071.004", "T1595.002", "T1071"]
    print("\nOur rules' techniques:")
    for t in our_techniques:
        print(f"  {t}: {mapping.get(t, 'NOT FOUND')}")