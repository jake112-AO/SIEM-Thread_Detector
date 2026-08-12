import json
from pathlib import Path
from sigma.collection import SigmaCollection
from sigma.backends.elasticsearch import LuceneBackend

RULES_DIR = "rules"
OUTPUT_FILE = "pipeline/compiled_rules.json"

# The correlation rule is handled separately by our own Python
# correlation engine (T-046), not converted via pySigma - see
# README/docs note on ES|QL sliding-window limitations.
SKIP_FILES = {"auth_login_after_bruteforce.yml"}

def convert_all_rules():
    backend = LuceneBackend()
    compiled = {}

    for rule_path in sorted(Path(RULES_DIR).glob("*.yml")):
        if rule_path.name in SKIP_FILES:
            print(f"Skipping {rule_path.name} (handled by Python correlation engine)")
            continue

        try:
            rule_collection = SigmaCollection.from_yaml(rule_path.read_text())
            queries = backend.convert(rule_collection)
            rule = rule_collection.rules[0]

            compiled[str(rule.id)] = {
                "title": rule.title,
                "file": rule_path.name,
                "level": str(rule.level.name).lower() if rule.level else "medium",
                "query": queries[0],
                "tags": [str(tag) for tag in rule.tags] if rule.tags else [],
            }
            print(f"Converted: {rule_path.name} -> {queries[0]}")
        except Exception as e:
            print(f"FAILED to convert {rule_path.name}: {e}")

    with open(OUTPUT_FILE, "w") as f:
        json.dump(compiled, f, indent=2)

    print(f"\nSaved {len(compiled)} compiled rules to {OUTPUT_FILE}")


if __name__ == "__main__":
    convert_all_rules()
