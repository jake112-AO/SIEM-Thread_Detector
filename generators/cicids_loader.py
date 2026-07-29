import pandas as pd
import json

CSV_PATH = "datasets/TrafficLabelling/Tuesday-WorkingHours.pcap_ISCX.csv"
OUTPUT_PATH = "logs/cicids/tuesday.json"

# CICIDS columns have sneaky leading spaces, e.g. " Source IP" instead of "Source IP"
# We only keep the handful of fields that matter for a SIEM view.
COLUMN_MAP = {
    " Timestamp": "timestamp",
    " Source IP": "src_ip",
    " Source Port": "src_port",
    " Destination IP": "dst_ip",
    " Destination Port": "dst_port",
    " Protocol": "protocol",
    " Flow Duration": "flow_duration",
    " Total Fwd Packets": "fwd_packets",
    " Total Backward Packets": "bwd_packets",
    " Label": "label",
}

def main():
    print(f"Reading {CSV_PATH} ...")
    df = pd.read_csv(CSV_PATH)

    # Some CICIDS files use slightly different spacing - handle both cases
    df.columns = [c.strip() for c in df.columns]
    rename_map = {k.strip(): v for k, v in COLUMN_MAP.items()}
    df = df.rename(columns=rename_map)

    keep_cols = list(rename_map.values())
    df = df[keep_cols]

    print(f"Writing {len(df)} events to {OUTPUT_PATH} ...")
    with open(OUTPUT_PATH, "w") as f:
        for _, row in df.iterrows():
            event = row.to_dict()
            f.write(json.dumps(event, default=str) + "\n")

    print("Done.")

if __name__ == "__main__":
    main()
