import pandas as pd
import json
import sys

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

def load_csv(csv_path, output_path):
    print(f"Reading {csv_path} ...")
   
    print(f"Reading {csv_path} ...")
    try:
        df = pd.read_csv(csv_path)
    except UnicodeDecodeError:
        print("UTF-8 failed, retrying with Windows-1252 encoding...")
        df = pd.read_csv(csv_path, encoding="cp1252")    

    df.columns = [c.strip() for c in df.columns]
    rename_map = {k.strip(): v for k, v in COLUMN_MAP.items()}
    df = df.rename(columns=rename_map)

    keep_cols = list(rename_map.values())
    df = df[keep_cols]

    print(f"Writing {len(df)} events to {output_path} ...")
    with open(output_path, "w") as f:
        for _, row in df.iterrows():
            event = row.to_dict()
            f.write(json.dumps(event, default=str) + "\n")

    # Quick label breakdown, so we can immediately see attack counts
    print("Label breakdown:")
    print(df["label"].value_counts())
    print("Done.\n")


if __name__ == "__main__":
    # Usage: python3 cicids_loader.py <csv_filename> <output_filename>
    csv_name = sys.argv[1]
    output_name = sys.argv[2]
    load_csv(f"datasets/TrafficLabelling/{csv_name}", f"logs/cicids/{output_name}")
