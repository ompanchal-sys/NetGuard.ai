import os
import pandas as pd

from scapy.all import PcapReader
from detector import extract_features


# ============================================================
# CONFIGURATION
# ============================================================

DATASET_DIR = r"C:\Users\dell\OneDrive\Desktop\dataset"
OUTPUT_FILE = "training_data.csv"

# Window size used to create samples from each PCAP
WINDOW_SECONDS = 5

# Ignore very small windows
MIN_PACKETS = 20


# ============================================================
# PCAP -> LABEL MAPPING
# ============================================================
#
# IMPORTANT:
# These labels are based on your current dataset/file names.
# Do NOT add a label unless the PCAP is actually known to
# contain that behavior.
#

LABELS = {
    "NORMAL.pcapng": "BENIGN",

    "c2 beconing.pcap": "C2_BEACONING",

    "dns tunnelling.pcap": "DGA_DNS_TUNNEL",

    "flood.pcap": "DDOS",

    "source flood.pcap": "DDOS",

    "synflood.pcap": "DDOS",

    "port scanning.pcap": "PORT_SCAN",
}


# ============================================================
# READ PCAP
# ============================================================

def read_pcap(path):
    """
    Read packets from a PCAP/PCAPNG file.

    Returns:
        list of packets
    """

    packets = []

    try:
        with PcapReader(path) as reader:
            for packet in reader:
                packets.append(packet)

    except Exception as e:
        print(f"ERROR reading {path}: {e}")
        return []

    return packets


# ============================================================
# CREATE WINDOWS
# ============================================================

def create_windows(packets, window_seconds):
    """
    Split packets into time-based windows.

    Each window contains packets belonging to approximately
    the same time interval.
    """

    if not packets:
        return []

    # Keep only packets that have timestamps
    packets = [
        p for p in packets
        if hasattr(p, "time")
    ]

    if not packets:
        return []

    start_time = float(packets[0].time)

    windows = []
    current_window = []

    for packet in packets:

        packet_time = float(packet.time)

        elapsed = packet_time - start_time

        # Start a new window
        if elapsed >= window_seconds and current_window:

            windows.append(current_window)

            current_window = []

            # Move the reference time forward
            start_time = packet_time

        current_window.append(packet)

    # Add final window
    if current_window:
        windows.append(current_window)

    return windows


# ============================================================
# PROCESS ONE PCAP
# ============================================================

def process_pcap(filename, label):

    path = os.path.join(DATASET_DIR, filename)

    print("\n" + "=" * 70)
    print(f"PCAP: {filename}")
    print(f"LABEL: {label}")
    print("=" * 70)

    if not os.path.exists(path):
        print("WARNING: File not found")
        return []

    packets = read_pcap(path)

    print(f"Packets read: {len(packets)}")

    if not packets:
        return []

    windows = create_windows(
        packets,
        WINDOW_SECONDS
    )

    print(f"Windows created: {len(windows)}")

    rows = []

    # ========================================================
    # PROCESS EACH WINDOW
    # ========================================================

    for window_id, window_packets in enumerate(windows):

        if len(window_packets) < MIN_PACKETS:
            continue

        try:
            features = extract_features(window_packets)

        except Exception as e:
            print(
                f"WARNING: Feature extraction failed "
                f"for window {window_id}: {e}"
            )
            continue

        if not features:
            continue

        # ----------------------------------------------------
        # Capture-level metadata
        # ----------------------------------------------------

        features["label"] = label

        # Original PCAP identity
        features["capture_id"] = filename

        # Window identity
        features["window_id"] = window_id

        # Useful for debugging/reproducibility
        features["source_file"] = filename

        rows.append(features)

    print(f"Usable windows: {len(rows)}")

    return rows


# ============================================================
# BUILD DATASET
# ============================================================

def build_dataset():

    all_rows = []

    print("\n")
    print("=" * 70)
    print("PASSIVE NETWORK THREAT DATASET BUILDER")
    print("=" * 70)

    print(f"Dataset directory : {DATASET_DIR}")
    print(f"Window size       : {WINDOW_SECONDS} seconds")
    print(f"Minimum packets   : {MIN_PACKETS}")

    # --------------------------------------------------------
    # Process only explicitly labelled PCAPs
    # --------------------------------------------------------

    for filename, label in LABELS.items():

        rows = process_pcap(
            filename,
            label
        )

        all_rows.extend(rows)

    # --------------------------------------------------------
    # Check result
    # --------------------------------------------------------

    if not all_rows:

        print("\nERROR: No training samples were generated.")
        return

    df = pd.DataFrame(all_rows)

    # --------------------------------------------------------
    # Put metadata at the end
    # --------------------------------------------------------

    metadata_columns = [
        "label",
        "capture_id",
        "window_id",
        "source_file"
    ]

    feature_columns = [
        col
        for col in df.columns
        if col not in metadata_columns
    ]

    df = df[
        feature_columns +
        metadata_columns
    ]

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    df.to_csv(
        OUTPUT_FILE,
        index=False
    )

    # ========================================================
    # SUMMARY
    # ========================================================

    print("\n")
    print("=" * 70)
    print("DATASET CREATED")
    print("=" * 70)

    print(f"Output file: {OUTPUT_FILE}")
    print(f"Total samples: {len(df)}")

    print("\nSamples per class:")
    print(
        df["label"]
        .value_counts()
        .to_string()
    )

    print("\nSamples per capture:")
    print(
        df["capture_id"]
        .value_counts()
        .to_string()
    )

    print("\nDataset columns:")
    print(
        df.columns.tolist()
    )

    print("\nCapture IDs:")
    for capture_id in df["capture_id"].unique():
        count = len(
            df[df["capture_id"] == capture_id]
        )

        label = df[
            df["capture_id"] == capture_id
        ]["label"].iloc[0]

        print(
            f"  {capture_id:30s} "
            f"{label:20s} "
            f"{count:4d} windows"
        )

    print("\nDone.")


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    build_dataset()