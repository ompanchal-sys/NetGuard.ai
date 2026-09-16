from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR
from collections import defaultdict, deque
from datetime import datetime, timezone
import statistics, time, json, math

MIN_PACKETS = 20
THRESHOLD = 60
THREATS = [
    "SYN Flood",
    "UDP Amplification",
    "Source Flood",
    "C2 Beaconing",
    "DGA / DNS Tunnelling",
    "Encrypted Traffic Anomaly",
    "Port Scanning",
    "Data Exfiltration"
]

def packet_time(p):
    try:
        return float(p.time)
    except:
        return time.time()

def packet_rate(packets):
    if len(packets) < 2:
        return 0
    times = [packet_time(p) for p in packets]
    d = max(times) - min(times)
    return len(packets) / d if d > 0 else 0

def entropy(text):
    if not text:
        return 0
    n = len(text)
    return -sum(
        (text.count(c) / n) * math.log2(text.count(c) / n)
        for c in set(text)
    )

def analyze(packets):
    scores = {t: 0 for t in THREATS}

    if len(packets) < MIN_PACKETS:
        return "No Threat", 0, "Not enough packets for analysis", scores

    sources = defaultdict(int)
    destinations = defaultdict(int)
    ports = defaultdict(set)
    flows = defaultdict(lambda: [0, 0, []])
    communications = defaultdict(list)
    dns_queries = []

    syn = 0
    synack = 0
    udp = 0
    total_bytes = 0
    ip_packets = 0

    for p in packets:

        if IP not in p:
            continue

        ip = p[IP]

        sources[ip.src] += 1
        destinations[ip.dst] += 1
        total_bytes += len(p)
        ip_packets += 1

        if TCP in p:

            tcp = p[TCP]

            key = (
                ip.src,
                ip.dst,
                tcp.sport,
                tcp.dport
            )

            flows[key][0] += 1
            flows[key][1] += len(p)
            flows[key][2].append(packet_time(p))

            ports[ip.src].add(tcp.dport)

            flags = int(tcp.flags)

            if flags & 2 and not flags & 16:
                syn += 1

            if flags & 2 and flags & 16:
                synack += 1

        elif UDP in p:
            udp += 1

        communications[
            (ip.src, ip.dst)
        ].append(packet_time(p))

        if DNS in p and DNSQR in p:

            try:
                q = p[DNSQR].qname.decode(
                    errors="ignore"
                ).rstrip(".")

                if q:
                    dns_queries.append(q)

            except:
                pass

    if not ip_packets:
        return (
            "No Threat",
            0,
            "No IPv4 packets available for analysis",
            scores
        )

    rate = packet_rate(packets)

    times = [
        packet_time(p)
        for p in packets
    ]

    duration = max(times) - min(times)

    syn_rate = syn / max(duration, 1)
    synack_ratio = synack / max(syn, 1)

    # ------------------------------------------------
    # 1. SYN FLOOD
    # ------------------------------------------------

    if (
        syn >= 30
        and syn_rate >= 20
        and synack_ratio < 0.30
    ):
        scores["SYN Flood"] = min(
            100,
            70 + int(min(30, syn_rate / 10))
        )

    # ------------------------------------------------
    # 2. UDP AMPLIFICATION
    # ------------------------------------------------

    non_quic_udp = sum(
        1
        for p in packets
        if UDP in p
        and p[UDP].sport not in (443, 8443)
        and p[UDP].dport not in (443, 8443)
    )

    if (
        non_quic_udp >= 100
        and udp / max(len(packets), 1) > 0.70
        and rate >= 50
    ):
        scores["UDP Amplification"] = 75

    # ------------------------------------------------
    # 3. SOURCE FLOOD
    # ------------------------------------------------

    unique_sources = len(sources)

    if unique_sources >= 30 and rate >= 50:
        scores["Source Flood"] = min(
            100,
            60 + unique_sources // 10
        )

    # ------------------------------------------------
    # 4. PORT SCANNING
    # ------------------------------------------------

    max_ports = max(
        (len(x) for x in ports.values()),
        default=0
    )

    if max_ports >= 20:
        scores["Port Scanning"] = 85

    # ------------------------------------------------
    # 5. DGA / DNS TUNNELLING
    # ------------------------------------------------

    if len(dns_queries) >= 10:

        average_length = (
            sum(map(len, dns_queries))
            / len(dns_queries)
        )

        long_domains = sum(
            len(x) >= 45
            for x in dns_queries
        )

        average_entropy = (
            sum(entropy(x) for x in dns_queries)
            / len(dns_queries)
        )

        if (
            long_domains >= 5
            and average_length >= 30
            and average_entropy >= 3.2
        ):
            scores["DGA / DNS Tunnelling"] = 80

    # ------------------------------------------------
    # 6. ENCRYPTED TRAFFIC ANOMALY
    # ------------------------------------------------

    encrypted_flows = sum(
        v[0] >= 20
        and v[1] >= 30000
        and k[3] in (443, 8443)
        for k, v in flows.items()
    )

    if encrypted_flows >= 10:
        scores["Encrypted Traffic Anomaly"] = 65

    # ------------------------------------------------
    # 7. DATA EXFILTRATION
    # ------------------------------------------------

    large_flows = sum(
        v[1] >= 300000
        for v in flows.values()
    )

    if (
        large_flows >= 3
        or total_bytes >= 5000000
    ):
        scores["Data Exfiltration"] = 75

    # ------------------------------------------------
    # 8. C2 BEACONING
    # ------------------------------------------------

    for timestamps in communications.values():

        if len(timestamps) < 15:
            continue

        timestamps.sort()

        intervals = [
            timestamps[i] - timestamps[i - 1]
            for i in range(1, len(timestamps))
            if timestamps[i] - timestamps[i - 1] >= 0.5
        ]

        if len(intervals) < 10:
            continue

        median_interval = statistics.median(
            intervals
        )

        regularity = (
            sum(
                abs(x - median_interval)
                <= median_interval * 0.15
                for x in intervals
            )
            / len(intervals)
            * 100
        )

        if (
            timestamps[-1] - timestamps[0] >= 20
            and regularity >= 75
        ):
            scores["C2 Beaconing"] = 80
            break

    # ------------------------------------------------
    # FINAL RESULT
    # ------------------------------------------------

    attack, score = max(
        scores.items(),
        key=lambda x: x[1]
    )

    if score < THRESHOLD:

        return (
            "No Threat",
            0,
            "No suspicious pattern crossed the alert threshold",
            scores
        )

    evidence = {

        "SYN Flood":
            f"SYN={syn}, rate={syn_rate:.1f}/s, "
            f"SYN/ACK ratio={synack_ratio:.2f}",

        "UDP Amplification":
            f"UDP={non_quic_udp}, rate={rate:.1f}/s",

        "Source Flood":
            f"{unique_sources} unique sources, "
            f"packet rate={rate:.1f}/s",

        "C2 Beaconing":
            "Periodic communication pattern detected",

        "DGA / DNS Tunnelling":
            f"{len(dns_queries)} DNS queries analyzed",

        "Encrypted Traffic Anomaly":
            f"{encrypted_flows} persistent encrypted flows",

        "Port Scanning":
            f"Source contacted {max_ports} destination ports",

        "Data Exfiltration":
            f"{large_flows} large flows, "
            f"{total_bytes / 1024 / 1024:.2f} MB total"
    }

    return (
        attack,
        score,
        evidence.get(
            attack,
            "Multiple indicators matched"
        ),
        scores
    )

def alert(attack, score, evidence):

    data = {
        "timestamp":
            datetime.now(timezone.utc).isoformat(),

        "threat_class":
            attack,

        "risk_score":
            score,

        "supporting_evidence":
            evidence,

        "analysis_mode":
            "Passive / Read-Only",

        "payload_inspection":
            False,

        "blocking":
            False
    }

    print("\n" + "=" * 60)
    print("🚨 THREAT ALERT")
    print(json.dumps(data, indent=2))
    print("=" * 60)

def analyze_pcap(path):

    packets = rdpcap(path)

    return analyze(packets)

if __name__ == "__main__":

    path = input(
        "PCAP path: "
    ).strip("'\"")

    try:

        packets = rdpcap(path)

        attack, score, evidence, scores = analyze(
            packets
        )

        print(
            f"\nRESULT: {attack} | {score}/100"
        )

        print(
            "Evidence:",
            evidence
        )

        print(
            "Scores:",
            scores
        )

        if attack != "No Threat":
            alert(
                attack,
                score,
                evidence
            )

    except Exception as error:
        print(
            "ERROR:",
            error
        )