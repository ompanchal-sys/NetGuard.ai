import streamlit as st
from scapy.all import rdpcap, sniff
#from scapy.arch.windows import get_windows_if_list
from detector import analyze
from concurrent.futures import ThreadPoolExecutor, as_completed

st.set_page_config(
    page_title="Passive Network Threat Detection",
    page_icon="🛡️",
    layout="wide"
)

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

# ==================================================
# PAGE STYLE
# ==================================================

st.markdown("""
<style>
.title {
    font-size:34px;
    font-weight:700;
}
.sub {
    color:#777;
    font-size:15px;
}
</style>
""", unsafe_allow_html=True)

st.markdown(
    '<div class="title">🛡️ Passive Network Threat Detection</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="sub">Read-Only • PCAP/PCAPNG + Live Traffic • No Blocking • No Injection • No Payload Decryption</div>',
    unsafe_allow_html=True
)

st.divider()

# ==================================================
# WINDOWS INTERFACE FUNCTIONS
# ==================================================

# def get_adapters():

#     try:
#         return get_windows_if_list()
#     except Exception:
#         return []


def real_adapters():

    result = []

    for a in get_adapters():

        name = a.get(
            "name",
            ""
        )

        desc = a.get(
            "description",
            ""
        ).lower()

        ips = a.get(
            "ips",
            []
        )

        if not ips:
            continue

        if "npcap" in desc:
            continue

        if "filter" in desc:
            continue

        if "loopback" in desc:
            continue

        if "virtual" in desc:
            continue

        if "wan miniport" in desc:
            continue

        if "teredo" in desc:
            continue

        if "6to4" in desc:
            continue

        if "ip-https" in desc:
            continue

        result.append(a)

    return result


def find_wifi():

    for a in real_adapters():

        name = a.get(
            "name",
            ""
        ).lower()

        desc = a.get(
            "description",
            ""
        ).lower()

        if (
            name == "wi-fi"
            or "wifi" in desc
            or "wireless" in desc
        ):
            return a

    return None


def capture_one(interface, duration):

    try:

        return sniff(
            iface=interface,
            timeout=duration,
            store=True
        )

    except Exception:
        return []


def capture_interfaces(interfaces, duration):

    packets = []

    if not interfaces:
        return packets

    with ThreadPoolExecutor(
        max_workers=len(interfaces)
    ) as executor:

        jobs = [
            executor.submit(
                capture_one,
                iface,
                duration
            )
            for iface in interfaces
        ]

        for job in as_completed(jobs):

            try:
                packets.extend(
                    job.result()
                )
            except Exception:
                pass

    return packets


# ==================================================
# RESULT DISPLAY
# ==================================================

def show_result(
    attack,
    score,
    evidence,
    scores,
    packet_count,
    mode
):

    if score >= 80:

        st.error(
            f"🚨 CRITICAL THREAT — {attack}"
        )

    elif score >= 60:

        st.warning(
            f"⚠️ SUSPICIOUS ACTIVITY — {attack}"
        )

    else:

        st.success(
            "✅ NETWORK APPEARS NORMAL"
        )

    c1, c2, c3, c4 = st.columns(4)

    c1.metric(
        "🎯 Risk Score",
        f"{score}/100"
    )

    c2.metric(
        "📦 Packets",
        f"{packet_count:,}"
    )

    c3.metric(
        "🚦 Status",
        "ALERT" if score >= 60 else "NORMAL"
    )

    c4.metric(
        "🔔 Alerts",
        sum(
            v >= 60
            for v in scores.values()
        )
    )

    st.subheader(
        "🔍 Detection Evidence"
    )

    st.info(evidence)

    # ==================================================
    # GRAPH
    # ==================================================

    st.subheader(
        "📊 Threat Risk Analysis"
    )

    chart_data = [
        {
            "Threat": threat,
            "Score": int(scores.get(threat, 0))
        }
        for threat in THREATS
    ]

    st.vega_lite_chart(
        {
            "data": {
                "values": chart_data
            },

            "mark": {
                "type": "bar",
                "tooltip": True
            },

            "encoding": {

                "x": {
                    "field": "Threat",
                    "type": "nominal",
                    "sort": "-y",
                    "axis": {
                        "labelAngle": -30,
                        "labelLimit": 180
                    }
                },

                "y": {
                    "field": "Score",
                    "type": "quantitative",

                    "scale": {
                        "domain": [0, 100],
                        "nice": False
                    },

                    "axis": {
                        "title": "Risk Score",
                        "values": [
                            0,
                            20,
                            40,
                            60,
                            80,
                            100
                        ]
                    }
                }
            },

            "height": 400
        },

        use_container_width=True
    )

    # ==================================================
    # SCORES
    # ==================================================

    st.subheader(
        "📋 Detailed Threat Scores"
    )

    for threat, value in sorted(
        scores.items(),
        key=lambda x: x[1],
        reverse=True
    ):

        if value >= 80:
            icon = "🚨"
        elif value >= 60:
            icon = "⚠️"
        else:
            icon = "🟢"

        c1, c2 = st.columns(
            [5, 1]
        )

        c1.write(
            f"{icon} **{threat}**"
        )

        c2.write(
            f"**{value}/100**"
        )

        st.progress(
            min(
                max(value, 0),
                100
            ) / 100
        )

    # ==================================================
    # INTERPRETATION
    # ==================================================

    st.subheader(
        "🧠 Interpretation"
    )

    if score >= 80:

        st.error(
            "Strong indicators were detected. "
            "Review the evidence and capture details."
        )

    elif score >= 60:

        st.warning(
            "Suspicious behavior was detected. "
            "The score is a heuristic risk score, not a probability."
        )

    else:

        st.success(
            "No threat category crossed the alert threshold."
        )

    # ==================================================
    # TECHNICAL DETAILS
    # ==================================================

    with st.expander(
        "🔬 Technical Details"
    ):

        st.write(
            f"**Mode:** {mode}"
        )

        st.write(
            f"**Packets:** {packet_count:,}"
        )

        st.write(
            "**Pipeline:** "
            "Packets → Features → Flow Analysis → "
            "Threat Scoring → Alert"
        )

        st.write(
            "**Analysis:** Passive / Read-Only"
        )

        st.write(
            "**Blocking:** Disabled"
        )

        st.write(
            "**Packet Modification:** Disabled"
        )

        st.write(
            "**Payload Decryption:** Disabled"
        )


# ==================================================
# SIDEBAR
# ==================================================

with st.sidebar:

    st.header(
        "⚙️ Control Panel"
    )

    mode = st.radio(
        "Analysis Mode",
        [
            "📁 PCAP / PCAPNG",
            "🌐 Live Network"
        ]
    )

    st.divider()

    st.subheader(
        "🛡️ Detection Categories"
    )

    for threat in THREATS:
        st.write(
            "•",
            threat
        )

    st.divider()

    st.caption(
        "Passive IDS"
    )

    st.caption(
        "Read-Only Analysis"
    )


# ==================================================
# PCAP MODE
# ==================================================

if mode == "📁 PCAP / PCAPNG":

    st.header(
        "📁 PCAP / PCAPNG Analysis"
    )

    st.write(
        "Upload a network capture for passive analysis."
    )

    uploaded = st.file_uploader(
        "Choose PCAP / PCAPNG file",
        type=[
            "pcap",
            "pcapng"
        ]
    )

    if uploaded:

        c1, c2, c3 = st.columns(3)

        c1.metric(
            "📄 File",
            uploaded.name
        )

        c2.metric(
            "💾 Size",
            f"{uploaded.size / 1024:.1f} KB"
        )

        c3.metric(
            "📦 Format",
            uploaded.name
            .split(".")[-1]
            .upper()
        )

        st.divider()

        if st.button(
            "🔍 Analyze Network Capture",
            type="primary",
            use_container_width=True
        ):

            try:

                with st.spinner(
                    "Analyzing network capture..."
                ):

                    packets = rdpcap(
                        uploaded
                    )

                    attack, score, evidence, scores = analyze(
                        packets
                    )

                st.success(
                    f"✓ {len(packets):,} packets processed."
                )

                show_result(
                    attack,
                    score,
                    evidence,
                    scores,
                    len(packets),
                    "PCAP / PCAPNG"
                )

            except Exception as error:

                st.error(
                    "❌ PCAP analysis failed."
                )

                with st.expander(
                    "🔧 Technical Error"
                ):

                    st.code(
                        str(error)
                    )


# ==================================================
# LIVE MODE
# ==================================================

else:

    st.header(
        "🌐 Live Network Monitoring"
    )

    st.write(
        "Passively monitor your laptop's network traffic."
    )

    st.info(
        "🔒 Passive mode: traffic is only observed. "
        "Nothing is blocked, modified, injected, or decrypted."
    )

    # ONLY TWO OPTIONS
    option = st.radio(
        "🌐 Monitoring Scope",

        [
            "📶 WiFi",
            "💻 Whole Laptop Networking"
        ],

        horizontal=True
    )

    duration = st.slider(
        "⏱️ Capture Duration",
        5,
        60,
        10,
        5
    )

    st.divider()

    # ==================================================
    # WIFI
    # ==================================================

    if option == "📶 WiFi":

        wifi = find_wifi()

        if wifi:

            st.success(
                "📶 WiFi adapter detected"
            )

            st.caption(
                wifi.get(
                    "description",
                    "Wi-Fi"
                )
            )

        else:

            st.error(
                "❌ WiFi adapter was not detected."
            )

            st.stop()

    # ==================================================
    # WHOLE LAPTOP
    # ==================================================

    else:

        adapters = real_adapters()

        if not adapters:

            st.error(
                "❌ No usable network adapter detected."
            )

            st.stop()

        st.success(
            f"💻 {len(adapters)} physical/active network adapter(s) available."
        )

        names = [
            a.get(
                "name",
                ""
            )
            for a in adapters
        ]

        st.caption(
            "Monitoring active physical adapters only."
        )

    st.divider()

    # ==================================================
    # START
    # ==================================================

    if st.button(
        "▶️ Start Passive Capture",
        type="primary",
        use_container_width=True
    ):

        try:

            # WiFi capture
            if option == "📶 WiFi":

                interface = wifi["name"]

                st.info(
                    "📶 Capturing from Wi-Fi..."
                )

                with st.spinner(
                    f"Capturing for {duration} seconds..."
                ):

                    packets = capture_one(
                        interface,
                        duration
                    )

            # Whole laptop capture
            else:

                interfaces = [
                    a["name"]
                    for a in adapters
                    if a.get("name")
                ]

                st.info(
                    f"💻 Capturing from {len(interfaces)} "
                    "active network interface(s)..."
                )

                with st.spinner(
                    f"Capturing for {duration} seconds..."
                ):

                    packets = capture_interfaces(
                        interfaces,
                        duration
                    )

            # ==================================================
            # ANALYZE
            # ==================================================

            if packets:

                st.success(
                    f"✓ {len(packets):,} packets captured."
                )

                with st.spinner(
                    "Analyzing captured traffic..."
                ):

                    attack, score, evidence, scores = analyze(
                        packets
                    )

                show_result(
                    attack,
                    score,
                    evidence,
                    scores,
                    len(packets),
                    option
                )

            else:

                st.warning(
                    "⚠️ No packets captured."
                )

                st.info(
                    "Make sure your laptop is actively using "
                    "the selected network connection and that "
                    "Npcap is installed."
                )

        except Exception as error:

            st.error(
                "❌ Live capture failed."
            )

            with st.expander(
                "🔧 Technical Error"
            ):

                st.code(
                    str(error)
                )


# ==================================================
# FOOTER
# ==================================================

st.divider()

st.caption(
    "🛡️ Passive IDS • Flow-Based Detection • "
    "Read-Only • No Blocking • No Injection • "
    "No Payload Decryption"
)