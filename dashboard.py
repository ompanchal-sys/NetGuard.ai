import platform
from concurrent.futures import ThreadPoolExecutor, as_completed

import streamlit as st
from scapy.all import rdpcap, sniff

from detector import analyze


# ==================================================
# CONFIGURATION
# ==================================================

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

IS_WINDOWS = platform.system().lower() == "windows"


# ==================================================
# WINDOWS-ONLY IMPORT
# ==================================================

if IS_WINDOWS:
    try:
        from scapy.arch.windows import get_windows_if_list
    except Exception:
        get_windows_if_list = None
else:
    get_windows_if_list = None


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

div.stButton > button {
    font-weight:600;
}
</style>
""", unsafe_allow_html=True)


st.markdown(
    '<div class="title">🛡️ Passive Network Threat Detection</div>',
    unsafe_allow_html=True
)

if IS_WINDOWS:
    subtitle = (
        "Read-Only • PCAP/PCAPNG + Live Traffic • "
        "No Blocking • No Injection • No Payload Decryption"
    )
else:
    subtitle = (
        "Read-Only • PCAP/PCAPNG Analysis • "
        "No Blocking • No Injection • No Payload Decryption"
    )

st.markdown(
    f'<div class="sub">{subtitle}</div>',
    unsafe_allow_html=True
)

st.divider()


# ==================================================
# WINDOWS NETWORK ADAPTER FUNCTIONS
# ==================================================

def get_adapters():
    """Return Windows network adapters."""
    
    if not IS_WINDOWS or get_windows_if_list is None:
        return []

    try:
        return get_windows_if_list()
    except Exception:
        return []


def real_adapters():
    """Return usable physical/active Windows adapters."""

    result = []

    for adapter in get_adapters():

        name = adapter.get("name", "")

        description = adapter.get(
            "description",
            ""
        ).lower()

        ips = adapter.get(
            "ips",
            []
        )

        if not ips:
            continue

        # Ignore Npcap/filter interfaces
        if "npcap" in description:
            continue

        if "filter" in description:
            continue

        # Ignore loopback
        if "loopback" in description:
            continue

        # Ignore virtual adapters
        if "virtual" in description:
            continue

        # Ignore Windows WAN adapters
        if "wan miniport" in description:
            continue

        if "teredo" in description:
            continue

        if "6to4" in description:
            continue

        if "ip-https" in description:
            continue

        result.append(adapter)

    return result


def find_wifi():
    """Find the Windows Wi-Fi adapter."""

    for adapter in real_adapters():

        name = adapter.get(
            "name",
            ""
        ).lower()

        description = adapter.get(
            "description",
            ""
        ).lower()

        if (
            name == "wi-fi"
            or "wifi" in description
            or "wireless" in description
        ):
            return adapter

    return None


# ==================================================
# LIVE PACKET CAPTURE
# ==================================================

def capture_one(interface, duration):

    try:

        packets = sniff(
            iface=interface,
            timeout=duration,
            store=True
        )

        return packets, None

    except Exception as error:

        return [], str(error)


def capture_interfaces(interfaces, duration):

    packets = []
    errors = []

    if not interfaces:
        return packets, errors

    with ThreadPoolExecutor(
        max_workers=len(interfaces)
    ) as executor:

        jobs = [
            executor.submit(
                capture_one,
                interface,
                duration
            )
            for interface in interfaces
        ]

        for job in as_completed(jobs):

            try:

                result, error = job.result()

                packets.extend(result)

                if error:
                    errors.append(error)

            except Exception as error:

                errors.append(str(error))

    return packets, errors


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

    # ------------------------------------------------
    # MAIN STATUS
    # ------------------------------------------------

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


    # ------------------------------------------------
    # METRICS
    # ------------------------------------------------

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
            value >= 60
            for value in scores.values()
        )
    )


    # ------------------------------------------------
    # EVIDENCE
    # ------------------------------------------------

    st.subheader(
        "🔍 Detection Evidence"
    )

    st.info(evidence)


    # ------------------------------------------------
    # THREAT GRAPH
    # ------------------------------------------------

    st.subheader(
        "📊 Threat Risk Analysis"
    )

    chart_data = [
        {
            "Threat": threat,
            "Score": int(
                scores.get(threat, 0)
            )
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


    # ------------------------------------------------
    # DETAILED SCORES
    # ------------------------------------------------

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

        c1, c2 = st.columns([5, 1])

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


    # ------------------------------------------------
    # INTERPRETATION
    # ------------------------------------------------

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
            "The score is a heuristic risk score, "
            "not a probability."
        )

    else:

        st.success(
            "No threat category crossed "
            "the alert threshold."
        )


    # ------------------------------------------------
    # TECHNICAL DETAILS
    # ------------------------------------------------

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

    st.sidebar.header("⚙️ Control Panel")

    mode = st.sidebar.radio(
        "Select Analysis Mode",
        ["📁 PCAP / PCAPNG", "🌐 Live Network"]
    )

    if not IS_WINDOWS:
    #     if mode == "🌐 Live Network":
    #         st.sidebar.warning(
    #             "⚠️ Live Network capture requires the local Windows application."
    #     )

        st.info(
            "☁️ Cloud Mode\n\n"
            "PCAP / PCAPNG analysis is available. "
            "Live laptop capture requires the "
            "local Windows application."
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
# PCAP / PCAPNG MODE
# ==================================================

if mode == "📁 PCAP / PCAPNG":

    st.header(
        "📁 PCAP / PCAPNG Analysis"
    )

    st.write(
        "Upload a network capture "
        "for passive threat analysis."
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

                    (
                        attack,
                        score,
                        evidence,
                        scores
                    ) = analyze(
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


    else:

        st.info(
            "👆 Upload a PCAP or PCAPNG file "
            "to begin analysis."
        )


# ==================================================
# LIVE NETWORK MODE
# ==================================================

elif mode == "🌐 Live Network":

    if not IS_WINDOWS:
        st.header("🌐 Live Network Monitoring")

        st.warning(
            "⚠️ Live Network capture is available only "
            "when this application is running locally on Windows."
        )

        st.info(
            "The Streamlit Cloud server cannot access "
            "your laptop's Wi-Fi or network adapters."
        )

        st.stop()

    st.header(
        "🌐 Live Network Monitoring"
    )

    st.write(
        "Passively monitor your laptop's "
        "network traffic."
    )

    st.info(
        "🔒 Passive mode: traffic is only observed. "
        "Nothing is blocked, modified, injected, "
        "or decrypted."
    )


    # ------------------------------------------------
    # MONITORING SCOPE
    # ------------------------------------------------

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

        min_value=5,
        max_value=60,
        value=10,
        step=5
    )


    st.divider()


    # ------------------------------------------------
    # WIFI
    # ------------------------------------------------

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


    # ------------------------------------------------
    # WHOLE LAPTOP
    # ------------------------------------------------

    else:

        adapters = real_adapters()


        if not adapters:

            st.error(
                "❌ No usable network adapter detected."
            )

            st.stop()


        st.success(
            f"💻 {len(adapters)} "
            "physical/active network adapter(s) available."
        )

        st.caption(
            "Monitoring active physical adapters only."
        )


    st.divider()


    # ------------------------------------------------
    # START CAPTURE
    # ------------------------------------------------

    if st.button(
        "▶️ Start Passive Capture",
        type="primary",
        use_container_width=True
    ):

        try:

            # =========================================
            # WIFI CAPTURE
            # =========================================

            if option == "📶 WiFi":

                interface = wifi.get("name")

                st.info(
                    "📶 Capturing from Wi-Fi..."
                )


                with st.spinner(
                    f"Capturing for {duration} seconds..."
                ):

                    packets, error = capture_one(
                        interface,
                        duration
                    )


                if error:

                    st.error(
                        "❌ Wi-Fi capture failed."
                    )

                    with st.expander(
                        "🔧 Technical Error"
                    ):

                        st.code(error)

                    st.stop()


            # =========================================
            # WHOLE LAPTOP CAPTURE
            # =========================================

            else:

                interfaces = [
                    adapter.get("name")
                    for adapter in adapters
                    if adapter.get("name")
                ]


                st.info(
                    f"💻 Capturing from "
                    f"{len(interfaces)} active "
                    "network interface(s)..."
                )


                with st.spinner(
                    f"Capturing for {duration} seconds..."
                ):

                    packets, errors = capture_interfaces(
                        interfaces,
                        duration
                    )


                if errors:

                    with st.expander(
                        "⚠️ Capture warnings"
                    ):

                        for error in errors:

                            st.code(error)


            # =========================================
            # ANALYZE
            # =========================================

            if packets:

                st.success(
                    f"✓ {len(packets):,} packets captured."
                )


                with st.spinner(
                    "Analyzing captured traffic..."
                ):

                    (
                        attack,
                        score,
                        evidence,
                        scores
                    ) = analyze(
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
                    "Make sure your laptop is actively "
                    "using the selected network connection "
                    "and that Npcap is installed."
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