import platform
import streamlit as st
from scapy.all import rdpcap, sniff
from detector import analyze, extract_features
from concurrent.futures import ThreadPoolExecutor, as_completed

# Windows-only Scapy adapter API.
# Streamlit Cloud runs Linux, so NEVER import scapy.arch.windows there.
if platform.system() == "Windows":
    from scapy.arch.windows import get_windows_if_list
else:
    get_windows_if_list = None


# =========================================================
# PAGE CONFIG
# =========================================================

st.set_page_config(
    page_title="Sentinel IDS",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# =========================================================
# CUSTOM CSS
# =========================================================

st.markdown("""
<style>
.stApp {
    background:
        radial-gradient(circle at 15% 10%, rgba(25,118,210,0.12), transparent 28%),
        radial-gradient(circle at 85% 20%, rgba(0,188,212,0.08), transparent 25%),
        #07111f;
    color: #e8eef7;
}

[data-testid="stHeader"] {
    background: rgba(0,0,0,0);
}

[data-testid="stSidebar"] {
    background: #091625;
    border-right: 1px solid #1b3148;
}

[data-testid="stSidebar"] * {
    color: #dce7f5;
}

.hero {
    padding: 25px 30px;
    border-radius: 18px;
    background:
        linear-gradient(
            135deg,
            rgba(17,40,67,0.95),
            rgba(7,22,38,0.95)
        );
    border: 1px solid #1d3b57;
    box-shadow: 0 10px 35px rgba(0,0,0,0.25);
    margin-bottom: 20px;
}

.hero-title {
    font-size: 34px;
    font-weight: 800;
    letter-spacing: -0.5px;
}

.hero-subtitle {
    color: #8fa8c1;
    font-size: 14px;
    margin-top: 7px;
}

.status-card {
    padding: 20px 24px;
    border-radius: 16px;
    background: #0c1b2b;
    border: 1px solid #1b344c;
    margin-bottom: 20px;
}

.status-normal {
    border-left: 5px solid #21c77a;
}

.status-warning {
    border-left: 5px solid #f5b942;
}

.status-danger {
    border-left: 5px solid #ff4d67;
}

.status-title {
    font-size: 22px;
    font-weight: 750;
}

.status-small {
    color: #8fa8c1;
    font-size: 13px;
    margin-top: 4px;
}

div[data-testid="stMetric"] {
    background: linear-gradient(145deg, #0d2033, #091827);
    border: 1px solid #1b3b56;
    padding: 17px;
    border-radius: 15px;
    box-shadow: 0 8px 20px rgba(0,0,0,0.20);
}

div[data-testid="stMetricLabel"] {
    color: #8fa8c1 !important;
}

div[data-testid="stMetricValue"] {
    color: #f2f7fc !important;
    font-weight: 750;
}

.section-title {
    font-size: 21px;
    font-weight: 750;
    margin-top: 28px;
    margin-bottom: 12px;
    color: #eaf3ff;
}

.info-card {
    background: #0b1b2b;
    border: 1px solid #19364f;
    border-radius: 14px;
    padding: 18px;
    height: 100%;
}

.info-label {
    color: #7894ad;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 1px;
}

.info-value {
    font-size: 20px;
    font-weight: 700;
    margin-top: 5px;
}

.sidebar-logo {
    text-align: center;
    padding: 10px 0 20px 0;
}

.sidebar-logo-icon {
    font-size: 42px;
}

.sidebar-logo-title {
    font-size: 21px;
    font-weight: 800;
}

.sidebar-logo-sub {
    color: #718ba4;
    font-size: 12px;
}

.footer {
    text-align: center;
    color: #587087;
    font-size: 12px;
    padding: 25px 0 5px 0;
}
</style>
""", unsafe_allow_html=True)


# =========================================================
# THREATS
# =========================================================

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


# =========================================================
# HEADER
# =========================================================

st.markdown("""<div class="hero">
<div class="hero-title">🛡️ SENTINEL</div>
<div class="hero-subtitle">Passive Network Threat Detection &amp; Security Analytics</div>
<div class="hero-subtitle">Flow-Based IDS • PCAP Analysis • Live Monitoring • Machine Learning</div>
</div>""", unsafe_allow_html=True)


# =========================================================
# NETWORK FUNCTIONS
# =========================================================

def get_adapters():
    """Safely get Windows network adapters.

    Returns an empty list on Linux/Streamlit Cloud because the Windows
    adapter API is not available there.
    """
    if platform.system() != "Windows" or get_windows_if_list is None:
        return []

    try:
        return get_windows_if_list()
    except Exception:
        return []


def real_adapters():
    """Return usable physical adapters."""
    result = []
    ignored = [
        "npcap",
        "filter",
        "loopback",
        "virtual",
        "wan miniport",
        "teredo",
        "6to4",
        "ip-https"
    ]

    for adapter in get_adapters():
        description = str(adapter.get("description", "")).lower()
        ips = adapter.get("ips", [])

        if not ips:
            continue
        if any(x in description for x in ignored):
            continue

        result.append(adapter)

    return result


def find_wifi():
    """Find Wi-Fi adapter."""
    for adapter in real_adapters():
        name = str(adapter.get("name", "")).lower()
        description = str(adapter.get("description", "")).lower()

        if (
            name == "wi-fi"
            or "wifi" in description
            or "wireless" in description
        ):
            return adapter

    return None


def capture_one(interface, duration):
    """Capture packets from one interface."""
    try:
        packets = sniff(
            iface=interface,
            timeout=duration,
            store=True
        )
        return packets
    except Exception:
        st.warning(f"Capture failed on interface: {interface}")
        return []


def capture_interfaces(interfaces, duration):
    """Capture from multiple interfaces."""
    packets = []
    if not interfaces:
        return packets

    with ThreadPoolExecutor(max_workers=len(interfaces)) as executor:
        jobs = [
            executor.submit(capture_one, interface, duration)
            for interface in interfaces
        ]
        for job in as_completed(jobs):
            try:
                result = job.result()
                if result:
                    packets.extend(result)
            except Exception:
                pass

    return packets


# =========================================================
# ML
# =========================================================

def get_ml(packets):
    try:
        if not packets:
            return "Unavailable", 0.0

        # Load the ML module only when ML analysis is requested.
        # This prevents a missing/incompatible threat_model.pkl from
        # crashing the whole dashboard during startup.
        from ml_model import predict_ml

        features = extract_features(packets)
        if not features:
            return "Unavailable", 0.0

        ml_attack, ml_confidence = predict_ml(features)

        try:
            ml_confidence = float(ml_confidence)
        except Exception:
            ml_confidence = 0.0

        if ml_confidence > 1:
            ml_confidence = ml_confidence / 100

        ml_confidence = max(0.0, min(1.0, ml_confidence))
        return ml_attack, ml_confidence

    except Exception:
        return "Unavailable", 0.0


# =========================================================
# RESULT DASHBOARD
# =========================================================

def show_result(
    attack,
    score,
    evidence,
    scores,
    packet_count,
    mode,
    ml_attack,
    ml_confidence
):
    try:
        score = int(score)
    except Exception:
        score = 0

    score = max(0, min(100, score))

    if not isinstance(scores, dict):
        scores = {}

    for threat in THREATS:
        if threat not in scores:
            scores[threat] = 0
        try:
            scores[threat] = int(scores[threat])
        except Exception:
            scores[threat] = 0
        scores[threat] = max(0, min(100, scores[threat]))

    if score >= 80:
        status_class = "status-danger"
        status_icon = "🚨"
        status_title = "CRITICAL THREAT DETECTED"
        status_text = f"{attack} pattern crossed the critical threshold."
    elif score >= 60:
        status_class = "status-warning"
        status_icon = "⚠️"
        status_title = "SUSPICIOUS ACTIVITY DETECTED"
        status_text = f"{attack} indicators were detected."
    else:
        status_class = "status-normal"
        status_icon = "🟢"
        status_title = "NETWORK APPEARS NORMAL"
        status_text = "No threat category crossed the alert threshold."

    st.markdown(
        f"""<div class="status-card {status_class}">
<div class="status-title">{status_icon} {status_title}</div>
<div class="status-small">{status_text}</div>
</div>""",
        unsafe_allow_html=True
    )

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("🎯 Threat Confidence", f"{score}%")
    c2.metric("🤖 ML Classification", str(ml_attack))
    c3.metric("🧠 ML Confidence", f"{ml_confidence * 100:.2f}%")
    c4.metric("📦 Packets", f"{packet_count:,}")
    c5.metric("🚦 Status", "ALERT" if score >= 60 else "NORMAL")

    st.markdown('<div class="section-title">🔍 Detection Summary</div>', unsafe_allow_html=True)
    left, right = st.columns([2, 1])

    with left:
        st.markdown(
            f"""<div class="info-card">
<div class="info-label">Detected Threat</div>
<div class="info-value">{attack}</div>
<br>
<div class="info-label">Supporting Evidence</div>
<div style="margin-top:8px;color:#b5c7d9;">{evidence}</div>
</div>""",
            unsafe_allow_html=True
        )

    with right:
        st.markdown(
            f"""<div class="info-card">
<div class="info-label">Analysis Mode</div>
<div class="info-value">{mode}</div>
<br>
<div class="info-label">Detection Engine</div>
<div class="info-value">Flow + ML</div>
</div>""",
            unsafe_allow_html=True
        )

    st.markdown('<div class="section-title">🤖 Machine Learning Analysis</div>', unsafe_allow_html=True)
    ml1, ml2 = st.columns(2)
    with ml1:
        st.metric("Predicted SIH Class", str(ml_attack))
    with ml2:
        st.metric("Model Confidence", f"{ml_confidence * 100:.2f}%")

    st.caption(
        "Random Forest probability estimate for the analyzed "
        "traffic window. This is not the overall model accuracy."
    )

    st.markdown('<div class="section-title">📊 Threat Risk Analysis</div>', unsafe_allow_html=True)
    chart_data = [{"Threat": t, "Score": scores.get(t, 0)} for t in THREATS]

    st.vega_lite_chart(
        {
            "data": {"values": chart_data},
            "mark": {"type": "bar", "cornerRadiusEnd": 5, "tooltip": True},
            "encoding": {
                "x": {
                    "field": "Threat",
                    "type": "nominal",
                    "sort": "-y",
                    "axis": {"labelAngle": -35, "labelLimit": 170}
                },
                "y": {
                    "field": "Score",
                    "type": "quantitative",
                    "scale": {"domain": [0, 100]},
                    "axis": {
                        "title": "Confidence / Risk Score",
                        "values": [0, 20, 40, 60, 80, 100]
                    }
                }
            },
            "height": 420
        },
        use_container_width=True
    )

    st.markdown('<div class="section-title">📋 Threat Breakdown</div>', unsafe_allow_html=True)
    sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)

    for threat_item, value in sorted_scores:
        value = max(0, min(100, int(value)))
        if value >= 80:
            icon, label = "🔴", "HIGH"
        elif value >= 60:
            icon, label = "🟠", "MEDIUM"
        else:
            icon, label = "🟢", "LOW"

        c1, c2, c3 = st.columns([5, 1, 1])
        c1.write(f"{icon} **{threat_item}**")
        c2.write(f"**{value}%**")
        c3.write(f"`{label}`")
        st.progress(value / 100)

    st.markdown('<div class="section-title">🧠 Interpretation</div>', unsafe_allow_html=True)
    if score >= 80:
        st.error("Strong indicators were detected. Review the supporting evidence and capture details.")
    elif score >= 60:
        st.warning("Suspicious behavior was detected. The score is a heuristic risk score, not a statistical probability.")
    else:
        st.success("No threat category crossed the alert threshold.")

    with st.expander("🔬 Technical Details"):
        t1, t2 = st.columns(2)
        with t1:
            st.write(f"**Analysis Mode:** {mode}")
            st.write(f"**Packets Processed:** {packet_count:,}")
            st.write("**Detection:** Flow-Based + Machine Learning")
        with t2:
            st.write("**Traffic Mode:** Passive / Read-Only")
            st.write("**Blocking:** Disabled")
            st.write("**Packet Modification:** Disabled")
            st.write("**Payload Decryption:** Disabled")


# =========================================================
# SIDEBAR
# =========================================================

with st.sidebar:
    st.markdown(
        """<div class="sidebar-logo">
<div class="sidebar-logo-icon">🛡️</div>
<div class="sidebar-logo-title">SENTINEL IDS</div>
<div class="sidebar-logo-sub">Passive Network Security</div>
</div>""",
        unsafe_allow_html=True
    )

    st.divider()
    st.subheader("⚙️ Analysis Mode")

    if platform.system() == "Windows":
        mode = st.radio(
            "Select source",
            ["📁 PCAP / PCAPNG", "🌐 Live Network"],
            label_visibility="collapsed"
        )
    else:
        mode = st.radio(
            "Select source",
            ["📁 PCAP / PCAPNG"],
            label_visibility="collapsed"
        )
        st.info("🌐 Live Network capture is available only when Sentinel runs locally on Windows.")

    st.divider()
    st.subheader("🛡️ Detection Engine")

    for threat in THREATS:
        st.write(f"• {threat}")

    st.divider()
    st.caption("🔒 Passive IDS")
    st.caption("Read-Only Analysis")
    st.caption("No Blocking / Injection")


# =========================================================
# PCAP MODE
# =========================================================

if mode == "📁 PCAP / PCAPNG":
    st.header("📁 PCAP / PCAPNG Analysis")
    st.write("Upload a network capture and analyze its traffic using flow-based detection and machine learning.")

    uploaded = st.file_uploader("Choose PCAP / PCAPNG file", type=["pcap", "pcapng"])

    if uploaded:
        c1, c2, c3 = st.columns(3)
        c1.metric("📄 File", uploaded.name)
        c2.metric("💾 Size", f"{uploaded.size / 1024:.1f} KB")
        extension = uploaded.name.split(".")[-1].upper() if "." in uploaded.name else "UNKNOWN"
        c3.metric("📦 Format", extension)

        st.divider()

        if st.button("🔍 Analyze Network Capture", type="primary", use_container_width=True):
            try:
                with st.spinner("Reading network capture..."):
                    packets = rdpcap(uploaded)

                if not packets:
                    st.warning("⚠️ The uploaded capture contains no packets.")
                    st.stop()

                with st.spinner("Analyzing network traffic..."):
                    attack, score, evidence, scores = analyze(packets)

                with st.spinner("Running machine learning classification..."):
                    ml_attack, ml_confidence = get_ml(packets)

                st.success(f"✓ {len(packets):,} packets processed successfully.")

                show_result(
                    attack,
                    score,
                    evidence,
                    scores,
                    len(packets),
                    "PCAP / PCAPNG",
                    ml_attack,
                    ml_confidence
                )

            except Exception as error:
                st.error("❌ PCAP analysis failed.")
                with st.expander("🔧 Technical Error"):
                    st.code(str(error))


# =========================================================
# LIVE NETWORK
# =========================================================

else:
    if platform.system() != "Windows":
        st.error("🌐 Live Network capture is disabled on Streamlit Cloud/Linux. Run Sentinel locally on Windows for live capture.")
        st.stop()

    st.header("🌐 Live Network Monitoring")
    st.write("Passively monitor your laptop's network traffic without blocking or modifying packets.")
    st.info("🔒 Passive mode: traffic is only observed. Nothing is blocked, modified, injected, or decrypted.")

    option = st.radio(
        "Monitoring Scope",
        ["📶 WiFi", "💻 Whole Laptop Networking"],
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

    if option == "📶 WiFi":
        wifi = find_wifi()
        if wifi:
            st.success("📶 WiFi adapter detected")
            st.caption(wifi.get("description", "Wi-Fi"))
        else:
            st.error("❌ WiFi adapter was not detected.")
            st.stop()
    else:
        adapters = real_adapters()
        if not adapters:
            st.error("❌ No usable network adapter detected.")
            st.stop()

        st.success(f"💻 {len(adapters)} active network adapter(s) available.")
        st.caption("Monitoring active physical adapters only.")

    st.divider()

    if st.button("▶️ Start Passive Capture", type="primary", use_container_width=True):
        try:
            if option == "📶 WiFi":
                st.info("📶 Capturing from Wi-Fi...")
                with st.spinner(f"Capturing for {duration} seconds..."):
                    packets = capture_one(wifi["name"], duration)
            else:
                interfaces = [a["name"] for a in adapters if a.get("name")]
                if not interfaces:
                    st.error("❌ No valid interfaces found.")
                    st.stop()

                st.info(f"💻 Capturing from {len(interfaces)} active interfaces...")
                with st.spinner(f"Capturing for {duration} seconds..."):
                    packets = capture_interfaces(interfaces, duration)

            if packets:
                st.success(f"✓ {len(packets):,} packets captured.")

                with st.spinner("Analyzing captured traffic..."):
                    attack, score, evidence, scores = analyze(packets)

                with st.spinner("Running machine learning classification..."):
                    ml_attack, ml_confidence = get_ml(packets)

                show_result(
                    attack,
                    score,
                    evidence,
                    scores,
                    len(packets),
                    option,
                    ml_attack,
                    ml_confidence
                )
            else:
                st.warning("⚠️ No packets captured.")
                st.info("Make sure your laptop is actively using the selected network connection and that Npcap is installed.")

        except Exception as error:
            st.error("❌ Live capture failed.")
            with st.expander("🔧 Technical Error"):
                st.code(str(error))


# =========================================================
# FOOTER
# =========================================================

st.markdown("""<div class="footer">
🛡️ SENTINEL IDS &nbsp;•&nbsp; Flow-Based Detection &nbsp;•&nbsp; Machine Learning &nbsp;•&nbsp; Read-Only Security Analytics
</div>""", unsafe_allow_html=True)