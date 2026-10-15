import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime

from database.database import (
    initialize_database,
    insert_event,
    get_events
)

from detection.hybrid_engine import analyze_event


st.set_page_config(
    page_title="Hybrid IDS SOC",
    page_icon="🛡️",
    layout="wide"
)


# -----------------------------
# DARK SOC STYLE
# -----------------------------

st.markdown("""
<style>

.stApp {
    background-color: #07111f;
    color: #e6edf7;
}

section[data-testid="stSidebar"] {
    background-color: #0b1728;
}

.metric-card {
    background: #0d1b2e;
    padding: 20px;
    border-radius: 12px;
    border: 1px solid #1c3554;
}

.title {
    font-size: 32px;
    font-weight: bold;
}

.subtitle {
    color: #7f9bb8;
}

</style>
""", unsafe_allow_html=True)


initialize_database()


# -----------------------------
# HEADER
# -----------------------------

st.markdown(
    '<div class="title">🛡️ HYBRID IDS — SECURITY OPERATIONS CENTER</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">'
    'AI + Rule-Based Intrusion Detection & Digital Forensic Monitoring'
    '</div>',
    unsafe_allow_html=True
)

st.divider()


# -----------------------------
# SIDEBAR
# -----------------------------

st.sidebar.title("⚙️ Control Panel")

mode = st.sidebar.radio(
    "Monitoring Mode",
    [
        "Dashboard",
        "Dataset Analysis",
        "Live Monitoring",
        "Forensic Investigation"
    ]
)


# -----------------------------
# LOAD EVENTS
# -----------------------------

df = get_events()


# -----------------------------
# DASHBOARD
# -----------------------------

if mode == "Dashboard":

    total_events = len(df)

    high_risk = (
        len(df[df["risk_level"] == "HIGH"])
        if not df.empty else 0
    )

    medium_risk = (
        len(df[df["risk_level"] == "MEDIUM"])
        if not df.empty else 0
    )

    attacks = (
        len(df[df["attack_type"] != "Normal"])
        if not df.empty else 0
    )

    c1, c2, c3, c4 = st.columns(4)

    c1.metric("Events Analyzed", total_events)
    c2.metric("Threats Detected", attacks)
    c3.metric("High Risk", high_risk)
    c4.metric("Medium Risk", medium_risk)

    st.divider()

    if not df.empty:

        left, right = st.columns(2)

        with left:

            risk_counts = df["risk_level"].value_counts()

            fig = px.pie(
                values=risk_counts.values,
                names=risk_counts.index,
                title="Risk Distribution"
            )

            fig.update_layout(
                paper_bgcolor="#07111f",
                plot_bgcolor="#07111f",
                font_color="white"
            )

            st.plotly_chart(fig, use_container_width=True)

        with right:

            attack_counts = df["attack_type"].value_counts()

            fig = px.bar(
                x=attack_counts.index,
                y=attack_counts.values,
                title="Detection Categories"
            )

            fig.update_layout(
                paper_bgcolor="#07111f",
                plot_bgcolor="#07111f",
                font_color="white"
            )

            st.plotly_chart(fig, use_container_width=True)

        st.subheader("🚨 Recent Security Events")

        st.dataframe(
            df.head(20),
            use_container_width=True
        )

    else:

        st.info(
            "No security events recorded yet. "
            "Run Dataset Analysis or Live Monitoring."
        )


# -----------------------------
# DATASET ANALYSIS
# -----------------------------

elif mode == "Dataset Analysis":

    st.header("📊 Dataset Analysis")

    uploaded = st.file_uploader(
        "Upload network traffic CSV",
        type=["csv"]
    )

    if uploaded:

        data = pd.read_csv(uploaded)

        st.subheader("Dataset Preview")
        st.dataframe(data.head(20), use_container_width=True)

        required = [
            "failed_attempts",
            "connection_count",
            "unique_ports",
            "packet_count",
            "bytes_transferred"
        ]

        if all(column in data.columns for column in required):

            if st.button("🔍 Analyze Dataset"):

                progress = st.progress(0)

                detected_count = 0

                for index, row in data.iterrows():

                    event_data = row.to_dict()

                    result = analyze_event(event_data)

                    if result["risk_level"] != "LOW":
                        detected_count += 1

                    event = {
                        "timestamp": datetime.now().isoformat(),
                        "source_ip": event_data.get(
                            "source_ip",
                            "Dataset"
                        ),
                        "destination_ip": event_data.get(
                            "destination_ip",
                            "Dataset"
                        ),
                        "protocol": event_data.get(
                            "protocol",
                            "Unknown"
                        ),
                        "source_port": 0,
                        "destination_port": 0,
                        "attack_type": result["attack_type"],
                        "rule_detection":
                            result["rule_detection"],
                        "ml_detection":
                            result["ml_detection"],
                        "confidence":
                            result["confidence"],
                        "risk_level":
                            result["risk_level"],
                        "evidence":
                            result["evidence"]
                    }

                    insert_event(event)

                    progress.progress(
                        (index + 1) / len(data)
                    )

                st.success(
                    f"Analysis completed. "
                    f"{detected_count} suspicious events detected."
                )

        else:

            st.error(
                "Dataset does not contain the required feature columns."
            )


# -----------------------------
# LIVE MONITORING
# -----------------------------

elif mode == "Live Monitoring":

    st.header("🌐 Live Network Monitoring")

    st.warning(
        "Live capture requires an authorized network interface "
        "and appropriate packet-capture permissions."
    )

    st.write(
        "The dashboard interface is ready. "
        "The Scapy capture module can feed packet features "
        "into the same Hybrid Detection Engine."
    )

    if st.button("Generate Test Security Event"):

        sample = {
            "failed_attempts": 8,
            "connection_count": 65,
            "unique_ports": 15,
            "packet_count": 500,
            "bytes_transferred": 50000
        }

        result = analyze_event(sample)

        event = {
            "timestamp": datetime.now().isoformat(),
            "source_ip": "LAB-TEST",
            "destination_ip": "LOCAL-NETWORK",
            "protocol": "TCP",
            "source_port": 5000,
            "destination_port": 80,
            "attack_type": result["attack_type"],
            "rule_detection": result["rule_detection"],
            "ml_detection": result["ml_detection"],
            "confidence": result["confidence"],
            "risk_level": result["risk_level"],
            "evidence": result["evidence"]
        }

        insert_event(event)

        st.success("Security event processed.")

        st.json(result)


# -----------------------------
# FORENSICS
# -----------------------------

elif mode == "Forensic Investigation":

    st.header("🔎 Forensic Investigation")

    df = get_events()

    if df.empty:

        st.info("No forensic events available.")

    else:

        event_id = st.number_input(
            "Enter Event ID",
            min_value=1,
            step=1
        )

        selected = df[df["id"] == event_id]

        if not selected.empty:

            record = selected.iloc[0]

            st.subheader(
                f"Incident #{record['id']}"
            )

            c1, c2, c3 = st.columns(3)

            c1.metric(
                "Risk",
                record["risk_level"]
            )

            c2.metric(
                "ML Detection",
                str(record["ml_detection"])
            )

            c3.metric(
                "Rule Detection",
                str(record["rule_detection"])
            )

            st.write("### Event Information")

            st.json({
                "timestamp":
                    record["timestamp"],
                "source_ip":
                    record["source_ip"],
                "destination_ip":
                    record["destination_ip"],
                "protocol":
                    record["protocol"],
                "attack_type":
                    record["attack_type"],
                "confidence":
                    record["confidence"],
                "evidence":
                    record["evidence"]
            })

        st.subheader("📁 Complete Forensic Log")

        st.dataframe(
            df,
            use_container_width=True
        )