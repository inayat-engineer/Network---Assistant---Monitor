import streamlit as st
import requests
import pandas as pd
import os

st.set_page_config(
    page_title="Network Assistant",
    page_icon="🛰️",
    layout="wide",
    initial_sidebar_state="expanded",
)

API_URL = os.environ.get("API_URL", "http://127.0.0.1:8000")

# --- Custom CSS ---
st.markdown(
    """
    <style>
    .main { background-color: #111827; color: white; }
    div[data-testid="stMetricValue"] { color: #00FFAA; font-size: 28px; font-weight: bold; }
    div[data-testid="stMetricLabel"] { color: #cccccc; font-size: 16px; }
    .alert-card { padding: 12px; border-radius: 10px; margin-bottom: 8px; font-size: 15px; font-weight: 500; }
    .alert-green { background-color: #063; color: #bdfccb; border: 1px solid #0f0; }
    .alert-yellow { background-color: #332f00; color: #ffe066; border: 1px solid #ffcc00; }
    .alert-red { background-color: #330000; color: #ff8080; border: 1px solid #ff1a1a; }
    .chat-box { padding: 15px; border-radius: 12px; background-color: #1f2937; margin-bottom: 10px; }
    .user-msg { text-align: right; color: #00d4ff; font-weight: bold; }
    .bot-msg { text-align: left; color: #ffffff; }
    </style>
    """,
    unsafe_allow_html=True
)

# --- Sidebar navigation ---
st.sidebar.title("📌 Navigation")
page = st.sidebar.radio("Go to", ["📊 Dashboard", "🛡️ Alerts", "🤖 Chat", "📂 Packets"])

# Helper: safely parse /packets response (handles dict or list)
def fetch_packets_and_alerts():
    try:
        resp = requests.get(f"{API_URL}/packets", timeout=5)
        resp.raise_for_status()
        json_data = resp.json()
    except Exception as e:
        return [], []

    if isinstance(json_data, dict):
        packets = json_data.get("packets", [])
        alerts = json_data.get("alerts", [])
    elif isinstance(json_data, list):
        packets = json_data
        alerts = []
    else:
        packets = []
        alerts = []
    return packets, alerts

# --- Dashboard ---
if page == "📊 Dashboard":
    st.title("📊 Quick Stats & 🛡️ Anomaly Alerts")
    packets, alerts = fetch_packets_and_alerts()
    df = pd.DataFrame(packets) if packets else pd.DataFrame()

    col1, col2 = st.columns([2, 1])
    with col1:
        st.subheader("📊 Quick Stats")
        if not df.empty:
            c1, c2 = st.columns(2)
            with c1:
                st.metric("Total Packets", len(df))
            with c2:
                st.metric("Unique Source IPs", df["src_ip"].nunique() if "src_ip" in df.columns else 0)
            if "protocol" in df.columns:
                st.bar_chart(df["protocol"].fillna("UNKNOWN").value_counts())
        else:
            st.info("No data captured yet.")
    with col2:
        st.subheader("🛡️ Anomaly Alerts")
        if alerts:
            for alert in alerts:
                css_class = "alert-red" if "port scan" in alert.lower() else "alert-yellow"
                st.markdown(f"<div class='alert-card {css_class}'>⚠️ {alert}</div>", unsafe_allow_html=True)
        else:
            st.markdown("<div class='alert-card alert-green'>✅ No anomalies detected</div>", unsafe_allow_html=True)

# --- Alerts Page ---
elif page == "🛡️ Alerts":
    st.title("🛡️ Detailed Anomaly Alerts")
    _, alerts = fetch_packets_and_alerts()
    if alerts:
        for alert in alerts:
            css_class = "alert-red" if "port scan" in alert.lower() else "alert-yellow"
            st.markdown(f"<div class='alert-card {css_class}'>⚠️ {alert}</div>", unsafe_allow_html=True)
    else:
        st.markdown("<div class='alert-card alert-green'>✅ No anomalies detected</div>", unsafe_allow_html=True)

# --- Chat Assistant Page ---
elif page == "🤖 Chat":
    st.title("🤖 Chat with Network Assistant")
    st.write("Ask questions like *'last 10 packets'*, *'traffic by protocol'*, *'is there a port scan?'*")

    # ensure chat_history exists
    if "chat_history" not in st.session_state:
        st.session_state["chat_history"] = []

    chat_history = st.session_state["chat_history"]

    # Display past chat
    for sender, msg in chat_history:
        css_class = "user-msg" if sender == "user" else "bot-msg"
        if isinstance(msg, pd.DataFrame):
            st.dataframe(msg, height=300)
        elif isinstance(msg, dict) and "chart" in msg:
            st.bar_chart(msg["chart"])
        else:
            # msg might be a string or other small summary
            st.markdown(f"<div class='chat-box {css_class}'>{msg}</div>", unsafe_allow_html=True)

    # Input
    user_input = st.text_input("Type your query", key="input_query")
    if st.button("Send"):
        if user_input and user_input.strip():
            try:
                resp = requests.post(f"{API_URL}/chat", json={"text": user_input}, timeout=10)
                resp.raise_for_status()
                reply = resp.json()
            except Exception as e:
                st.error(f"Error contacting backend: {e}")
                reply = {"type": "text", "text": f"Backend error: {e}"}

            chat_history.append(("user", user_input))

            r_type = reply.get("type")
            if r_type == "table":
                df_reply = pd.DataFrame(reply.get("data", []))
                chat_history.append(("bot", df_reply))
            elif r_type == "chart":
                series = pd.Series(reply.get("data", {}) or {})
                chat_history.append(("bot", {"chart": series}))
            else:
                chat_history.append(("bot", reply.get("text", str(reply))))

            st.session_state["chat_history"] = chat_history
            st.rerun()

    # Quick queries
    st.markdown("**Quick Queries:**")
    quick_queries = ["Top talkers", "DNS queries", "Traffic by protocol", "Port scan detected"]
    cols = st.columns(4)
    for i, q in enumerate(quick_queries):
        if cols[i].button(q):
            try:
                resp = requests.post(f"{API_URL}/chat", json={"text": q}, timeout=8)
                resp.raise_for_status()
                reply = resp.json()
            except Exception as e:
                st.error(f"Error contacting backend: {e}")
                reply = {"type": "text", "text": f"Backend error: {e}"}

            chat_history.append(("user", q))
            r_type = reply.get("type")
            if r_type == "table":
                df_reply = pd.DataFrame(reply.get("data", []))
                chat_history.append(("bot", df_reply))
            elif r_type == "chart":
                series = pd.Series(reply.get("data", {}) or {})
                chat_history.append(("bot", {"chart": series}))
            else:
                chat_history.append(("bot", reply.get("text", str(reply))))

            st.session_state["chat_history"] = chat_history
            st.rerun()

# --- Packet Table Page ---
elif page == "📂 Packets":
    st.title("📂 Live Packet Table")
    packets, _ = fetch_packets_and_alerts()
    df = pd.DataFrame(packets) if packets else pd.DataFrame()
    if not df.empty:
        st.dataframe(df.tail(200), height=400)
    else:
        st.info("No packets captured yet.")
