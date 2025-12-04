# Network Assistant — Real-time Packet Monitoring with Anomaly Alerts + Chatbot

## 🔹 Overview
This project is a **network monitoring dashboard** that captures real-time network traffic using **Pyshark** and **Wireshark’s tshark**. It acts as a mini intrusion detection system (IDS) and a learning tool for network security.

## 🔹 Features
* **Real-time Monitoring:** Live packet visualization (mini-Wireshark).
* **Anomaly Alerts:** Detects Port scans 🚨, Unusual protocols ⚠️, and Traffic spikes 📈.
* **Interactive Chatbot:** Query traffic in plain English (e.g., "last 10 packets").
* **Quick Stats:** Total packets, top protocols, and unique IPs.

## 🔹 Tech Stack
* **Frontend:** Streamlit
* **Backend:** FastAPI
* **Packet Capture:** Pyshark / Tshark