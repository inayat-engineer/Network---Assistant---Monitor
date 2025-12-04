import re
import pandas as pd

def _safe_series(df, col):
    if df is None or df.empty or col not in df.columns:
        return pd.Series(dtype="object")
    return df[col].dropna().astype(str)

def analyze_query(text: str, df: pd.DataFrame):
    t = (text or "").lower().strip()
    if df is None or df.empty:
        return {"type": "text", "text": "No packet data available yet."}

    # --- last N packets
    m = re.search(r"last\s+(\d+)\s+packets", t)
    if m:
        n = max(1, min(2000, int(m.group(1))))
        rows = df.tail(n).to_dict(orient="records")
        return {"type": "table", "text": f"Last {n} packets", "data": rows}

    # --- top talkers
    if any(k in t for k in ["top talker", "top talkers", "top hosts", "top src"]):
        series = _safe_series(df, "src_ip")
        counts = series.value_counts().head(20).to_dict()
        return {"type": "chart", "text": "Top talkers (src_ip)", "data": counts}

    # --- top 5 destination IPs
    if any(k in t for k in ["top dest", "top destinations", "top destination", "top dst", "top 5 destination"]):
        s = _safe_series(df, "dst_ip")
        if s.empty:
            return {"type": "text", "text": "No destination IP data available."}
        counts = s.value_counts().head(5).to_dict()
        return {"type": "chart", "text": "Top 5 destination IPs", "data": counts}

    # --- traffic by protocol
    if any(k in t for k in ["traffic by protocol", "traffic by protocols", "by protocol", "protocol count", "protocol breakdown"]):
        series = _safe_series(df, "protocol")
        counts = series.value_counts().to_dict()
        return {"type": "chart", "text": "Traffic by protocol", "data": counts}

    # --- packets larger than N bytes
    m = re.search(r"(packets|packet)\s+(larger|greater|above)\s+than\s+(\d+)", t)
    if m:
        threshold = int(m.group(3))
        if "length" not in df.columns:
            return {"type": "text", "text": "No packet length data available."}
        rows = df[df["length"].astype(int) > threshold].to_dict(orient="records")
        return {"type": "table", "text": f"Packets larger than {threshold} bytes", "data": rows}

    # Alternate: "packets > 1000"
    m = re.search(r"(packets|packet)\s*>\s*(\d+)", t)
    if m:
        threshold = int(m.group(2))
        if "length" not in df.columns:
            return {"type": "text", "text": "No packet length data available."}
        rows = df[df["length"].astype(int) > threshold].to_dict(orient="records")
        return {"type": "table", "text": f"Packets larger than {threshold} bytes", "data": rows}

    # --- show HTTP hostnames
    if any(k in t for k in ["http host", "http hosts", "http hostname", "http hostnames", "show http host", "show http hostnames"]):
        if "http_host" not in df.columns:
            return {"type": "text", "text": "No HTTP host data captured."}
        hosts = df["http_host"].dropna().astype(str)
        if hosts.empty:
            return {"type": "text", "text": "No HTTP hostnames seen in the buffer."}
        counts = hosts.value_counts().to_dict()
        return {"type": "chart", "text": "HTTP hostnames seen", "data": counts}

    # --- domains accessed (HTTP + DNS + TLS)
    if any(k in t for k in ["domains", "which domains", "domains accessed", "which domains are being accessed"]):
        candidates = []
        if "http_host" in df.columns:
            candidates += df["http_host"].dropna().astype(str).tolist()
        if "dns_qry_name" in df.columns:
            candidates += df["dns_qry_name"].dropna().astype(str).tolist()
        if "tls_sni" in df.columns:
            candidates += df["tls_sni"].dropna().astype(str).tolist()
        candidates = [c for c in candidates if c]
        if not candidates:
            return {"type": "text", "text": "No domain/hostname data available."}
        s = pd.Series(candidates)
        counts = s.value_counts().head(30).to_dict()
        return {"type": "chart", "text": "Domains accessed (HTTP/DNS/TLS SNI)", "data": counts}

    # --- TLS SNI values
    if any(k in t for k in ["tls sni", "sni", "tls names", "server names"]):
        if "tls_sni" not in df.columns:
            return {"type": "text", "text": "No TLS SNI data captured."}
        s = _safe_series(df, "tls_sni")
        if s.empty:
            return {"type": "text", "text": "No TLS SNI values seen in the buffer."}
        counts = s.value_counts().to_dict()
        return {"type": "chart", "text": "TLS SNI values", "data": counts}

    # --- DNS queries
    if any(k in t for k in ["dns queries", "list dns", "dns query", "dns queries list", "show dns queries"]):
        if "dns_qry_name" not in df.columns:
            return {"type": "text", "text": "No DNS data captured."}
        rows = df[["time", "src_ip", "dst_ip", "dns_qry_name"]].dropna(subset=["dns_qry_name"]).to_dict(orient="records")
        if not rows:
            return {"type": "text", "text": "No DNS queries in recent buffer."}
        return {"type": "table", "text": "DNS queries", "data": rows}

    # --- top targeted ports
    if any(k in t for k in ["top ports", "most targeted ports", "ports targeted", "which ports"]):
        counts = {}
        if "dst_port" in df.columns:
            counts = _safe_series(df, "dst_port").value_counts().head(20).to_dict()
        else:
            counts = _safe_series(df, "src_port").value_counts().head(20).to_dict()
        if not counts:
            return {"type": "text", "text": "No port data available."}
        return {"type": "chart", "text": "Top targeted ports (destination ports)", "data": counts}

    # --- port scan detection
    if any(k in t for k in ["scan", "port scan", "suspicious", "scan detected"]):
        if "dst_port" not in df.columns:
            return {"type": "text", "text": "No dst_port data captured (cannot check for scans)."}
        grouped = df.groupby(df["src_ip"].astype(str))["dst_port"].nunique()
        suspicious = grouped[grouped > 10].sort_values(ascending=False)
        if suspicious.empty:
            return {"type": "text", "text": "No obvious port-scan behavior in recent buffer."}
        items = [{"src_ip": idx, "unique_dst_ports": int(v)} for idx, v in suspicious.items()]
        return {"type": "table", "text": "Potential port scanners", "data": items}

    # --- fallback stats
    stats = {
        "total_packets": int(len(df)),
        "unique_src_ips": int(df["src_ip"].nunique()) if "src_ip" in df.columns else 0,
        "protocols": _safe_series(df, "protocol").value_counts().to_dict()
    }
    return {"type": "text", "text": "Couldn't detect a specific intent. Here are some quick stats.", "stats": stats}


def detect_anomalies(df: pd.DataFrame):
    """
    Run anomaly checks:
    1) Port scan detection
    2) Unusual protocols
    3) Traffic spikes
    """
    alerts = []
    if df is None or df.empty:
        return alerts

    # 1) Port scan detection
    if "src_ip" in df.columns and "dst_port" in df.columns:
        grouped = df.groupby(df["src_ip"].astype(str))["dst_port"].nunique()
        suspicious = grouped[grouped > 20]  # threshold = 20 unique ports
        for ip, count in suspicious.items():
            alerts.append(f"⚠️ Port scan detected: {ip} contacted {count} unique destination ports")

    # 2) Unusual protocols
    if "protocol" in df.columns:
        common_protocols = {"TCP", "UDP", "IP", "ICMP", "ARP", "DNS", "HTTP", "HTTPS", "TLS", "FTP", "SMTP", "DHCP"}

        unusual = set(df["protocol"].unique()) - common_protocols
        for proto in unusual:
            alerts.append(f"⚠️ Unusual protocol observed: {proto}")

    # 3) Traffic spike
    if len(df) >= 40:
        recent = df.tail(20)
        prev = df.tail(40).head(20)
        if len(prev) > 0 and len(recent) > 2 * len(prev):
            alerts.append("⚠️ Sudden traffic spike detected")

    return alerts


