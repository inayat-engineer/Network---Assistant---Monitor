import os
import threading
import traceback
import time
import base64
import json
from fastapi import FastAPI, Request
from pydantic import BaseModel
from dotenv import load_dotenv
import pandas as pd
import asyncio

# local import
from app.chat_logic import analyze_query, detect_anomalies

load_dotenv()

CAPTURE_INTERFACE = os.getenv("CAPTURE_INTERFACE", "any")
MAX_BUFFER = int(os.getenv("MAX_BUFFER", "1000"))

app = FastAPI(title="Network Assistant (Deterministic)")

packets_buffer = []
buffer_lock = threading.Lock()

def _safe_attr(obj, attr):
    return getattr(obj, attr) if obj and hasattr(obj, attr) else None

def capture_loop(interface_name: str):
    try:
        import pyshark
    except Exception as e:
        print("pyshark import failed — capture disabled:", e)
        return

    print(f"[capture] Starting capture on interface '{interface_name}' (may require admin/root).")

    # Create event loop for this thread
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        capture = pyshark.LiveCapture(interface=interface_name)
    except Exception as e:
        print(f"[capture] LiveCapture failed: {e}")
        return

    for packet in capture.sniff_continuously():
        try:
            pkt = {}
            sniff_time = _safe_attr(packet, "sniff_time")
            pkt["time"] = sniff_time.isoformat() if sniff_time else time.strftime("%Y-%m-%dT%H:%M:%S")
            pkt["protocol"] = _safe_attr(packet, "highest_layer") or "N/A"
            pkt["length"] = int(_safe_attr(packet, "length") or 0)

            # IPs
            if hasattr(packet, "ip"):
                pkt["src_ip"] = str(_safe_attr(packet.ip, "src") or "")
                pkt["dst_ip"] = str(_safe_attr(packet.ip, "dst") or "")
            else:
                pkt["src_ip"] = ""
                pkt["dst_ip"] = ""

            # Ports
            if hasattr(packet, "tcp"):
                pkt["src_port"] = str(_safe_attr(packet.tcp, "srcport") or "")
                pkt["dst_port"] = str(_safe_attr(packet.tcp, "dstport") or "")
            elif hasattr(packet, "udp"):
                pkt["src_port"] = str(_safe_attr(packet.udp, "srcport") or "")
                pkt["dst_port"] = str(_safe_attr(packet.udp, "dstport") or "")
            else:
                pkt["src_port"] = ""
                pkt["dst_port"] = ""

            # HTTP host
            pkt["http_host"] = str(_safe_attr(packet.http, "host") or "") if hasattr(packet, "http") else ""

            # TLS / SNI
            tls_layer = _safe_attr(packet, "tls") or _safe_attr(packet, "ssl")
            if tls_layer:
                sni = None
                for f in ("handshake_extensions_server_name", "handshake_extensions_server_name_value"):
                    try:
                        sni = getattr(tls_layer, f)
                        if sni:
                            break
                    except Exception:
                        sni = None
                pkt["tls_sni"] = str(sni) if sni else ""
            else:
                pkt["tls_sni"] = ""

            # DNS query / response (pyshark field names vary)
            pkt["dns_qry_name"] = ""
            pkt["dns_qry_type"] = ""
            pkt["dns_resp_name"] = ""
            if hasattr(packet, "dns"):
                try:
                    dns = packet.dns
                    # query name
                    if hasattr(dns, "qry_name"):
                        pkt["dns_qry_name"] = str(dns.qry_name)
                    elif hasattr(dns, "qname"):
                        pkt["dns_qry_name"] = str(dns.qname)
                    elif hasattr(dns, "qry_name_0"):
                        pkt["dns_qry_name"] = str(dns.qry_name_0)
                    # query type
                    if hasattr(dns, "qry_type"):
                        pkt["dns_qry_type"] = str(dns.qry_type)
                    # response name
                    if hasattr(dns, "resp_name"):
                        pkt["dns_resp_name"] = str(dns.resp_name)
                except Exception:
                    pass

            # Add to buffer
            with buffer_lock:
                packets_buffer.append(pkt)
                if len(packets_buffer) > MAX_BUFFER:
                    packets_buffer.pop(0)

        except Exception:
            print("[capture] packet parse error:", traceback.format_exc())
            continue

# Start capture thread
capture_thread = threading.Thread(target=capture_loop, args=(CAPTURE_INTERFACE,), daemon=True)
capture_thread.start()

@app.get("/packets")
def get_packets():
    with buffer_lock:
        df = pd.DataFrame(packets_buffer)
    alerts = detect_anomalies(df)
    return {"packets": list(packets_buffer), "alerts": alerts}

@app.post("/report")
async def report_packet(payload: dict):
    with buffer_lock:
        packets_buffer.append(payload)
        if len(packets_buffer) > MAX_BUFFER:
            packets_buffer.pop(0)
    return {"ok": True}

@app.get("/api/")
async def receive_report(request: Request):
    raw_q = request.url.query
    if not raw_q:
        return {"ok": False, "reason": "empty query"}
    try:
        decoded = base64.b64decode(raw_q).decode("utf-8")
        payload = json.loads(decoded)
    except Exception as e:
        return {"ok": False, "error": str(e)}
    with buffer_lock:
        packets_buffer.append(payload)
        if len(packets_buffer) > MAX_BUFFER:
            packets_buffer.pop(0)
    return {"ok": True}

class ChatRequest(BaseModel):
    text: str

@app.post("/chat")
def chat(req: ChatRequest):
    with buffer_lock:
        df = pd.DataFrame(packets_buffer)
    result = analyze_query(req.text or "", df)
    return result
