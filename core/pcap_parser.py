"""
analyzer/pcap_parser.py

Scapy yordamida PCAP/PCAPNG faylni o'qib,
anomaliyalarni aniqlab, frontend kutgan formatda qaytaradi.
"""

import os
import time

try:
    from scapy.all import rdpcap, TCP, UDP, ICMP, DNS, IP

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ==================== ASOSIY PARSER ====================

def parse_pcap(filepath: str) -> dict:
    """
    PCAP faylni to'liq tahlil qiladi.

    Returns:
        {
            "stats": {...},
            "packets": [...],
            "dns_map": {...},
            "retrans_map": {...}
        }
    """
    if not SCAPY_AVAILABLE:
        raise RuntimeError("Scapy o'rnatilmagan. Buyruq: pip install scapy")

    raw_packets = rdpcap(filepath)

    # ---------- Schyotchiklar ----------
    stats = {
        "total": 0,
        "tcp": 0,
        "udp": 0,
        "dns": 0,
        "icmp": 0,
        "http": 0,
        "syn": 0,
        "rst": 0,
        "fin": 0,
        "ack": 0,
        "psh": 0,
        "retrans": 0,
        "dupAck": 0,
        "lostSeg": 0,
        "synFlood": 0,
    }

    dns_map: dict[str, int] = {}
    retrans_map: dict[str, int] = {}
    result_packets: list[dict] = []

    # Anomaliya aniqlash uchun yordamchi lug'atlar
    syn_counter: dict[str, int] = {}  # src_ip -> SYN soni
    seen_seqs: dict[tuple, float] = {}  # (src, dst, seq) -> vaqt
    ack_tracker: dict[tuple, dict] = {}  # (src, dst) -> {ack, count}

    base_time = float(raw_packets[0].time) if len(raw_packets) > 0 else 0

    for i, pkt in enumerate(raw_packets):

        # IP qatlami bo'lmasa o'tkazib yuborish
        if not pkt.haslayer(IP):
            continue

        stats["total"] += 1
        rel_time = float(pkt.time) - base_time

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        pkt_len = len(pkt)
        flags_list: list[str] = []
        anomaly = None
        proto_name = "OTHER"
        info = ""

        # ===== TCP =====
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            proto_name = "TCP"
            stats["tcp"] += 1

            payload = bytes(tcp.payload)

            # ===== HTTP detection =====
            if payload.startswith((
                    b"GET", b"POST", b"PUT",
                    b"DELETE", b"HEAD", b"OPTIONS",
                    b"PATCH", b"HTTP/"
            )):
                proto_name = "HTTP"
                stats["http"] += 1

            # ===== TCP flags =====
            f = int(tcp.flags)

            if f & 0x02:
                flags_list.append("SYN")
                stats["syn"] += 1
                syn_counter[src_ip] = syn_counter.get(src_ip, 0) + 1

            if f & 0x10:
                flags_list.append("ACK")
                stats["ack"] += 1

            if f & 0x04:
                flags_list.append("RST")
                stats["rst"] += 1
                anomaly = "RST"

            if f & 0x01:
                flags_list.append("FIN")
                stats["fin"] += 1

            if f & 0x08:
                flags_list.append("PSH")
                stats["psh"] += 1

            # ===== Retransmission detection =====
            seq_key = (src_ip, dst_ip, tcp.sport, tcp.dport, tcp.seq)

            if seq_key in seen_seqs:
                anomaly = anomaly or "RETRANSMIT"
                stats["retrans"] += 1
                retrans_map[src_ip] = retrans_map.get(src_ip, 0) + 1
            else:
                seen_seqs[seq_key] = rel_time

            # ===== Duplicate ACK =====
            ip_header = pkt[IP].ihl * 4
            tcp_header = tcp.dataofs * 4

            is_pure_ack = (
                    "ACK" in flags_list and
                    "SYN" not in flags_list and
                    "FIN" not in flags_list and
                    "RST" not in flags_list and
                    pkt_len == ip_header + tcp_header
            )

            if is_pure_ack:
                ak = (src_ip, dst_ip, tcp.sport, tcp.dport)

                if ak in ack_tracker:
                    prev = ack_tracker[ak]

                    if prev["ack"] == tcp.ack:
                        prev["count"] += 1

                        if prev["count"] >= 3:
                            anomaly = anomaly or "DUP-ACK"
                            stats["dupAck"] += 1
                    else:
                        ack_tracker[ak] = {"ack": tcp.ack, "count": 1}

                else:
                    ack_tracker[ak] = {"ack": tcp.ack, "count": 1}

            # ===== SYN Flood detection =====
            is_syn_only = "SYN" in flags_list and "ACK" not in flags_list

            if is_syn_only and syn_counter.get(src_ip, 0) > 20:
                anomaly = anomaly or "SYN-FLOOD"
                stats["synFlood"] += 1

            flags_str = "+".join(flags_list) if flags_list else "NO FLAGS"

            info = (
                f"[{proto_name}] {flags_str} "
                f"Seq={tcp.seq} Ack={tcp.ack} "
                f"Win={tcp.window} Len={pkt_len}"
            )

        # ===== UDP =====
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            proto_name = "UDP"
            stats["udp"] += 1
            info = f"[UDP] Sport={udp.sport} Dport={udp.dport} Len={pkt_len}"

        # ===== DNS (UDP/TCP ustida) =====
        if pkt.haslayer(DNS):
            dns_layer = pkt[DNS]
            # UDP statistikasidan alohida hisoblash
            if proto_name == "UDP":
                proto_name = "DNS"
                stats["dns"] += 1
                stats["udp"] -= 1
            if dns_layer.qd:
                try:
                    domain = dns_layer.qd.qname.decode(errors="ignore").rstrip(".")
                    dns_map[domain] = dns_map.get(domain, 0) + 1
                    info = f"DNS query: {domain} (type {dns_layer.qd.qtype})"
                except Exception:
                    pass

        # ===== ICMP =====
        elif pkt.haslayer(ICMP) and proto_name not in ("TCP", "UDP", "DNS", "HTTP"):
            icmp = pkt[ICMP]
            proto_name = "ICMP"
            stats["icmp"] += 1
            icmp_types = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable",
                          11: "Time Exceeded", 5: "Redirect"}
            type_name = icmp_types.get(icmp.type, f"type={icmp.type}")
            info = f"ICMP {type_name} code={icmp.code} Len={pkt_len}"

        # ===== Lost Segment (taxminiy) =====
        # Agar anomaliya yo'q va seq raqami juda katta sakragan bo'lsa
        # if anomaly is None and proto_name in ("TCP", "HTTP"):
        #     if pkt.haslayer(TCP) and pkt[TCP].seq > 2 ** 31:
        #         anomaly = "LOST-SEG"
        #         stats["lostSeg"] += 1

        result_packets.append({
            "num": i + 1,
            "time": f"{rel_time:.6f}",
            "src": src_ip,
            "dst": dst_ip,
            "proto": proto_name,
            "len": pkt_len,
            "flags": flags_list,
            "anomaly": anomaly,
            "info": info or f"[{proto_name}] Len={pkt_len}",
        })

    return {
        "stats": stats,
        "packets": result_packets,
        "dns_map": dns_map,
        "retrans_map": retrans_map,
    }


# ==================== ALERT BUILDER ====================

def build_alerts(stats: dict) -> list[dict]:
    """
    Statistika asosida anomaliya ogohlantirishlari ro'yxatini qaytaradi.
    level: "critical" | "warning" | "info" | "ok"
    """
    alerts = []

    # SYN-Flood
    if stats["synFlood"] > 3:
        alerts.append({
            "level": "critical",
            "type": "SYN-Flood Hujum",
            "desc": "Ko'p SYN paketlar, SYN+ACK javobi kam — potensial DDoS yoki port skanerlash",
            "count": stats["synFlood"] + stats["syn"],
        })
    elif stats["syn"] > 0:
        alerts.append({
            "level": "info",
            "type": "SYN Paketlar",
            "desc": "Oddiy ulanish urinishlari aniqlandi",
            "count": stats["syn"],
        })

    # RST
    if stats["rst"] > 5:
        alerts.append({
            "level": "warning",
            "type": "Ko'p RST Paketlar",
            "desc": "Ulanishlar tez-tez majburiy uzilmoqda — server muammosi yoki IDS bloklash",
            "count": stats["rst"],
        })
    elif stats["rst"] > 0:
        alerts.append({
            "level": "info",
            "type": "RST Paketlar",
            "desc": "Bir nechta ulanish uzilishi aniqlandi",
            "count": stats["rst"],
        })

    # Retransmission
    if stats["retrans"] > 5:
        alerts.append({
            "level": "warning",
            "type": "Ko'p Retransmission",
            "desc": "Paket yo'qotish — Wi-Fi signal sust yoki tarmoq band",
            "count": stats["retrans"],
        })
    elif stats["retrans"] > 0:
        alerts.append({
            "level": "info",
            "type": "Retransmission",
            "desc": "Bir nechta qayta uzatish aniqlandi",
            "count": stats["retrans"],
        })

    # Dup ACK
    if stats["dupAck"] > 3:
        alerts.append({
            "level": "warning",
            "type": "Dublikat ACK",
            "desc": "Qabul qiluvchi takror ACK yubormoqda — paket yo'qolishi ehtimoli",
            "count": stats["dupAck"],
        })

    # Lost Segment
    if stats["lostSeg"] > 0:
        alerts.append({
            "level": "critical",
            "type": "Yo'qolgan Segment",
            "desc": "TCP segment yo'qolishi aniqlandi — jiddiy kanal muammosi",
            "count": stats["lostSeg"],
        })

    # Hech narsa topilmagan
    if not alerts:
        alerts.append({
            "level": "ok",
            "type": "Anomaliya topilmadi",
            "desc": "Trafik normal ko'rinadi, shubhali faoliyat aniqlanmadi",
            "count": 0,
        })

    return alerts
