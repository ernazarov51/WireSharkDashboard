

try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False


def _is_dns_pkt(pkt) -> bool:
    layers = [l.layer_name.lower() for l in pkt.layers]
    if 'dns' in layers:
        return True
    if 'udp' in layers:
        try:
            return pkt.udp.dstport == '53' or pkt.udp.srcport == '53'
        except Exception:
            pass
    return False


def _detect_proto(pkt) -> str:
    layers = [l.layer_name.lower() for l in pkt.layers]
    if _is_dns_pkt(pkt): return "DNS"
    if 'http' in layers:  return "HTTP"
    if 'tcp'  in layers:  return "TCP"
    if 'udp'  in layers:  return "UDP"
    if 'icmp' in layers:  return "ICMP"
    return "OTHER"


def _count_proto_stats(pkt, proto_name: str, stats: dict) -> None:
    layers = [l.layer_name.lower() for l in pkt.layers]
    if 'tcp'  in layers:     stats["tcp"]  += 1
    if 'udp'  in layers:     stats["udp"]  += 1
    if proto_name == "DNS":  stats["dns"]  += 1
    if proto_name == "HTTP": stats["http"] += 1
    if proto_name == "ICMP": stats["icmp"] += 1


def _get_tcp_flags(pkt) -> list:
    flags = []
    try:
        raw = str(pkt.tcp.flags)
        f   = int(raw, 16)
        if f & 0x002: flags.append("SYN")
        if f & 0x010: flags.append("ACK")
        if f & 0x004: flags.append("RST")
        if f & 0x001: flags.append("FIN")
        if f & 0x008: flags.append("PSH")
    except Exception:
        pass
    return flags


def _check_tcp_analysis(pkt) -> tuple:
    is_retransmit = False
    is_dup_ack    = False
    is_lost_seg   = False
    try:
        for name in pkt.tcp.field_names:
            n = name.lower()
            if 'retransmission' in n: is_retransmit = True
            if 'duplicate_ack'  in n: is_dup_ack    = True
            if 'lost_segment'   in n: is_lost_seg   = True
    except Exception:
        pass
    return is_retransmit, is_dup_ack, is_lost_seg


def _get_dns_qname(pkt) -> str | None:

    try:
        dns   = pkt.dns
        qname = getattr(dns, 'qry_name', None) or getattr(dns, 'name', None)

        flags_response = getattr(dns, 'flags_response', None)
        flags_qr       = getattr(dns, 'flags_qr', None)

        if flags_response is not None:
            is_query = str(flags_response) == '0'
        elif flags_qr is not None:
            is_query = str(flags_qr) == '0'
        else:
            is_query = qname is not None

        if is_query and qname:
            return str(qname)
    except Exception:
        pass

    try:
        layers = [l.layer_name.lower() for l in pkt.layers]
        if 'data' in layers and 'udp' in layers:
            raw_hex = pkt.data.data.replace(':', '')
            raw     = bytes.fromhex(raw_hex)
            if len(raw) < 13:
                return None
            qr_bit = (raw[2] >> 7) & 1
            if qr_bit != 0:
                return None
            pos    = 12
            labels = []
            while pos < len(raw):
                length = raw[pos]
                if length == 0:
                    break
                if (length & 0xC0) == 0xC0:
                    break
                pos += 1
                if pos + length > len(raw):
                    break
                labels.append(raw[pos:pos + length].decode('ascii', errors='replace'))
                pos += length
            if labels:
                return '.'.join(labels)
    except Exception:
        pass

    return None


def _build_info(pkt, proto_name: str, flags_list: list, pkt_len: int) -> str:
    if proto_name == "DNS":
        qname = _get_dns_qname(pkt)
        if qname:
            return f"DNS query {qname}"
        return f"DNS Len={pkt_len}"

    if proto_name in ("TCP", "HTTP"):
        try:
            tcp       = pkt.tcp
            flags_str = "+".join(flags_list) if flags_list else "NO FLAGS"
            seq = getattr(tcp, 'seq', '?')
            ack = getattr(tcp, 'ack', '?')
            win = getattr(tcp, 'window_size_value', getattr(tcp, 'window_size', '?'))
            return f"[{proto_name}] {flags_str} Seq={seq} Ack={ack} Win={win} Len={pkt_len}"
        except AttributeError:
            pass

    if proto_name == "UDP":
        try:
            udp = pkt.udp
            return f"[UDP] Sport={udp.srcport} Dport={udp.dstport} Len={pkt_len}"
        except AttributeError:
            pass

    if proto_name == "ICMP":
        try:
            icmp     = pkt.icmp
            icmp_map = {'0':'Echo Reply','8':'Echo Request',
                        '3':'Dest Unreachable','11':'Time Exceeded','5':'Redirect'}
            type_name = icmp_map.get(str(icmp.type), f"type={icmp.type}")
            return f"ICMP {type_name} code={icmp.code} Len={pkt_len}"
        except AttributeError:
            pass

    return f"[{proto_name}] Len={pkt_len}"



def parse_pcap(filepath: str) -> dict:
    if not PYSHARK_AVAILABLE:
        raise RuntimeError(
            "PyShark o'rnatilmagan.\n"
            "  pip install pyshark\n"
            "  sudo apt install tshark   (Ubuntu/Debian)\n"
            "  brew install wireshark    (macOS)"
        )

    cap = pyshark.FileCapture(
        filepath,
        use_json=False,
        include_raw=False,
        custom_parameters=['-d', 'udp.port==53,dns'],
    )

    stats = {
        "total": 0, "tcp": 0, "udp": 0, "dns": 0, "icmp": 0, "http": 0,
        "syn": 0, "rst": 0, "fin": 0, "ack": 0, "psh": 0,
        "retrans": 0, "dupAck": 0, "lostSeg": 0, "synFlood": 0,
    }

    dns_map:        dict = {}
    retrans_map:    dict = {}
    result_packets: list = []
    syn_counter:    dict = {}
    base_time             = None
    pkt_index             = 0

    try:
        for pkt in cap:
            try:
                src_ip = pkt.ip.src
                dst_ip = pkt.ip.dst
            except AttributeError:
                continue

            pkt_index += 1
            stats["total"] += 1

            try:
                abs_time = float(pkt.sniff_timestamp)
                if base_time is None:
                    base_time = abs_time
                rel_time = abs_time - base_time
            except (AttributeError, ValueError):
                rel_time = 0.0

            pkt_len    = int(pkt.length) if hasattr(pkt, 'length') else 0
            proto_name = _detect_proto(pkt)

            _count_proto_stats(pkt, proto_name, stats)

            if proto_name == "DNS":
                qname = _get_dns_qname(pkt)
                if qname:
                    for domain in qname.split('\n'):
                        domain = domain.strip().rstrip('.')
                        if domain:
                            dns_map[domain] = 1

            flags_list = []
            anomaly    = None
            has_tcp    = 'tcp' in [l.layer_name.lower() for l in pkt.layers]

            if has_tcp:
                flags_list = _get_tcp_flags(pkt)

                if "SYN" in flags_list:
                    stats["syn"] += 1
                    syn_counter[src_ip] = syn_counter.get(src_ip, 0) + 1
                if "ACK" in flags_list: stats["ack"] += 1
                if "RST" in flags_list:
                    stats["rst"] += 1
                    anomaly = "RST"
                if "FIN" in flags_list: stats["fin"] += 1
                if "PSH" in flags_list: stats["psh"] += 1

                is_retransmit, is_dup_ack, is_lost_seg = _check_tcp_analysis(pkt)

                if is_retransmit:
                    anomaly = anomaly or "RETRANSMIT"
                    stats["retrans"] += 1
                    retrans_map[src_ip] = retrans_map.get(src_ip, 0) + 1
                elif is_dup_ack:
                    anomaly = anomaly or "DUP-ACK"
                    stats["dupAck"] += 1

                if is_lost_seg:
                    anomaly = anomaly or "LOST-SEG"
                    stats["lostSeg"] += 1

                if "SYN" in flags_list and "ACK" not in flags_list:
                    if syn_counter.get(src_ip, 0) > 20:
                        anomaly = anomaly or "SYN-FLOOD"
                        stats["synFlood"] += 1

            info = _build_info(pkt, proto_name, flags_list, pkt_len)

            result_packets.append({
                "num":     pkt_index,
                "time":    f"{rel_time:.6f}",
                "src":     src_ip,
                "dst":     dst_ip,
                "proto":   proto_name,
                "len":     pkt_len,
                "flags":   flags_list,
                "anomaly": anomaly,
                "info":    info,
            })

    finally:
        cap.close()

    return {
        "stats":       stats,
        "packets":     result_packets,
        "dns_map":     dns_map,
        "retrans_map": retrans_map,
    }


# ==================== ALERT BUILDER ====================

def build_alerts(stats: dict) -> list:
    alerts = []

    if stats["synFlood"] > 3:
        alerts.append({"level": "critical", "type": "SYN-Flood Hujum",
            "desc": "Ko'p SYN paketlar — potensial DDoS yoki port skanerlash",
            "count": stats["synFlood"] + stats["syn"]})
    elif stats["syn"] > 0:
        alerts.append({"level": "info", "type": "SYN Paketlar",
            "desc": "Oddiy ulanish urinishlari aniqlandi", "count": stats["syn"]})

    if stats["rst"] > 5:
        alerts.append({"level": "warning", "type": "Ko'p RST Paketlar",
            "desc": "Ulanishlar tez-tez majburiy uzilmoqda", "count": stats["rst"]})
    elif stats["rst"] > 0:
        alerts.append({"level": "info", "type": "RST Paketlar",
            "desc": "Bir nechta ulanish uzilishi aniqlandi", "count": stats["rst"]})

    if stats["retrans"] > 5:
        alerts.append({"level": "warning", "type": "Ko'p Retransmission",
            "desc": "Paket yo'qotish — tarmoq muammosi", "count": stats["retrans"]})
    elif stats["retrans"] > 0:
        alerts.append({"level": "info", "type": "Retransmission",
            "desc": "Bir nechta qayta uzatish aniqlandi", "count": stats["retrans"]})

    if stats["dupAck"] > 3:
        alerts.append({"level": "warning", "type": "Dublikat ACK",
            "desc": "Paket yo'qolishi ehtimoli", "count": stats["dupAck"]})

    if stats["lostSeg"] > 0:
        alerts.append({"level": "critical", "type": "Yo'qolgan Segment",
            "desc": "TCP segment yo'qolishi aniqlandi", "count": stats["lostSeg"]})

    if not alerts:
        alerts.append({"level": "ok", "type": "Anomaliya topilmadi",
            "desc": "Trafik normal ko'rinadi", "count": 0})

    return alerts