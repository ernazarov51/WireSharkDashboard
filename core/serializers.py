"""
analyzer/serializers.py

Request va Response uchun DRF Serializers.
"""

from rest_framework import serializers


# ==================== REQUEST SERIALIZERS ====================

class PcapUploadSerializer(serializers.Serializer):
    """
    POST /api/analyze/ va boshqa endpointlar uchun
    fayl yuklash serializer.

    Frontend shu tarzda yuboradi:
        Content-Type: multipart/form-data
        Body: file=<binary fayl>
    """
    file = serializers.FileField(
        help_text="PCAP, PCAPNG yoki CAP formatdagi tarmoq fayli"
    )

    def validate_file(self, value):
        """Fayl kengaytmasini tekshirish"""
        name = value.name.lower()
        allowed = ('.pcap', '.pcapng', '.cap')
        if not name.endswith(allowed):
            raise serializers.ValidationError(
                f"Faqat {', '.join(allowed)} fayllar qabul qilinadi. "
                f"Yuborilgan: {name}"
            )
        # 100 MB dan katta bo'lsa rad etish
        max_size = 100 * 1024 * 1024
        if value.size > max_size:
            raise serializers.ValidationError(
                f"Fayl hajmi {value.size // (1024*1024)} MB — maksimal 100 MB"
            )
        return value


class PacketsQuerySerializer(serializers.Serializer):
    """
    POST /api/packets/ uchun query parametrlar.
    """
    page = serializers.IntegerField(
        default=1, min_value=1,
        help_text="Sahifa raqami (default: 1)"
    )
    per_page = serializers.IntegerField(
        default=15, min_value=1, max_value=100,
        help_text="Bir sahifadagi paketlar soni (default: 15, max: 100)"
    )
    search = serializers.CharField(
        required=False, allow_blank=True,
        help_text="IP yoki protokol bo'yicha qidirish"
    )
    anomaly_filter = serializers.ChoiceField(
        choices=['all', 'anomaly', 'normal'],
        default='all',
        help_text="'all' | 'anomaly' | 'normal'"
    )


# ==================== RESPONSE SERIALIZERS ====================

class StatsSerializer(serializers.Serializer):
    """
    Statistika raqamlari. Frontend stat cardlarga bog'liq.
    """
    total    = serializers.IntegerField()
    tcp      = serializers.IntegerField()
    udp      = serializers.IntegerField()
    dns      = serializers.IntegerField()
    icmp     = serializers.IntegerField()
    http     = serializers.IntegerField()
    syn      = serializers.IntegerField()
    rst      = serializers.IntegerField()
    fin      = serializers.IntegerField()
    ack      = serializers.IntegerField()
    psh      = serializers.IntegerField()
    retrans  = serializers.IntegerField()
    dupAck   = serializers.IntegerField()
    lostSeg  = serializers.IntegerField()
    synFlood = serializers.IntegerField()


class PacketItemSerializer(serializers.Serializer):
    """
    Bitta paket. Frontend jadval qatoriga mos.

    proto qiymatlari: "TCP" | "UDP" | "DNS" | "ICMP" | "HTTP" | "OTHER"
    anomaly qiymatlari: "RETRANSMIT" | "DUP-ACK" | "RST" | "LOST-SEG" | "SYN-FLOOD" | null
    flags qiymatlari: ["SYN"] | ["SYN","ACK"] | ["RST"] | ["FIN","ACK"] | ...
    """
    num     = serializers.IntegerField()
    time    = serializers.CharField()           # "0.001234"
    src     = serializers.CharField()           # "192.168.1.1"
    dst     = serializers.CharField()           # "10.0.0.2"
    proto   = serializers.CharField()           # "TCP"
    len     = serializers.IntegerField()        # bytes
    flags   = serializers.ListField(
                  child=serializers.CharField()
              )                                 # ["SYN", "ACK"]
    anomaly = serializers.CharField(
                  allow_null=True, default=None
              )                                 # "RST" yoki null
    info    = serializers.CharField()           # "[TCP] SYN Seq=0..."


class AlertSerializer(serializers.Serializer):
    """
    Anomaliya ogohlantirishi.
    level: "critical" | "warning" | "info" | "ok"
    """
    level = serializers.CharField()
    type  = serializers.CharField()
    desc  = serializers.CharField()
    count = serializers.IntegerField()


class AnalyzeResponseSerializer(serializers.Serializer):
    """
    POST /api/analyze/ — to'liq javob.
    """
    success     = serializers.BooleanField()
    filename    = serializers.CharField()
    file_size   = serializers.IntegerField()
    analyzed_at = serializers.FloatField()       # Unix timestamp
    stats       = StatsSerializer()
    packets     = PacketItemSerializer(many=True)
    dns_map     = serializers.DictField(
                      child=serializers.IntegerField()
                  )                              # {"google.com": 15}
    retrans_map = serializers.DictField(
                      child=serializers.IntegerField()
                  )                              # {"192.168.1.5": 3}


class PacketsResponseSerializer(serializers.Serializer):
    """
    POST /api/packets/ — pagination bilan paketlar javob.
    """
    page     = serializers.IntegerField()
    per_page = serializers.IntegerField()
    total    = serializers.IntegerField()
    pages    = serializers.IntegerField()
    packets  = PacketItemSerializer(many=True)


class AlertsResponseSerializer(serializers.Serializer):
    """
    POST /api/alerts/ — ogohlantirishlar javob.
    """
    alerts = AlertSerializer(many=True)


class StatsResponseSerializer(serializers.Serializer):
    """
    POST /api/stats/ — faqat statistika javob.
    """
    stats       = StatsSerializer()
    dns_map     = serializers.DictField(child=serializers.IntegerField())
    retrans_map = serializers.DictField(child=serializers.IntegerField())