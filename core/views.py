"""
analyzer/views.py

TUITScope — barcha API endpointlar.

Endpointlar:
    GET  /api/health/    — server holati
    POST /api/analyze/   — PCAP to'liq tahlil (asosiy)
    POST /api/stats/     — faqat statistika
    POST /api/packets/   — paketlar (pagination + filtr)
    POST /api/alerts/    — anomaliya ogohlantirishlari
"""

import os
import time
import tempfile

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework import status
from drf_spectacular.utils import extend_schema, OpenApiParameter

from .serializers import (
    PcapUploadSerializer,
    PacketsQuerySerializer,
    AnalyzeResponseSerializer,
    PacketsResponseSerializer,
    AlertsResponseSerializer,
    StatsResponseSerializer,
)
from .pcap_parser import parse_pcap, build_alerts


# ==================== YORDAMCHI FUNKSIYA ====================

def save_temp_file(uploaded_file) -> str:
    """
    Django UploadedFile ni vaqtinchalik faylga yozib,
    fayl yo'lini qaytaradi. Ishlatgandan keyin os.unlink() qiling!
    """
    ext = os.path.splitext(uploaded_file.name)[1].lower()
    with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
        for chunk in uploaded_file.chunks():
            tmp.write(chunk)
        return tmp.name


# ==================== VIEWS ====================

class HealthView(APIView):
    """
    GET /api/health/
    Server ishlayotganligini tekshirish.
    """

    @extend_schema(
        summary="Server holati",
        responses={200: {"type": "object", "properties": {
            "status":    {"type": "string", "example": "ok"},
            "service":   {"type": "string"},
            "version":   {"type": "string"},
            "timestamp": {"type": "number"},
        }}}
    )
    def get(self, request):
        return Response({
            "status":    "ok",
            "service":   "TUITScope API",
            "version":   "2.4.1",
            "timestamp": time.time(),
        })


class AnalyzeView(APIView):
    """
    POST /api/analyze/

    PCAP faylni yuklab, to'liq tahlil natijasini qaytaradi.
    Frontend shu endpointdan hamma narsani oladi.

    Request  → multipart/form-data,  field: "file"
    Response → AnalyzeResponseSerializer
    """
    parser_classes = [MultiPartParser, FormParser]

    @extend_schema(
        summary="PCAP faylni to'liq tahlil qilish",
        request=PcapUploadSerializer,
        responses={200: AnalyzeResponseSerializer},
    )
    def post(self, request):
        # 1. Faylni validatsiya qilish
        serializer = PcapUploadSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {"success": False, "errors": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )

        uploaded_file = serializer.validated_data["file"]
        tmp_path = None

        try:
            # 2. Vaqtinchalik faylga saqlash
            tmp_path = save_temp_file(uploaded_file)

            # 3. PCAP tahlil
            result = parse_pcap(tmp_path)

            # 4. Javob yig'ish
            response_data = {
                "success":     True,
                "filename":    uploaded_file.name,
                "file_size":   uploaded_file.size,
                "analyzed_at": time.time(),
                "stats":       result["stats"],
                "packets":     result["packets"],
                "dns_map":     result["dns_map"],
                "retrans_map": result["retrans_map"],
            }

            return Response(response_data, status=status.HTTP_200_OK)

        except RuntimeError as e:
            # Scapy o'rnatilmagan
            return Response(
                {"success": False, "error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        except Exception as e:
            return Response(
                {"success": False, "error": f"Tahlil xatosi: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        finally:
            # Vaqtinchalik faylni o'chirish
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)


class StatsView(APIView):
    """
    POST /api/stats/

    Faqat statistika raqamlarini qaytaradi.
    Charts va stat cardlar uchun yengil endpoint.

    Request  → multipart/form-data,  field: "file"
    Response → {stats, dns_map, retrans_map}
    """
    parser_classes = [MultiPartParser, FormParser]

    @extend_schema(
        summary="Faqat statistika raqamlarini olish",
        request=PcapUploadSerializer,
        responses={200: StatsResponseSerializer},
    )
    def post(self, request):
        serializer = PcapUploadSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {"success": False, "errors": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )

        uploaded_file = serializer.validated_data["file"]
        tmp_path = None

        try:
            tmp_path = save_temp_file(uploaded_file)
            result = parse_pcap(tmp_path)

            return Response({
                "stats":       result["stats"],
                "dns_map":     result["dns_map"],
                "retrans_map": result["retrans_map"],
            })
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)


class PacketsView(APIView):
    """
    POST /api/packets/

    Paket ro'yxatini pagination va filtrlar bilan qaytaradi.

    Request  → multipart/form-data,  field: "file"
               Query params: page, per_page, search, anomaly_filter
    Response → {page, per_page, total, pages, packets[...]}

    Frontend jadval (table) shu endpointdan foydalanishi mumkin.
    """
    parser_classes = [MultiPartParser, FormParser]

    @extend_schema(
        summary="Paket ro'yxati (pagination + filtr)",
        request=PcapUploadSerializer,
        parameters=[
            OpenApiParameter("page",           int,  description="Sahifa raqami"),
            OpenApiParameter("per_page",       int,  description="Sahifadagi paketlar"),
            OpenApiParameter("search",         str,  description="IP yoki protokol"),
            OpenApiParameter("anomaly_filter", str,  description="all|anomaly|normal"),
        ],
        responses={200: PacketsResponseSerializer},
    )
    def post(self, request):
        # Fayl validatsiyasi
        file_serializer = PcapUploadSerializer(data=request.data)
        if not file_serializer.is_valid():
            return Response(
                {"errors": file_serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Query parametrlar
        query_serializer = PacketsQuerySerializer(data=request.query_params)
        if not query_serializer.is_valid():
            return Response(
                {"errors": query_serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )

        params         = query_serializer.validated_data
        page           = params["page"]
        per_page       = params["per_page"]
        search         = params.get("search", "").lower()
        anomaly_filter = params.get("anomaly_filter", "all")

        uploaded_file = file_serializer.validated_data["file"]
        tmp_path = None

        try:
            tmp_path = save_temp_file(uploaded_file)
            result   = parse_pcap(tmp_path)
            packets  = result["packets"]

            # --- Filtrlar ---
            if search:
                packets = [
                    p for p in packets
                    if search in p["src"]
                    or search in p["dst"]
                    or search in p["proto"].lower()
                ]

            if anomaly_filter == "anomaly":
                packets = [p for p in packets if p["anomaly"]]
            elif anomaly_filter == "normal":
                packets = [p for p in packets if not p["anomaly"]]

            # --- Pagination ---
            total    = len(packets)
            pages    = max(1, (total + per_page - 1) // per_page)
            start    = (page - 1) * per_page
            page_data = packets[start: start + per_page]

            return Response({
                "page":     page,
                "per_page": per_page,
                "total":    total,
                "pages":    pages,
                "packets":  page_data,
            })

        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)


class AlertsView(APIView):
    """
    POST /api/alerts/

    Anomaliya ogohlantirishlarini qaytaradi.
    Paket faylini yuklash shart emas — stats asosida hisoblanadi.

    Request  → multipart/form-data,  field: "file"
    Response → {alerts: [{level, type, desc, count}, ...]}

    level qiymatlari:
        "critical" → qizil     (SYN-Flood, Lost Segment)
        "warning"  → to'q sariq (Ko'p RST, Retransmission)
        "info"     → ko'k      (Oddiy SYN, RST)
        "ok"       → yashil    (Anomaliya topilmadi)
    """
    parser_classes = [MultiPartParser, FormParser]

    @extend_schema(
        summary="Anomaliya ogohlantirishlari",
        request=PcapUploadSerializer,
        responses={200: AlertsResponseSerializer},
    )
    def post(self, request):
        serializer = PcapUploadSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {"errors": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )

        uploaded_file = serializer.validated_data["file"]
        tmp_path = None

        try:
            tmp_path = save_temp_file(uploaded_file)
            result   = parse_pcap(tmp_path)
            alerts   = build_alerts(result["stats"])

            return Response({"alerts": alerts})

        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)