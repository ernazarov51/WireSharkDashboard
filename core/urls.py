"""
analyzer/urls.py — API URL marshrutlari
"""
from django.urls import path
from .views import HealthView, AnalyzeView, StatsView, PacketsView, AlertsView

urlpatterns = [
    # GET  /api/health/
    path('health/',  HealthView.as_view(),  name='health'),

    # POST /api/analyze/   ← Frontend asosiy endpoint
    path('analyze/', AnalyzeView.as_view(), name='analyze'),

    # POST /api/stats/
    path('stats/',   StatsView.as_view(),   name='stats'),

    # POST /api/packets/?page=1&per_page=15&search=192.168&anomaly_filter=anomaly
    path('packets/', PacketsView.as_view(), name='packets'),

    # POST /api/alerts/
    path('alerts/',  AlertsView.as_view(),  name='alerts'),
]