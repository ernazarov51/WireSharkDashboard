"""
analyzer/urls.py — API URL marshrutlari
"""
from django.urls import path
# from .views import HealthView, AnalyzeView, StatsView, PacketsView, AlertsView
from .views import AnalyzeView, DashboardTemplateView

urlpatterns = [
    # path('health/',  HealthView.as_view(),  name='health'),
    path('dashboard/',DashboardTemplateView.as_view()),

    path('analyze/', AnalyzeView.as_view(), name='analyze'),

    # path('stats/',   StatsView.as_view(),   name='stats'),


    # path('packets/', PacketsView.as_view(), name='packets'),

    # path('alerts/',  AlertsView.as_view(),  name='alerts'),
]