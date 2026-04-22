from django.urls import path
from .views import DashboardView, ScanCreateView, ScanListView, ScanDetailView, ScanReportView, ScanPDFView, ScanEvidenceZipView

urlpatterns = [
    path('', DashboardView.as_view(), name='dashboard'),
    path('api/scans/', ScanCreateView.as_view(), name='scan-create'),
    path('api/scans/list/', ScanListView.as_view(), name='scan-list'),
    path('api/scans/<uuid:scan_id>/', ScanDetailView.as_view(), name='scan-detail'),
    path('api/scans/<uuid:scan_id>/report/', ScanReportView.as_view(), name='scan-report'),
    path('api/scans/<uuid:scan_id>/pdf/', ScanPDFView.as_view(), name='scan-pdf'),
    path('api/scans/<uuid:scan_id>/evidence/', ScanEvidenceZipView.as_view(), name='scan-evidence'),
]
