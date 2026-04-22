import json, threading, logging
from django.shortcuts import render
from django.http import JsonResponse, HttpResponse, Http404
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status as drf_status

from .models import ScanTarget, ScanLog, Finding
from .engine import run_full_scan

logger = logging.getLogger('scanner')


class DashboardView(View):
    def get(self, request):
        recent_scans = ScanTarget.objects.all()[:10]
        stats = {
            'total_scans': ScanTarget.objects.count(),
            'critical_findings': Finding.objects.filter(severity='CRITICAL').count(),
            'high_findings': Finding.objects.filter(severity='HIGH').count(),
            'done_scans': ScanTarget.objects.filter(status='done').count(),
        }
        return render(request, 'scanner/dashboard.html', {'recent_scans': recent_scans, 'stats': stats})


@method_decorator(csrf_exempt, name='dispatch')
class ScanCreateView(APIView):
    def post(self, request):
        try:
            data = request.data
        except Exception:
            try:
                data = json.loads(request.body)
            except Exception:
                data = {}
        url = (data.get('url') or '').strip()
        if not url:
            return Response({'error': 'URL obrigatória'}, status=drf_status.HTTP_400_BAD_REQUEST)
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        scan = ScanTarget.objects.create(url=url, status='queued')
        threading.Thread(target=run_full_scan, args=(str(scan.id),), daemon=True).start()
        logger.info("Scan %s iniciado para %s", scan.id, url)
        return Response({'scan_id': str(scan.id), 'target': scan.url, 'status': scan.status}, status=drf_status.HTTP_201_CREATED)


class ScanListView(APIView):
    def get(self, request):
        scans = ScanTarget.objects.all()[:50]
        return Response([{'id': str(s.id), 'target': s.url, 'status': s.status, 'risk_score': s.risk_score, 'created_at': s.created_at.isoformat()} for s in scans])


class ScanDetailView(APIView):
    def get(self, request, scan_id):
        try:
            scan = ScanTarget.objects.get(id=scan_id)
        except ScanTarget.DoesNotExist:
            return Response({'error': 'Não encontrado'}, status=drf_status.HTTP_404_NOT_FOUND)
        logs = list(scan.logs.values('step', 'message', 'elapsed_s'))
        return Response({'id': str(scan.id), 'target': scan.url, 'status': scan.status, 'error': scan.error_message, 'logs': logs})


class ScanReportView(APIView):
    def get(self, request, scan_id):
        try:
            scan = ScanTarget.objects.get(id=scan_id)
        except ScanTarget.DoesNotExist:
            return Response({'error': 'Não encontrado'}, status=drf_status.HTTP_404_NOT_FOUND)
        if scan.status != 'done':
            return Response({'error': 'Scan em andamento'}, status=drf_status.HTTP_202_ACCEPTED)
        return Response(scan.to_dict())


class ScanPDFView(View):
    def get(self, request, scan_id):
        try:
            scan = ScanTarget.objects.get(id=scan_id)
        except ScanTarget.DoesNotExist:
            raise Http404
        if scan.status != 'done':
            return JsonResponse({'error': 'PDF não disponível'}, status=202)
        from reports.generator import generate_pdf
        pdf_bytes = generate_pdf(scan.to_dict())
        slug = scan.url.replace('https://','').replace('http://','').replace('/','_')[:30]
        resp = HttpResponse(pdf_bytes, content_type='application/pdf')
        resp['Content-Disposition'] = f'attachment; filename="redshield-{slug}.pdf"'
        return resp
