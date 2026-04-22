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
class ScanCreateView(View):
    """
    Usa django.views.View (nao APIView do DRF) para que o @csrf_exempt
    funcione corretamente. O DRF intercepta o decorator antes que ele
    tenha efeito quando usado com APIView.
    """
    def post(self, request):
        try:
            data = json.loads(request.body)
        except Exception:
            data = {}

        url = (data.get('url') or '').strip()
        silent_mode = bool(data.get('silent_mode', False))
        if not url:
            return JsonResponse({'error': 'URL obrigatoria'}, status=400)
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        scan = ScanTarget.objects.create(url=url, status='queued')
        threading.Thread(
            target=run_full_scan,
            args=(str(scan.id),),
            kwargs={'silent_mode': silent_mode},
            daemon=True
        ).start()
        logger.info("Scan %s iniciado para %s", scan.id, url)
        return JsonResponse(
            {'scan_id': str(scan.id), 'target': scan.url, 'status': scan.status},
            status=201
        )


class ScanListView(APIView):
    def get(self, request):
        scans = ScanTarget.objects.all()[:50]
        return Response([{'id': str(s.id), 'target': s.url, 'status': s.status, 'risk_score': s.risk_score, 'created_at': s.created_at.isoformat()} for s in scans])


class ScanDetailView(APIView):
    def get(self, request, scan_id):
        try:
            scan = ScanTarget.objects.get(id=scan_id)
        except ScanTarget.DoesNotExist:
            return Response({'error': 'Nao encontrado'}, status=drf_status.HTTP_404_NOT_FOUND)
        logs = list(scan.logs.values('step', 'message', 'elapsed_s'))
        return Response({'id': str(scan.id), 'target': scan.url, 'status': scan.status, 'error': scan.error_message, 'logs': logs})


class ScanReportView(APIView):
    def get(self, request, scan_id):
        try:
            scan = ScanTarget.objects.get(id=scan_id)
        except ScanTarget.DoesNotExist:
            return Response({'error': 'Nao encontrado'}, status=drf_status.HTTP_404_NOT_FOUND)
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
            return JsonResponse({'error': 'PDF nao disponivel'}, status=202)
        from reports.generator import generate_pdf
        pdf_bytes = generate_pdf(scan.to_dict())
        slug = scan.url.replace('https://','').replace('http://','').replace('/','_')[:30]
        resp = HttpResponse(pdf_bytes, content_type='application/pdf')
        resp['Content-Disposition'] = f'attachment; filename="redshield-{slug}.pdf"'
        return resp


class ScanEvidenceZipView(View):
    """
    Gera e retorna um ZIP com todas as evidências capturadas automaticamente
    pelo engine durante o scan (request, response, prova de cada vuln).
    """
    def get(self, request, scan_id):
        import io, zipfile, json
        try:
            scan = ScanTarget.objects.get(id=scan_id)
        except ScanTarget.DoesNotExist:
            raise Http404
        if scan.status != 'done':
            return JsonResponse({'error': 'Scan ainda não concluído'}, status=202)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
            findings = scan.findings.exclude(evidence={})
            if not findings.exists():
                findings = scan.findings.all()

            # README
            readme = f"""REDSHIELD PTaaS — Evidências do Scan
======================================
Alvo   : {scan.url}
Scan ID: {scan.id}
Status : {scan.status}
Score  : {scan.risk_score}/10
Total  : {findings.count()} findings com evidências

Estrutura do ZIP:
  00_resumo.json          — Todos os findings com evidências em JSON
  evidencias/NNN_<ID>/
    request.txt           — Request HTTP completo enviado pelo scanner
    response.txt          — Response HTTP completa recebida do servidor
    prova.txt             — Prova automática capturada (payload + conclusão)
    como_reproduzir.txt   — Passo a passo detalhado para reproduzir a falha manualmente
    detalhes.json         — Metadados completos do finding em JSON
"""
            zf.writestr('README.txt', readme)

            # Resumo geral
            summary_data = {
                'alvo': scan.url,
                'scan_id': str(scan.id),
                'data': scan.created_at.isoformat(),
                'risk_score': scan.risk_score,
                'findings': []
            }

            for idx, f in enumerate(findings, 1):
                ev = f.evidence or {}
                folder = f"evidencias/{idx:03d}_{f.finding_id.replace('/', '_').replace(' ', '_')[:40]}/"

                # request.txt
                req_txt = ev.get('request', 'Requisição não capturada para este finding.')
                zf.writestr(folder + 'request.txt', req_txt)

                # response.txt
                resp_txt = ev.get('response', 'Response não capturada para este finding.')
                zf.writestr(folder + 'response.txt', resp_txt)

                # prova.txt
                prova = (
                    f"FINDING   : {f.title}\n"
                    f"SEVERIDADE: {f.severity}\n"
                    f"ID        : {f.finding_id}\n"
                    f"ALVO      : {ev.get('target_url', scan.url)}\n"
                    f"PAYLOAD   : {ev.get('payload', 'N/A')}\n"
                    f"CAPTURADO : {ev.get('captured_at', 'N/A')}\n"
                    f"LATÊNCIA  : {ev.get('elapsed_ms', 'N/A')} ms\n"
                    f"\n"
                    f"PROVA / CONCLUSÃO AUTOMÁTICA\n"
                    f"----------------------------\n"
                    f"{ev.get('proof', f.description)}\n"
                    f"\n"
                    f"DESCRIÇÃO\n"
                    f"---------\n"
                    f"{f.description}\n"
                    f"\n"
                    f"REMEDIAÇÃO\n"
                    f"----------\n"
                    f"{f.remediation}\n"
                )
                zf.writestr(folder + 'prova.txt', prova)

                # como_reproduzir.txt — passos detalhados para comprovar a falha manualmente
                from scanner.engine import reproduction_steps
                repro = reproduction_steps(
                    finding_type=f.finding_type,
                    finding_id=f.finding_id,
                    url=scan.url,
                    payload=ev.get('payload') or None,
                    extra=ev,
                )
                zf.writestr(folder + 'como_reproduzir.txt', repro)

                # detalhes.json
                zf.writestr(folder + 'detalhes.json', json.dumps(f.to_dict(), indent=2, ensure_ascii=False))

                summary_data['findings'].append({
                    'idx': idx,
                    'id': f.finding_id,
                    'title': f.title,
                    'severity': f.severity,
                    'proof': ev.get('proof', ''),
                    'captured_at': ev.get('captured_at', ''),
                })

            zf.writestr('00_resumo.json', json.dumps(summary_data, indent=2, ensure_ascii=False))

        buf.seek(0)
        slug = scan.url.replace('https://','').replace('http://','').replace('/','_')[:30]
        resp = HttpResponse(buf.read(), content_type='application/zip')
        resp['Content-Disposition'] = f'attachment; filename="evidencias-{slug}.zip"'
        return resp
