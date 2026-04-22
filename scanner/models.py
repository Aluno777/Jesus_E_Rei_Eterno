from django.db import models
import uuid


class ScanTarget(models.Model):
    STATUS_CHOICES = [
        ('queued','Na fila'),('running','Executando'),
        ('done','Concluído'),('error','Erro'),
    ]
    id            = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    url           = models.URLField(max_length=2048)
    created_at    = models.DateTimeField(auto_now_add=True)
    updated_at    = models.DateTimeField(auto_now=True)
    status        = models.CharField(max_length=20, choices=STATUS_CHOICES, default='queued')
    risk_score    = models.FloatField(null=True, blank=True)
    scan_duration_s = models.FloatField(null=True, blank=True)
    dns_data      = models.JSONField(default=dict, blank=True)
    tls_data      = models.JSONField(default=dict, blank=True)
    technologies  = models.JSONField(default=list, blank=True)
    waf_data      = models.JSONField(default=dict, blank=True)
    owasp_results = models.JSONField(default=list, blank=True)
    security_headers = models.JSONField(default=list, blank=True)
    red_team_score = models.IntegerField(default=0)
    blue_team_score = models.IntegerField(default=0)
    red_team_actions = models.JSONField(default=list, blank=True)
    blue_team_actions = models.JSONField(default=list, blank=True)
    error_message = models.TextField(blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"[{self.status}] {self.url}"

    def summary(self):
        counts = {'CRITICAL':0,'HIGH':0,'MEDIUM':0,'LOW':0,'INFO':0}
        for f in self.findings.all():
            if f.severity in counts:
                counts[f.severity] += 1
        return counts

    def to_dict(self):
        return {
            'id': str(self.id), 'target': self.url,
            'timestamp': self.created_at.isoformat(),
            'status': self.status, 'risk_score': self.risk_score or 0.0,
            'scan_duration_s': self.scan_duration_s or 0,
            'dns': self.dns_data, 'tls': self.tls_data,
            'technologies': self.technologies, 'waf': self.waf_data,
            'owasp_results': self.owasp_results,
            'security_headers': self.security_headers,
            'summary': self.summary(),
            'all_findings': [f.to_dict() for f in self.findings.all()],
            'red_team_score': self.red_team_score,
            'blue_team_score': self.blue_team_score,
            'red_team_actions': self.red_team_actions,
            'blue_team_actions': self.blue_team_actions,
        }


class ScanLog(models.Model):
    scan      = models.ForeignKey(ScanTarget, on_delete=models.CASCADE, related_name='logs')
    step      = models.CharField(max_length=50)
    message   = models.TextField()
    elapsed_s = models.FloatField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at']


class Finding(models.Model):
    SEVERITY_CHOICES = [
        ('CRITICAL','Crítico'),('HIGH','Alto'),('MEDIUM','Médio'),
        ('LOW','Baixo'),('INFO','Info'),
    ]
    TYPE_CHOICES = [
        ('CVE','CVE'),('OWASP','OWASP'),('WAF','WAF Bypass'),
        ('Header','HTTP Header'),('TLS','TLS/SSL'),('CUSTOM','Custom'),
    ]
    id           = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan         = models.ForeignKey(ScanTarget, on_delete=models.CASCADE, related_name='findings')
    finding_type = models.CharField(max_length=20, choices=TYPE_CHOICES, default='CUSTOM')
    finding_id   = models.CharField(max_length=100, blank=True)
    title        = models.CharField(max_length=512)
    severity     = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='INFO')
    cvss_score   = models.FloatField(null=True, blank=True)
    description  = models.TextField(blank=True)
    remediation  = models.TextField(blank=True)
    references   = models.JSONField(default=list, blank=True)
    # Evidência capturada automaticamente pelo engine
    evidence     = models.JSONField(default=dict, blank=True)
    created_at   = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at']

    def __str__(self):
        return f"[{self.severity}] {self.title}"

    def to_dict(self):
        return {
            'id': self.finding_id or str(self.id),
            'type': self.finding_type, 'title': self.title,
            'severity': self.severity, 'cvss': self.cvss_score,
            'description': self.description, 'remediation': self.remediation,
            'references': self.references,
            'evidence': self.evidence,
        }
