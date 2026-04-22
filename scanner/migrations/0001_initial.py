from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='ScanTarget',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('url', models.URLField(max_length=2048)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('status', models.CharField(
                    choices=[('queued', 'Na fila'), ('running', 'Executando'), ('done', 'Concluído'), ('error', 'Erro')],
                    default='queued', max_length=20
                )),
                ('risk_score', models.FloatField(blank=True, null=True)),
                ('scan_duration_s', models.FloatField(blank=True, null=True)),
                ('dns_data', models.JSONField(blank=True, default=dict)),
                ('tls_data', models.JSONField(blank=True, default=dict)),
                ('technologies', models.JSONField(blank=True, default=list)),
                ('waf_data', models.JSONField(blank=True, default=dict)),
                ('owasp_results', models.JSONField(blank=True, default=list)),
                ('security_headers', models.JSONField(blank=True, default=list)),
                ('red_team_score', models.IntegerField(default=0)),
                ('blue_team_score', models.IntegerField(default=0)),
                ('red_team_actions', models.JSONField(blank=True, default=list)),
                ('blue_team_actions', models.JSONField(blank=True, default=list)),
                ('error_message', models.TextField(blank=True)),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='ScanLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('step', models.CharField(max_length=50)),
                ('message', models.TextField()),
                ('elapsed_s', models.FloatField(default=0)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('scan', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='logs', to='scanner.scantarget')),
            ],
            options={
                'ordering': ['created_at'],
            },
        ),
        migrations.CreateModel(
            name='Finding',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('finding_type', models.CharField(
                    choices=[('CVE', 'CVE'), ('OWASP', 'OWASP'), ('WAF', 'WAF Bypass'), ('Header', 'HTTP Header'), ('TLS', 'TLS/SSL'), ('CUSTOM', 'Custom')],
                    default='CUSTOM', max_length=20
                )),
                ('finding_id', models.CharField(blank=True, max_length=100)),
                ('title', models.CharField(max_length=512)),
                ('severity', models.CharField(
                    choices=[('CRITICAL', 'Crítico'), ('HIGH', 'Alto'), ('MEDIUM', 'Médio'), ('LOW', 'Baixo'), ('INFO', 'Info')],
                    default='INFO', max_length=20
                )),
                ('cvss_score', models.FloatField(blank=True, null=True)),
                ('description', models.TextField(blank=True)),
                ('remediation', models.TextField(blank=True)),
                ('references', models.JSONField(blank=True, default=list)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('scan', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='findings', to='scanner.scantarget')),
            ],
            options={
                'ordering': ['created_at'],
            },
        ),
    ]
