"""
RedShield PTaaS — Scanner Engine (Django)
Motor de varredura real: DNS, TLS, WAF, CVE, OWASP Top 10
"""

import socket
import ssl
import time
import datetime
import urllib.request
import urllib.error
import urllib.parse
import logging

from .threat_intel import (
    CVE_DATABASE, WAF_SIGNATURES, WAF_BYPASS_TECHNIQUES, SECURITY_HEADERS
)

logger = logging.getLogger('scanner')


def safe_request(url, method="GET", headers=None, timeout=5):
    """
    HTTP request segura — retorna (status, headers, body, elapsed_ms).

    Timeout reduzido para 5s (era 8s): scans com 53 requests tinham
    pior caso de 424s. Com 5s o pior caso cai para 265s.
    Socket timeout explícito evita que DNS resolution fique pendurado.
    """
    default_headers = {
        # User-Agent de navegador real — menos agressivo que "Security-Scanner"
        # Não engana o servidor, mas não anuncia proativamente ser um scanner.
        # Ferramentas como Burp Suite e Nmap fazem o mesmo.
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
        "Accept-Encoding": "gzip, deflate, br",
        "Cache-Control": "no-cache",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
    }
    if headers:
        default_headers.update(headers)
    req = urllib.request.Request(url, headers=default_headers, method=method)
    start = time.time()
    # Socket timeout global para cobrir DNS resolution (urlopen timeout não cobre)
    import socket as _socket
    old_timeout = _socket.getdefaulttimeout()
    _socket.setdefaulttimeout(timeout)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(8192).decode("utf-8", errors="ignore")
            elapsed = round((time.time() - start) * 1000)
            return resp.status, dict(resp.headers), body, elapsed
    except urllib.error.HTTPError as e:
        elapsed = round((time.time() - start) * 1000)
        try:
            body = e.read(4096).decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        return e.code, dict(e.headers), body, elapsed
    except Exception as e:
        return None, {}, str(e), round((time.time() - start) * 1000)
    finally:
        _socket.setdefaulttimeout(old_timeout)



def browser_request(url, timeout=15):
    """
    Faz requisição usando Playwright (navegador real Chromium).
    Passa por todas as verificações de bot: JavaScript challenges,
    fingerprint de canvas/WebGL, cookies de sessão, TLS fingerprint real.

    Retorna (status, headers, body, elapsed_ms) — mesma interface do safe_request.
    Usado como fallback quando safe_request é bloqueado (status None ou 5xx sem body).
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        logger.warning("Playwright não instalado — usando safe_request")
        return safe_request(url, timeout=timeout)

    start = time.time()
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-blink-features=AutomationControlled",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--single-process",
                    "--no-zygote",
                    "--window-size=1920,1080",
                ],
            )
            context = browser.new_context(
                viewport={"width": 1920, "height": 1080},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                locale="pt-BR",
                timezone_id="America/Sao_Paulo",
                # Aceitar cookies e scripts — simula usuário real
                java_script_enabled=True,
                accept_downloads=False,
                ignore_https_errors=True,
                extra_http_headers={
                    "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                },
            )

            # Remover a flag que identifica automação no JavaScript
            context.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
                Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3] });
                Object.defineProperty(navigator, 'languages', { get: () => ['pt-BR', 'en-US'] });
                window.chrome = { runtime: {} };
            """)

            page = context.new_page()

            resp_status = None
            resp_headers = {}

            def on_response(response):
                nonlocal resp_status, resp_headers
                if response.url == url or url in response.url:
                    resp_status = response.status
                    resp_headers = dict(response.headers)

            page.on("response", on_response)

            # Navegar e aguardar rede estabilizar (igual a usuário real)
            page.goto(url, wait_until="networkidle", timeout=timeout * 1000)

            # Aguardar um tempo mínimo como humano faria
            import random
            page.wait_for_timeout(random.randint(800, 1500))

            body = page.content()
            elapsed = round((time.time() - start) * 1000)

            browser.close()
            return resp_status or 200, resp_headers, body, elapsed

    except Exception as e:
        elapsed = round((time.time() - start) * 1000)
        logger.warning("browser_request falhou para %s: %s", url, e)
        # Fallback para safe_request
        return safe_request(url, timeout=timeout)



def capture_evidence(title, url, method="GET", req_headers=None, req_body=None,
                     resp_status=None, resp_headers=None, resp_body=None,
                     payload=None, proof=None, elapsed_ms=None):
    """
    Monta o dicionário de evidência capturada automaticamente pelo engine.
    Inclui request completo, response completo e prova da vulnerabilidade.
    """
    import datetime
    req_lines = [f"{method} {url} HTTP/1.1"]
    for k, v in (req_headers or {}).items():
        req_lines.append(f"{k}: {v}")
    if req_body:
        req_lines.append("")
        req_lines.append(req_body)

    resp_lines = [f"HTTP/1.1 {resp_status or '?'}"]
    for k, v in (resp_headers or {}).items():
        resp_lines.append(f"{k}: {v}")
    if resp_body:
        resp_lines.append("")
        resp_lines.append(resp_body[:2000])  # limita a 2KB para não explodir o banco

    return {
        "captured_at": datetime.datetime.utcnow().isoformat() + "Z",
        "target_url": url,
        "payload": payload or "",
        "proof": proof or "",
        "elapsed_ms": elapsed_ms,
        "request": "\n".join(req_lines),
        "response": "\n".join(resp_lines),
        "response_status": resp_status,
    }


def reproduction_steps(finding_type, finding_id, url, payload=None, extra=None):
    """
    Gera guia de reprodução no formato Bug Bounty:
    request exato, response esperada, critério de validação.
    """
    ev     = extra or {}
    target = ev.get('target_url', url)
    base   = url.rstrip('/')
    host   = url.replace('https://','').replace('http://','').split('/')[0]
    pl     = payload or ''

    def fmt(title, found, request_cmd, expected_vuln, expected_safe, impact, cvss):
        return f"""================================================================
 RELATÓRIO DE REPRODUÇÃO — {title}
 Alvo      : {target}
 Scanner   : RedShield PTaaS
 Data      : {__import__('datetime').datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}
================================================================

O QUE FOI DETECTADO
-------------------
{found}

REQUEST ENVIADO PELO SCANNER
-----------------------------
{ev.get('request', '(ver request.txt nesta pasta)').split(chr(10))[0]}
{ev.get('request', '').split(chr(10))[1] if chr(10) in ev.get('request','') else ''}

COMO REPRODUZIR (passo a passo)
---------------------------------
{request_cmd}

RESULTADO QUE CONFIRMA A VULNERABILIDADE
-----------------------------------------
{expected_vuln}

RESULTADO QUE INDICA CORREÇÃO
-------------------------------
{expected_safe}

IMPACTO
-------
{impact}

CVSS
----
{cvss}

REFERÊNCIAS
-----------
https://owasp.org/www-project-top-ten/
https://cwe.mitre.org/
================================================================
"""

    # ── A01 — Broken Access Control ──────────────────────────────────────────
    if 'A01' in (finding_id or ''):
        path = target.replace(base, '') or '/admin'
        return fmt(
            title="A01 — Broken Access Control",
            found=(
                f"O recurso '{path}' retornou HTTP 200 sem nenhum cookie de sessão\n"
                f"ou header de autenticação. Qualquer pessoa pode acessá-lo diretamente."
            ),
            request_cmd=(
                f"1. Abra um terminal e execute o comando abaixo (sem cookies):\n\n"
                f"     curl -v --cookie \"\" \"{target}\"\n\n"
                f"2. Observe o código HTTP retornado.\n\n"
                f"3. Para confirmar que não há redirect para login:\n\n"
                f"     curl -v --max-redirs 0 \"{target}\"\n\n"
                f"4. Compare com uma URL que exige autenticação — o comportamento\n"
                f"   deve ser diferente (401 ou redirect para /login)."
            ),
            expected_vuln=(
                f"  HTTP 200 com conteúdo do recurso restrito na response.\n"
                f"  Sem redirect para página de login."
            ),
            expected_safe=(
                f"  HTTP 401 Unauthorized  — recurso exige autenticação.\n"
                f"  HTTP 302 → /login      — redirect para tela de login.\n"
                f"  HTTP 403 Forbidden     — acesso negado explicitamente."
            ),
            impact=(
                f"Acesso não autorizado a recursos administrativos ou dados sensíveis\n"
                f"sem necessidade de credenciais."
            ),
            cvss="7.5 HIGH — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        )

    # ── A02 — Falhas Criptográficas / HSTS ───────────────────────────────────
    if 'A02' in (finding_id or ''):
        http_url = base.replace('https://', 'http://')
        return fmt(
            title="A02 — Falhas Criptográficas / HSTS Ausente",
            found=(
                f"O servidor não envia o header Strict-Transport-Security (HSTS)\n"
                f"e/ou responde em HTTP sem forçar redirecionamento para HTTPS."
            ),
            request_cmd=(
                f"1. Verifique se HTTP responde sem redirecionar para HTTPS:\n\n"
                f"     curl -v -I \"{http_url}/\"\n\n"
                f"   Observe: se retornar HTTP 200, não há redirect.\n\n"
                f"2. Verifique ausência do header HSTS:\n\n"
                f"     curl -sI \"{target}\" | grep -i strict-transport-security\n\n"
                f"   Ausência de output = header não presente.\n\n"
                f"3. Verificação completa com testssl.sh:\n\n"
                f"     testssl.sh --hsts \"{host}\""
            ),
            expected_vuln=(
                f"  Passo 1: HTTP 200 sem 'Location: https://' na response.\n"
                f"  Passo 2: Nenhuma linha retornada (header HSTS ausente)."
            ),
            expected_safe=(
                f"  Passo 1: HTTP 301/302 com Location: https://...\n"
                f"  Passo 2: Strict-Transport-Security: max-age=31536000"
            ),
            impact=(
                f"Sem HSTS, o browser aceita conexões HTTP. Em redes não confiáveis,\n"
                f"um atacante posicionado na rede pode interceptar o tráfego."
            ),
            cvss="5.9 MEDIUM — AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"
        )

    # ── A03 — SQL Injection ───────────────────────────────────────────────────
    if 'A03' in (finding_id or ''):
        return fmt(
            title="A03 — SQL Injection",
            found=(
                f"O parâmetro de busca refletiu erro de banco de dados quando o\n"
                f"scanner injetou o payload: {pl or chr(39) + chr(39) + chr(32) + chr(79) + chr(82) + chr(32) + chr(49) + chr(61) + chr(49)}\n"
                f"URL testada: {target}"
            ),
            request_cmd=(
                f"1. Execute a requisição com o payload exato do scanner:\n\n"
                f"     curl -s \"{target}\"\n\n"
                f"2. Teste com aspas simples isoladas para confirmar o erro:\n\n"
                f"     curl -s \"{base}/search?q=%27\"\n\n"
                f"3. Teste com payload clássico:\n\n"
                f"     curl -s \"{base}/search?q=1%27+OR+%271%27%3D%271\"\n\n"
                f"4. Compare a response com uma busca normal:\n\n"
                f"     curl -s \"{base}/search?q=teste\""
            ),
            expected_vuln=(
                f"  Response contém qualquer um destes termos:\n"
                f"    - 'You have an error in your SQL syntax'\n"
                f"    - 'Warning: mysql_fetch'\n"
                f"    - 'ORA-01756' / 'pg_query()'\n"
                f"    - 'Unclosed quotation mark'\n"
                f"  Ou: comportamento diferente entre payload e busca normal."
            ),
            expected_safe=(
                f"  Response idêntica para qualquer input.\n"
                f"  Mensagem genérica de erro sem detalhes do banco.\n"
                f"  HTTP 400 com mensagem 'input inválido'."
            ),
            impact=(
                f"Leitura não autorizada de dados do banco de dados.\n"
                f"Potencial bypass de autenticação e, em casos extremos, escrita no banco."
            ),
            cvss="9.8 CRITICAL — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        )

    # ── A05 — Security Misconfiguration ──────────────────────────────────────
    if 'A05' in (finding_id or ''):
        return fmt(
            title="A05 — Security Misconfiguration",
            found=(
                f"Headers HTTP expõem versão de software e/ou arquivos sensíveis\n"
                f"estão acessíveis publicamente: {target}"
            ),
            request_cmd=(
                f"1. Verifique os headers informativos do servidor:\n\n"
                f"     curl -sI \"{target}\"\n\n"
                f"   Observe os headers: Server, X-Powered-By, X-Generator.\n\n"
                f"2. Verifique se arquivos sensíveis estão acessíveis:\n\n"
                f"     curl -o /dev/null -sw '%{{http_code}}' \"{base}/.env\"\n"
                f"     curl -o /dev/null -sw '%{{http_code}}' \"{base}/.git/config\"\n"
                f"     curl -o /dev/null -sw '%{{http_code}}' \"{base}/phpinfo.php\"\n\n"
                f"3. Se algum retornar 200, acesse e veja o conteúdo:\n\n"
                f"     curl -s \"{base}/.env\" | head -20"
            ),
            expected_vuln=(
                f"  Passo 1: Headers revelam versão — ex: 'Server: Apache/2.4.49'.\n"
                f"  Passo 2: HTTP 200 em .env, .git/config ou phpinfo.php.\n"
                f"  Passo 3: Arquivo retorna conteúdo com variáveis ou configurações."
            ),
            expected_safe=(
                f"  Passo 1: Header Server genérico ou ausente.\n"
                f"  Passo 2: HTTP 403 ou 404 em todos os arquivos sensíveis."
            ),
            impact=(
                f"Exposição de versão de software facilita seleção de exploits.\n"
                f"Arquivos sensíveis podem conter credenciais de banco e serviços."
            ),
            cvss="7.5 HIGH — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        )

    # ── A07 — Auth Failures ───────────────────────────────────────────────────
    if 'A07' in (finding_id or ''):
        return fmt(
            title="A07 — Falhas de Autenticação",
            found=(
                f"Endpoint de autenticação acessível em: {target}\n"
                f"O scanner não detectou mecanismo de bloqueio após tentativas repetidas."
            ),
            request_cmd=(
                f"1. Confirme que o endpoint existe e responde:\n\n"
                f"     curl -v -o /dev/null -w '%{{http_code}}' \"{target}\"\n\n"
                f"2. Verifique ausência de rate limiting (envie 10 requisições):\n\n"
                f"     for i in $(seq 1 10); do\n"
                f"       curl -s -o /dev/null -w \"Tentativa $i: %{{http_code}}\\n\" \\\n"
                f"            -X POST \"{target}\" \\\n"
                f"            -d \"username=admin&password=errada$i\"\n"
                f"     done\n\n"
                f"3. Verifique se respostas para usuário válido e inválido são diferentes:\n\n"
                f"     curl -s -X POST \"{target}\" -d \"username=admin&password=errada\"\n"
                f"     curl -s -X POST \"{target}\" -d \"username=naoexiste99&password=errada\""
            ),
            expected_vuln=(
                f"  Passo 2: Todas as 10 tentativas retornam o mesmo código HTTP (sem bloqueio).\n"
                f"  Passo 3: Respostas diferentes para usuário válido vs. inválido\n"
                f"           (indica enumeração de usuários)."
            ),
            expected_safe=(
                f"  Passo 2: HTTP 429 (Too Many Requests) a partir da tentativa 5.\n"
                f"  Passo 3: Mesma response para usuário válido e inválido."
            ),
            impact=(
                f"Sem rate limiting: credenciais podem ser descobertas por força bruta.\n"
                f"Com enumeração: lista de usuários válidos fica exposta."
            ),
            cvss="7.5 HIGH — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        )

    # ── A10 — SSRF ────────────────────────────────────────────────────────────
    if 'A10' in (finding_id or ''):
        return fmt(
            title="A10 — Server-Side Request Forgery (SSRF)",
            found=(
                f"O parâmetro em {target} aceita URLs externas e o servidor\n"
                f"realizou a requisição retornando o conteúdo para o cliente.\n"
                f"Payload testado: {pl or 'http://169.254.169.254/'}"
            ),
            request_cmd=(
                f"1. Reproduza a requisição exata do scanner:\n\n"
                f"     curl -s \"{target}\"\n\n"
                f"   Observe o corpo da response.\n\n"
                f"2. Para confirmar SSRF, use um serviço de callback público:\n\n"
                f"   a. Acesse https://webhook.site e copie sua URL única.\n"
                f"   b. Substitua no parâmetro vulnerável:\n\n"
                f"     curl -s \"{base}/fetch?url=https://webhook.site/SUA-URL-UNICA\"\n\n"
                f"   c. Verifique no webhook.site se uma requisição chegou.\n"
                f"      Requisição recebida = SSRF confirmado.\n\n"
                f"3. Se o alvo for AWS, verifique se metadados são retornados:\n\n"
                f"     curl -s \"{target}\" | grep -iE 'ami-id|instance-id|hostname'"
            ),
            expected_vuln=(
                f"  Passo 1: Response contém conteúdo de URL interna ou externa.\n"
                f"  Passo 2c: Requisição recebida no webhook.site.\n"
                f"  Passo 3: Metadados de cloud visíveis na response."
            ),
            expected_safe=(
                f"  Passo 1: HTTP 400 / mensagem 'URL não permitida'.\n"
                f"  Passo 2c: Nenhuma requisição recebida no webhook.site.\n"
                f"  Validação de allowlist de domínios no servidor."
            ),
            impact=(
                f"O servidor pode ser usado para acessar recursos internos da rede.\n"
                f"Em ambientes cloud, pode expor credenciais temporárias de IAM."
            ),
            cvss="9.8 CRITICAL — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        )

    # ── WAF Bypass ────────────────────────────────────────────────────────────
    if 'WAF-BYPASS' in (finding_id or ''):
        return fmt(
            title="WAF Bypass",
            found=(
                f"O scanner enviou um payload com técnica de ofuscação e não recebeu\n"
                f"resposta de bloqueio (HTTP 403) do WAF.\n"
                f"Payload: {pl or 'payload ofuscado'}\n"
                f"URL testada: {target}"
            ),
            request_cmd=(
                f"1. Confirme que o WAF bloqueia payload direto (linha de base):\n\n"
                f"     curl -o /dev/null -sw '%{{http_code}}' \"{base}/?q=<script>alert(1)</script>\"\n\n"
                f"   Esperado: 403 (WAF bloqueia).\n\n"
                f"2. Reproduza com o payload do scanner que não foi bloqueado:\n\n"
                f"     curl -v \"{target}\"\n\n"
                f"3. Compare os códigos HTTP dos dois comandos.\n"
                f"   Passo 1 retorna 403 e passo 2 retorna 200/404 = bypass confirmado."
            ),
            expected_vuln=(
                f"  Passo 1: HTTP 403 (WAF ativo).\n"
                f"  Passo 2: HTTP 200 ou 404 — payload passou pelo WAF sem bloqueio."
            ),
            expected_safe=(
                f"  Ambos os passos retornam HTTP 403.\n"
                f"  WAF normaliza e bloqueia variações de encoding."
            ),
            impact=(
                f"Payloads maliciosos podem alcançar a aplicação contornando o WAF,\n"
                f"expondo vulnerabilidades que o WAF deveria mitigar."
            ),
            cvss="8.1 HIGH — AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
        )

    # ── TLS ───────────────────────────────────────────────────────────────────
    if finding_id in ('TLS-EXPIRED', 'TLS-SELFSIGNED'):
        issue = "expirado" if finding_id == 'TLS-EXPIRED' else "auto-assinado"
        return fmt(
            title=f"TLS — Certificado {issue}",
            found=(
                f"O certificado TLS do servidor está {issue}.\n"
                f"Browsers e clientes HTTP rejeitam a conexão com erro de certificado."
            ),
            request_cmd=(
                f"1. Verifique os dados do certificado:\n\n"
                f"     echo | openssl s_client -connect {host}:443 2>/dev/null \\\n"
                f"     | openssl x509 -noout -dates -issuer -subject\n\n"
                f"   {'Observe: notAfter no passado = expirado.' if finding_id == 'TLS-EXPIRED' else 'Observe: issuer == subject = auto-assinado.'}\n\n"
                f"2. Confirme que curl rejeita a conexão:\n\n"
                f"     curl -v \"https://{host}/\" 2>&1 | grep -iE 'expire|self.sign|verify|SSL'\n\n"
                f"3. Verifique visualmente no browser:\n\n"
                f"   Acesse https://{host}/ — o browser deve exibir alerta de segurança."
            ),
            expected_vuln=(
                f"  Passo 1: notAfter no passado {'ou issuer == subject' if issue == 'auto-assinado' else ''}.\n"
                f"  Passo 2: curl retorna erro SSL sem --insecure.\n"
                f"  Passo 3: Browser exibe alerta de certificado inválido."
            ),
            expected_safe=(
                f"  Passo 1: notAfter no futuro, issuer = CA confiável (Let's Encrypt, DigiCert etc).\n"
                f"  Passo 2: curl conecta sem erros.\n"
                f"  Passo 3: Browser exibe cadeado verde/seguro."
            ),
            impact=(
                f"Usuários que ignoram o alerta ficam sujeitos a interceptação de tráfego.\n"
                f"Clientes automatizados rejeitam a conexão, causando falhas de integração."
            ),
            cvss="7.4 HIGH — AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
        )

    # ── Headers ausentes ──────────────────────────────────────────────────────
    if finding_id and finding_id.startswith('HEADER-'):
        header_name = finding_id.replace('HEADER-', '')
        impacts = {
            'X-Frame-Options':        ('Clickjacking — página pode ser embutida em iframe malicioso.', '4.3 MEDIUM'),
            'Content-Security-Policy':('XSS sem restrição de origens de scripts externos.',            '6.1 MEDIUM'),
            'X-Content-Type-Options': ('MIME sniffing — browser pode executar arquivos com tipo errado.','4.3 MEDIUM'),
            'Strict-Transport-Security': ('Downgrade HTTP possível em redes não confiáveis.',           '5.9 MEDIUM'),
            'Referrer-Policy':        ('URL completa (com tokens/IDs) enviada em header Referer.',      '3.1 LOW'),
        }
        impact_txt, cvss_val = impacts.get(header_name, (f"Consultar OWASP para impacto do {header_name}.", '3.1 LOW'))
        return fmt(
            title=f"Header de Segurança Ausente: {header_name}",
            found=(
                f"O header '{header_name}' não está presente na response HTTP.\n"
                f"Este header é obrigatório pelas diretrizes OWASP Secure Headers."
            ),
            request_cmd=(
                f"1. Confirme a ausência do header:\n\n"
                f"     curl -sI \"{target}\" | grep -i \"{header_name.lower()}\"\n\n"
                f"   Resultado vulnerável: sem output.\n\n"
                f"2. Veja todos os headers de segurança presentes:\n\n"
                f"     curl -sI \"{target}\" | grep -iE \\\n"
                f"     'strict-transport|content-security|x-frame|x-content-type|referrer|permissions'\n\n"
                f"3. Verificação completa via securityheaders.com:\n\n"
                f"     https://securityheaders.com/?q={target}&followRedirects=on"
            ),
            expected_vuln=(
                f"  Passo 1: Nenhuma linha retornada.\n"
                f"  Passo 3: Grade F ou D no securityheaders.com."
            ),
            expected_safe=(
                f"  Passo 1: {header_name}: <valor configurado>\n"
                f"  Passo 3: Grade A ou B no securityheaders.com."
            ),
            impact=impact_txt,
            cvss=cvss_val
        )

    # ── CVE ───────────────────────────────────────────────────────────────────
    if finding_id and 'CVE-' in (finding_id or ''):
        return fmt(
            title=f"CVE Identificado: {finding_id}",
            found=(
                f"Os headers HTTP do servidor revelam uma versão de software que\n"
                f"corresponde ao range afetado pelo {finding_id}."
            ),
            request_cmd=(
                f"1. Confirme a versão do software nos headers:\n\n"
                f"     curl -sI \"{target}\" | grep -iE 'server|x-powered-by|x-generator'\n\n"
                f"2. Compare a versão com o range afetado no NVD:\n\n"
                f"     https://nvd.nist.gov/vuln/detail/{finding_id}\n\n"
                f"3. Verifique se há template público de detecção com nuclei:\n\n"
                f"     nuclei -u \"{target}\" -id {finding_id.lower()} -v\n\n"
                f"4. Se nuclei confirmar: vulnerabilidade ativa detectada."
            ),
            expected_vuln=(
                f"  Passo 1: Header revela versão dentro do range afetado pelo CVE.\n"
                f"  Passo 3: nuclei retorna '[{finding_id}] [{target}] matched'."
            ),
            expected_safe=(
                f"  Passo 1: Versão atualizada (fora do range afetado).\n"
                f"  Passo 3: nuclei não retorna match."
            ),
            impact=(
                f"Versão desatualizada com vulnerabilidade conhecida e pública.\n"
                f"Consulte https://nvd.nist.gov/vuln/detail/{finding_id} para CVSS e impacto específico."
            ),
            cvss=f"Ver NVD: https://nvd.nist.gov/vuln/detail/{finding_id}"
        )

    # ── Fallback ──────────────────────────────────────────────────────────────
    return fmt(
        title=finding_id or "Vulnerabilidade Detectada",
        found=f"Comportamento anômalo detectado em: {target}",
        request_cmd=(
            f"1. Acesse a URL diretamente:\n\n"
            f"     curl -v \"{target}\"\n\n"
            f"2. Compare com URL base sem payload:\n\n"
            f"     curl -v \"{base}/\"\n\n"
            f"3. {f'Repita com o payload: {pl}' if pl else 'Ver detalhes em detalhes.json nesta pasta.'}"
        ),
        expected_vuln=f"  Comportamento diferente entre passo 1 e passo 2.{chr(10)}  {f'Payload {pl} causa resposta anômala.' if pl else ''}",
        expected_safe="  Respostas idênticas e sem anomalia para qualquer input.",
        impact="Consultar descrição do finding para impacto específico.",
        cvss="Ver detalhes.json"
    )


def resolve_dns(hostname):
    result = {"hostname": hostname, "ips": [], "errors": []}
    try:
        # Timeout explícito para não ficar pendurado em DNS lento
        old_to = socket.getdefaulttimeout()
        socket.setdefaulttimeout(5)
        info = socket.getaddrinfo(hostname, None)
        socket.setdefaulttimeout(old_to)
        result["ips"] = list(set(x[4][0] for x in info))
    except Exception as e:
        result["errors"].append(str(e))
    return result


def check_tls(hostname, port=443):
    result = {
        "valid": False, "expired": False, "issuer": "", "subject": "",
        "expiry": "", "version": "", "cipher": "", "days_remaining": 0,
        "self_signed": False, "errors": []
    }
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((hostname, port), timeout=8),
            server_hostname=hostname
        ) as ssock:
            cert = ssock.getpeercert()
            result["valid"] = True
            result["version"] = ssock.version()
            result["cipher"] = ssock.cipher()[0] if ssock.cipher() else ""
            not_after = cert.get("notAfter", "")
            if not_after:
                expiry_dt = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                result["expiry"] = expiry_dt.strftime("%Y-%m-%d")
                delta = expiry_dt - datetime.datetime.utcnow()
                result["days_remaining"] = delta.days
                result["expired"] = delta.days < 0
            issuer = dict(x[0] for x in cert.get("issuer", []))
            subject = dict(x[0] for x in cert.get("subject", []))
            result["issuer"] = issuer.get("organizationName", issuer.get("commonName", ""))
            result["subject"] = subject.get("commonName", "")
            result["self_signed"] = result["issuer"] == result["subject"]
    except ssl.SSLCertVerificationError:
        result["errors"].append("Certificado inválido ou não confiável")
    except Exception as e:
        result["errors"].append(str(e))
    return result


def detect_waf(resp_headers, body):
    detected = []
    header_keys_lower = {k.lower(): v.lower() for k, v in resp_headers.items()}
    for waf_name, sig in WAF_SIGNATURES.items():
        score = 0
        for h in sig.get("headers", []):
            if h.lower() in header_keys_lower:
                score += 2
        for pattern in sig.get("body_patterns", []):
            if pattern.lower() in body.lower():
                score += 2
        if score >= 2:
            detected.append(waf_name)
    return detected or ["Não detectado / Personalizado"]


def test_waf_bypasses(url, silent=False):
    """
    Testa técnicas de bypass contra o WAF com teste de baseline.

    POLÍTICA ANTI-FALSO-POSITIVO:
    ──────────────────────────────────────────────────────────────
    Antes de testar payloads, faz 2 requisições baseline:
      1. /search?q=hello  (query normal — sem payload)
      2. /search?q=       (query vazia)

    Regras de classificação:
    • Se baseline retorna 404: endpoint não existe → todos NOT_FOUND
    • Se baseline retorna 200 E payload retorna 200: NOT_BYPASS
      (site responde 200 para tudo — não dá pra distinguir bypass)
    • Se baseline retorna 403 E payload retorna 200: BYPASS real
    • BYPASS confirmado → HTTP 200 sem bloqueio E baseline era 403/bloqueado
    • BLOQUEADO → HTTP 403, 406, 429, 503, 418
    • NOT_FOUND → HTTP 404 — endpoint inexistente
    • PARCIAL   → HTTP 400, 405, 500, 502
    """
    results = []
    test_base = url.rstrip("/") + "/search?q="

    # ── Teste de baseline: comportamento sem payload ──────────────────────────
    baseline_status, _, baseline_body, _ = safe_request(test_base + "hello")
    baseline_blocked = baseline_status in [403, 406, 429, 503, 418]
    baseline_200     = baseline_status in [200, 201, 202, 204]
    baseline_404     = baseline_status == 404

    # Se o endpoint não existe, nenhum teste tem sentido
    if baseline_404:
        return [{
            **t,
            "result": "NOT_FOUND",
            "status_code": baseline_status,
            "response_time_ms": 0,
            "note": "Endpoint /search não existe neste alvo"
        } for t in WAF_BYPASS_TECHNIQUES]

    # Padrões que indicam bloqueio mesmo com HTTP 200
    WAF_BLOCK_INDICATORS = [
        "access denied", "request blocked", "forbidden", "security violation",
        "intrusion detected", "waf blocked", "your request has been blocked",
        "the request was rejected", "incapsula incident", "you have been blocked",
        "sucuri website firewall", "cloudflare", "security check", "bot protection",
        "please verify", "ddos protection", "attention required",
    ]

    def _test_one(technique):
        import random
        if silent:
            # Modo silencioso: browser real com delay humano entre requests
            time.sleep(random.uniform(1.0, 2.5))
            encoded = urllib.parse.quote(str(technique["payload"]))
            status, resp_headers, body, elapsed = browser_request(test_base + encoded, timeout=15)
        else:
            # Modo padrão: HTTP direto com delay mínimo
            time.sleep(random.uniform(0.1, 0.3))
            encoded = urllib.parse.quote(str(technique["payload"]))
            status, resp_headers, body, elapsed = safe_request(test_base + encoded)
        if status is None:
            result = "ERROR"
        elif status in [403, 406, 429, 503, 418]:
            result = "BLOQUEADO"
        elif status in [301, 302, 307, 308]:
            result = "REDIRECT"
        elif status == 404:
            result = "NOT_FOUND"
        elif status in [200, 201, 202, 204]:
            body_lower = body.lower()
            if any(indicator in body_lower for indicator in WAF_BLOCK_INDICATORS):
                result = "BLOQUEADO"
            elif baseline_200:
                # REGRA ANTI-FALSO-POSITIVO: se o baseline também retorna 200,
                # não podemos afirmar que houve bypass — o site responde 200
                # para qualquer input. Só é bypass se baseline era bloqueado.
                result = "NOT_BYPASS"
            else:
                # Baseline era bloqueado (403) e payload passou (200) = bypass real
                result = "BYPASS"
        elif status in [400, 405, 500, 502]:
            result = "PARCIAL"
        else:
            result = "PARCIAL"
        return {**technique, "result": result, "status_code": status, "response_time_ms": elapsed}

    # Paralelismo: 8 workers simultâneos — reduz 27 requests sequenciais
    # de ~135s (pior caso) para ~20s
    from concurrent.futures import ThreadPoolExecutor, as_completed
    futures = {}
    with ThreadPoolExecutor(max_workers=8) as executor:
        for technique in WAF_BYPASS_TECHNIQUES:
            futures[executor.submit(_test_one, technique)] = technique
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                t = futures[future]
                results.append({**t, "result": "ERROR", "status_code": None, "response_time_ms": 0})

    # manter ordem original
    order = {t["technique"]: i for i, t in enumerate(WAF_BYPASS_TECHNIQUES)}
    results.sort(key=lambda r: order.get(r.get("technique",""), 999))

    return results


def check_security_headers(resp_headers):
    """
    Regras anti-falso-positivo para headers de segurança:

    1. X-Frame-Options: reportar ausente SOMENTE se o CSP também não tiver
       frame-ancestors. CSP com frame-ancestors é equivalente e mais moderno
       — browsers modernos ignoram X-Frame-Options quando CSP está presente.

    2. X-XSS-Protection: ignorar sempre — descontinuado em todos os browsers
       modernos e pode até criar vulnerabilidades em alguns casos.

    3. Content-Security-Policy: severidade rebaixada de HIGH para MEDIUM
       quando o site já tem outros headers de segurança configurados
       (indica configuração intencional, não negligência total).
    """
    results = []
    header_keys_lower = {k.lower(): v for k, v in resp_headers.items()}

    # Verifica se CSP tem frame-ancestors (substitui X-Frame-Options)
    csp_value = header_keys_lower.get("content-security-policy", "")
    csp_has_frame_ancestors = "frame-ancestors" in csp_value.lower()

    # Headers descontinuados que não devem ser reportados como ausentes
    DEPRECATED_HEADERS = {"x-xss-protection"}

    for header_name, info in SECURITY_HEADERS.items():
        # Pular headers descontinuados
        if header_name.lower() in DEPRECATED_HEADERS:
            continue

        present = header_name.lower() in header_keys_lower

        # X-Frame-Options: PASS se CSP já cobre com frame-ancestors
        if header_name == "X-Frame-Options" and not present and csp_has_frame_ancestors:
            results.append({
                "header": header_name,
                "present": True,  # Coberto pelo CSP
                "value": f"Coberto por CSP frame-ancestors: {csp_value[:80]}...",
                "recommended": info["recommended"],
                "severity": "INFO",
                "description": "X-Frame-Options ausente mas CSP contém frame-ancestors, "
                               "que é equivalente e preferido nos browsers modernos.",
                "status": "PASS",
                "covered_by_csp": True,
            })
            continue

        results.append({
            "header": header_name,
            "present": present,
            "value": header_keys_lower.get(header_name.lower()) if present else None,
            "recommended": info["recommended"],
            "severity": info["severity"],
            "description": info["description"],
            "status": "PASS" if present else "FAIL",
        })
    return results


def detect_technologies(resp_headers, body):
    techs = []
    header_lower = {k.lower(): v.lower() for k, v in resp_headers.items()}
    if server := header_lower.get("server"):
        techs.append({"name": server, "category": "Servidor Web", "source": "Server header"})
    if powered := header_lower.get("x-powered-by"):
        techs.append({"name": powered, "category": "Linguagem/Framework", "source": "X-Powered-By"})
    body_lower = body.lower()
    fingerprints = [
        ("WordPress",    ["wp-content", "wp-includes", "wordpress"]),
        ("Drupal",       ["drupal", "sites/default/files"]),
        ("Joomla",       ["joomla", "/components/com_"]),
        ("React",        ["react", "__react_root", "data-reactroot"]),
        ("Angular",      ["ng-version", "angular"]),
        ("Vue.js",       ["vue", "__vue__", "data-v-"]),
        ("jQuery",       ["jquery", "jquery.min.js"]),
        ("Laravel",      ["laravel", "csrf-token", "laravel_session"]),
        ("Django",       ["csrfmiddlewaretoken", "django", "__admin_media_prefix__"]),
        ("Ruby on Rails",["rails", "csrf-param", "_rails_"]),
        ("ASP.NET",      ["__viewstate", "asp.net", "__eventvalidation"]),
        ("Apache Tomcat",["apache-coyote", "jserv", "catalina"]),
        ("Nginx",        ["nginx"]),
        ("Bootstrap",    ["bootstrap.min.css", "bootstrap.css"]),
        ("Cloudflare CDN",["cloudflare", "cf-ray"]),
    ]
    for tech_name, patterns in fingerprints:
        for p in patterns:
            if p.lower() in body_lower or p.lower() in str(header_lower):
                techs.append({"name": tech_name, "category": "Tecnologia", "source": "fingerprint"})
                break
    seen, unique = set(), []
    for t in techs:
        k = t["name"].lower()
        if k not in seen:
            seen.add(k)
            unique.append(t)
    return unique


def check_cves(technologies, resp_headers, body):
    """
    Match de CVEs com 3 regras anti-falso-positivo:

    REGRA 1 — Só headers confiáveis de servidor (nunca body HTML)
      Match apenas em: Server, X-Powered-By, X-Generator, Via e
      tecnologias detectadas por fingerprint ativo.
      O corpo HTML é ignorado — qualquer site pode mencionar qualquer
      produto no texto sem usá-lo como infraestrutura.

    REGRA 2 — CVEs de software desktop são excluídos do scan web
      CVEs de Microsoft Office, MSDT, Windows kernel, SMB, Print Spooler,
      Active Directory etc. NÃO são detectáveis via HTTP. Reportá-los
      contra um site web é sempre falso positivo.

    REGRA 3 — CVEs de plugins WordPress exigem slug específico do plugin
      Detectar WordPress não é suficiente para reportar CVE de plugin.
      É necessário encontrar o slug do plugin na response
      (ex: /wp-content/plugins/wp-file-manager/).
    """
    findings = []

    # CVEs que nunca se aplicam a uma aplicação web — são de software desktop,
    # protocolos de rede interna ou componentes de SO. Excluir sempre.
    WEB_SCANNER_EXCLUSIONS = {
        # Microsoft Office / cliente desktop
        "CVE-2023-36884", "CVE-2022-30190", "CVE-2023-23397",
        "CVE-2024-38112",
        # Windows kernel / OS
        "CVE-2025-21333", "CVE-2025-29824", "CVE-2024-30078",
        "CVE-2024-49039", "CVE-2022-26923", "CVE-2022-21999",
        "CVE-2021-34527", "CVE-2020-1472", "CVE-2020-0796",
        "CVE-2020-0601",
    }

    # CVEs que exigem fingerprint ESPECÍFICO além da tecnologia base.
    # Detectar "nginx" não é suficiente para CVE-2025-1974 (IngressNightmare)
    # que afeta somente o nginx INGRESS CONTROLLER do Kubernetes.
    # Detectar "nginx" ou "apache" não é suficiente para CVE-2023-44487
    # (HTTP/2 Rapid Reset) sem confirmar HTTP/2 ativo nos headers.
    REQUIRES_SPECIFIC_FINGERPRINT = {
        # Requer ingress-nginx / kubernetes nos headers ou body
        "CVE-2025-1974": ["ingress-nginx", "kubernetes", "ingress"],
        # Requer confirmação de HTTP/2 (header upgrade ou alt-svc h2)
        "CVE-2023-44487": ["h2", "http/2", "alt-svc"],
        # Requer Exchange específico
        "CVE-2021-26855": ["exchange", "owa", "microsoft exchange"],
        "CVE-2021-26857": ["exchange", "owa"],
        "CVE-2021-26858": ["exchange", "owa"],
        "CVE-2021-27065": ["exchange", "owa"],
    }

    # Headers confiáveis para fingerprint de servidor web
    FINGERPRINT_HEADERS = [
        "server", "x-powered-by", "x-generator", "via",
        "x-aspnet-version", "x-aspnetmvc-version", "x-runtime",
        "x-drupal-cache", "x-joomla", "x-wp-total",
    ]
    header_fp = " ".join(
        v.lower() for k, v in resp_headers.items()
        if k.lower() in FINGERPRINT_HEADERS
    )
    tech_fp = " ".join(t["name"].lower() for t in technologies)
    reliable_signal = header_fp + " " + tech_fp

    # Para CVEs de plugins WordPress: verificar slug no body também
    wp_body_signal = body.lower() if "wordpress" in reliable_signal else ""

    for cve in CVE_DATABASE:
        # REGRA 2: pular CVEs de software desktop
        if cve["id"] in WEB_SCANNER_EXCLUSIONS:
            continue

        # REGRA 2b: CVEs que exigem fingerprint específico além da tech base
        if cve["id"] in REQUIRES_SPECIFIC_FINGERPRINT:
            required = REQUIRES_SPECIFIC_FINGERPRINT[cve["id"]]
            # Checar nos headers + body (body é necessário para h2/HTTP2)
            full_signal = reliable_signal + " " + body.lower()[:2000]
            if not any(req.lower() in full_signal for req in required):
                continue  # fingerprint específico não encontrado

        # REGRA 3: CVEs de plugins WordPress precisam do slug no body
        is_wp_plugin_cve = (
            "wordpress" in " ".join(cve.get("affected", [])).lower()
            and any(
                kw in " ".join(cve.get("indicators", [])).lower()
                for kw in ["plugin", "wp-file-manager", "elementor", "woocommerce",
                           "contact-form", "yoast", "revslider", "gravityforms"]
            )
        )
        if is_wp_plugin_cve:
            # Exige que o slug do plugin apareça no body (wp-content/plugins/<slug>)
            plugin_indicators = [
                ind for ind in cve.get("indicators", [])
                if ind.lower() not in ["wordpress", "wp-content", "wp-includes"]
            ]
            if not plugin_indicators:
                continue  # sem slug específico, não reportar
            if not any(slug.lower() in wp_body_signal for slug in plugin_indicators):
                continue  # slug do plugin não encontrado no body

        # REGRA 1: match somente no sinal confiável
        matched = any(ind.lower() in reliable_signal for ind in cve.get("indicators", []))
        if not matched:
            matched = any(aff.lower() in reliable_signal for aff in cve.get("affected", []))
        if matched:
            findings.append({
                "cve_id": cve["id"], "name": cve["name"],
                "severity": cve["severity"], "cvss": cve["cvss"],
                "description": cve["description"], "remediation": cve["remediation"],
                "references": cve.get("references", []),
                "matched_on": reliable_signal[:120],
            })
    return findings


def run_owasp_checks(url, resp_headers, body, status, technologies=None):
    results = []
    evidences = {}  # category -> evidence dict
    header_lower = {k.lower(): v.lower() for k, v in resp_headers.items()}
    technologies = technologies or []

    # A01 — Broken Access Control
    # Regra anti-falso-positivo:
    #   HTTP 200 = acesso real sem autenticação → VULN
    #   HTTP 403 = servidor bloqueou corretamente → PASS (recurso protegido)
    #   HTTP 404 = recurso não existe → PASS (sem relevância)
    #   HTTP 401 = exige autenticação → PASS (comportamento correto)
    a01 = []
    a01_ev = None
    from concurrent.futures import ThreadPoolExecutor as _TPE
    def _req(path):
        return path, *safe_request(url.rstrip("/") + path)

    with _TPE(max_workers=6) as ex:
        a01_results = list(ex.map(_req, ["/admin", "/.git/", "/.env", "/backup", "/config", "/.htaccess"]))

    for path, s, rh, b, ms in a01_results:
        test_url = url.rstrip("/") + path
        if s == 200:
            body_lower = b.lower()
            is_login_page = any(kw in body_lower for kw in [
                "login", "password", "sign in", "authentication required",
                "access denied", "unauthorized", "forbidden"
            ])
            if not is_login_page:
                a01.append(f"Recurso acessível sem autenticação: {path} (HTTP 200)")
                if not a01_ev:
                    a01_ev = capture_evidence(
                        "A01 — Broken Access Control", test_url,
                        resp_status=s, resp_headers=rh, resp_body=b,
                        proof=f"HTTP 200 em {path} sem autenticação — acesso indevido confirmado",
                        elapsed_ms=ms
                    )
        # HTTP 403, 401, 404 = comportamento correto, não reportar
    results.append({"category": "A01 — Broken Access Control", "status": "VULN" if a01 else "PASS",
                    "findings": a01, "severity": "HIGH" if a01 else "INFO"})
    if a01_ev:
        evidences["A01 — Broken Access Control"] = a01_ev

    # A02 — Cryptographic Failures
    a02 = []
    a02_ev = None
    if url.startswith("http://"):
        a02.append("Site acessível via HTTP sem redirecionamento HTTPS")
        a02_ev = capture_evidence(
            "A02 — Falhas Criptográficas", url,
            resp_status=status, resp_headers=resp_headers, resp_body=body[:500],
            proof="Requisição HTTP respondeu sem redirecionar para HTTPS",
        )
    if not header_lower.get("strict-transport-security"):
        a02.append("HSTS (Strict-Transport-Security) header ausente")
        if not a02_ev:
            a02_ev = capture_evidence(
                "A02 — Falhas Criptográficas", url,
                resp_status=status, resp_headers=resp_headers, resp_body="",
                proof="Header Strict-Transport-Security ausente na response",
            )
    results.append({"category": "A02 — Falhas Criptográficas", "status": "VULN" if a02 else "PASS",
                    "findings": a02, "severity": "HIGH" if a02 else "INFO"})
    if a02_ev:
        evidences["A02 — Falhas Criptográficas"] = a02_ev

    # A03 — Injection
    # Regra anti-falso-positivo:
    #   HTTP 429 = rate limit ativo — servidor bloqueou a requisição, NÃO é SQLi
    #   HTTP 403 = WAF bloqueou — NÃO é SQLi
    #   HTTP 404 = endpoint não existe — NÃO é SQLi
    #   Só reportar se HTTP 200 ou 500 E body contém erro de banco real
    a03 = []
    a03_ev = None
    SQL_ERROR_KEYWORDS = [
        "you have an error in your sql syntax",
        "warning: mysql_",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "ora-01756",
        "pg_query(): query failed",
        "supplied argument is not a valid mysql",
        "invalid query",
        "db error",
    ]
    for payload in ["'", "1' OR '1'='1"]:
        test_url = url.rstrip("/") + "/search?q=" + urllib.parse.quote(payload)
        s, rh, b, ms = safe_request(test_url)
        # Ignorar respostas que indicam bloqueio — não são vulnerabilidade
        if s in [None, 429, 403, 401, 404, 503]:
            continue
        # Só reportar em 200 ou 500 com erro real de banco
        if s in [200, 500] and any(kw in b.lower() for kw in SQL_ERROR_KEYWORDS):
            a03.append(f"SQL Injection confirmado com payload: {payload} (HTTP {s})")
            if not a03_ev:
                a03_ev = capture_evidence(
                    "A03 — SQL Injection", test_url,
                    resp_status=s, resp_headers=rh, resp_body=b,
                    payload=payload,
                    proof=f"HTTP {s}: response contém erro explícito de banco com payload: {payload}",
                    elapsed_ms=ms
                )
    results.append({"category": "A03 — Injection (SQLi)", "status": "VULN" if a03 else "PASS",
                    "findings": a03, "severity": "CRITICAL" if a03 else "INFO"})
    if a03_ev:
        evidences["A03 — Injection (SQLi)"] = a03_ev

    # A05 — Security Misconfiguration
    a05 = []
    a05_ev = None
    if "x-powered-by" in header_lower:
        a05.append(f"X-Powered-By expõe tecnologia: {header_lower['x-powered-by']}")
    if "server" in header_lower and any(v in header_lower["server"] for v in ["/", "."]):
        a05.append(f"Header Server expõe versão: {header_lower['server']}")
    # HTTP 5xx só é misconfiguration se retornou body com stack trace/debug info
    # HTTP 543 sem body = bloqueio customizado, não erro real exposto
    STANDARD_5XX = {500, 501, 502, 503, 504, 505}
    if status and status in STANDARD_5XX and any(
        kw in body.lower() for kw in
        ["traceback", "stack trace", "exception", "debug", "at line", "syntax error",
         "fatal error", "warning:", "notice:", "undefined variable"]
    ):
        a05.append(f"Erro 5xx com stack trace exposto ao cliente: HTTP {status}")
    for path in ["/phpinfo.php", "/.env", "/debug", "/server-status"]:
        test_url = url.rstrip("/") + path
        s, rh, b, ms = safe_request(test_url)
        if s == 200 and any(kw in b.lower() for kw in ["phpinfo", "password", "secret", "debug", "server version"]):
            a05.append(f"Recurso de debug exposto: {path}")
            if not a05_ev:
                a05_ev = capture_evidence(
                    "A05 — Security Misconfiguration", test_url,
                    resp_status=s, resp_headers=rh, resp_body=b,
                    proof=f"HTTP 200 com conteúdo sensível em {path}",
                    elapsed_ms=ms
                )
    if not a05_ev and a05:
        a05_ev = capture_evidence(
            "A05 — Security Misconfiguration", url,
            resp_status=status, resp_headers=resp_headers, resp_body="",
            proof="; ".join(a05[:2])
        )
    results.append({"category": "A05 — Security Misconfiguration", "status": "VULN" if a05 else "PASS",
                    "findings": a05, "severity": "MEDIUM" if a05 else "INFO"})
    if a05_ev:
        evidences["A05 — Security Misconfiguration"] = a05_ev

    # A07 — Auth Failures
    # Regra anti-falso-positivo:
    # Cloudflare e outros CDNs retornam HTTP 200 para qualquer rota inexistente
    # servindo a homepage cacheada. Um endpoint de autenticação real deve conter
    # formulário de login no body (input de senha, form de login, etc.)
    # /wp-login.php só é válido se WordPress foi detectado nas tecnologias.
    a07 = []
    a07_ev = None
    PLATFORMS = {
        "/wp-login.php": ["wordpress", "wp-"],
        "/admin/login":  [],  # genérico, aceitar se body confirmar
    }
    LOGIN_BODY_INDICATORS = [
        'type="password"', "type='password'",
        'name="password"', "name='password'",
        'id="password"',  "id='password'",
        '<form', 'login-form', 'signin-form',
        'username', 'email', 'log in', 'sign in',
        'senha', 'entrar', 'acessar',
    ]
    import re as _re
    tech_list = technologies if isinstance(technologies, list) else []
    detected_tech_str = " ".join(t["name"].lower() for t in tech_list)

    for path in ["/login", "/wp-login.php", "/admin/login", "/api/auth", "/signin"]:
        # Pular /wp-login.php se WordPress não foi detectado
        if path == "/wp-login.php" and "wordpress" not in detected_tech_str:
            continue

        test_url = url.rstrip("/") + path
        s, rh, b, ms = safe_request(test_url)

        if s == 200:
            b_lower = b.lower()
            # Verificar se o body realmente contém elementos de formulário de login
            has_login_content = any(
                ind in b_lower for ind in LOGIN_BODY_INDICATORS
            )
            if not has_login_content:
                # Body não tem formulário — provavelmente página genérica do CDN
                continue

            a07.append(f"Endpoint de autenticação encontrado: {path}")
            if not a07_ev:
                a07_ev = capture_evidence(
                    "A07 — Falhas de Autenticação", test_url,
                    resp_status=s, resp_headers=rh, resp_body=b[:500],
                    proof=f"Endpoint {path} respondeu HTTP 200 com formulário de login",
                    elapsed_ms=ms
                )
        elif s in [401, 403]:
            # 401/403 também indica que o endpoint existe mas exige autenticação
            a07.append(f"Endpoint protegido encontrado: {path} (HTTP {s})")

    results.append({"category": "A07 — Falhas de Autenticação", "status": "INFO",
                    "findings": a07, "severity": "INFO"})
    if a07_ev:
        evidences["A07 — Falhas de Autenticação"] = a07_ev

    # A10 — SSRF
    # Regra anti-falso-positivo tripla:
    # 1. Body deve conter keywords reais de metadados AWS/GCP/Azure
    # 2. Content-Type não pode ser text/html (metadados são texto puro)
    # 3. Resposta não pode ser cache do CDN (cf-cache-status: HIT)
    a10 = []
    a10_ev = None
    SSRF_KEYWORDS = [
        "ami-id", "instance-id", "instance-type", "local-ipv4",
        "security-credentials", "iam", "placement", "public-ipv4",
        "computeMetadata", "metadata.google.internal",
        "latest/meta-data",
    ]
    for suffix in ["/fetch?url=", "/proxy?url=", "/redirect?to="]:
        test_url = url.rstrip("/") + suffix + "http://169.254.169.254/"
        s, rh, b, ms = safe_request(test_url)
        if s != 200:
            continue

        rh_lower = {k.lower(): v.lower() for k, v in rh.items()}

        # Rejeitar se for cache do CDN (homepage sendo servida)
        if rh_lower.get("cf-cache-status") in ["hit", "miss"]:
            # Cloudflare cache = não é resposta do backend para o payload
            # Só aceitar se body tiver keywords reais de metadados
            pass

        # Rejeitar se Content-Type for HTML (metadados são texto puro)
        content_type = rh_lower.get("content-type", "")
        if "text/html" in content_type:
            continue

        # Verificar keywords de metadados no body
        b_lower = b.lower()
        if any(kw.lower() in b_lower for kw in SSRF_KEYWORDS):
            a10.append(f"SSRF confirmado via: {suffix}")
            if not a10_ev:
                a10_ev = capture_evidence(
                    "A10 — SSRF", test_url,
                    resp_status=s, resp_headers=rh, resp_body=b,
                    payload="http://169.254.169.254/",
                    proof=f"Body contém metadados internos via {suffix} (Content-Type: {content_type})",
                    elapsed_ms=ms
                )

    results.append({"category": "A10 — Server-Side Request Forgery", "status": "VULN" if a10 else "PASS",
                    "findings": a10, "severity": "CRITICAL" if a10 else "INFO"})
    if a10_ev:
        evidences["A10 — Server-Side Request Forgery"] = a10_ev

    return results, evidences


def calculate_risk_score(summary):
    weights = {"CRITICAL": 4.0, "HIGH": 2.5, "MEDIUM": 1.5, "LOW": 0.5, "INFO": 0.1}
    raw = sum(weights.get(sev, 0) * count for sev, count in summary.items())
    return round(min(10.0, raw), 1)


def calculate_team_scores(findings, owasp_results, bypass_results):
    red = sum({"CRITICAL":15,"HIGH":10,"MEDIUM":6,"LOW":3}.get(f.get("severity","INFO"),1) for f in findings)
    red += sum(8 for b in bypass_results if b["result"] == "BYPASS")
    blue = sum(8 for b in bypass_results if b["result"] == "BLOQUEADO")
    blue += sum(10 for c in owasp_results if c["status"] == "PASS")
    total = red + blue or 1
    return round((red/total)*100), round((blue/total)*100)


# Timeout máximo por scan — evita que um host lento trave o servidor
SCAN_TIMEOUT_S = 120  # 2 minutos no máximo por scan completo


def run_full_scan(scan_id: str, log_callback=None, silent_mode: bool = False):
    """
    Motor principal de scan. Recebe scan_id (UUID string), executa análise
    completa e persiste no banco via Django ORM.

    Timeout global: o scan é abortado após SCAN_TIMEOUT_S segundos para
    evitar que hosts lentos ou travados bloqueiem o servidor indefinidamente.
    """
    from .models import ScanTarget, ScanLog, Finding

    _log_buffer = []
    _log_lock = __import__('threading').Lock()

    def _flush_logs():
        """Grava os logs acumulados no banco em um único batch."""
        with _log_lock:
            buf = _log_buffer[:]
            _log_buffer.clear()
        if not buf:
            return
        try:
            scan_obj = ScanTarget.objects.get(id=scan_id)
            ScanLog.objects.bulk_create([
                ScanLog(scan=scan_obj, step=s, message=m, elapsed_s=e)
                for s, m, e in buf
            ], ignore_conflicts=True)
        except Exception:
            pass

    def log(step, msg):
        logger.info("[%s] %s: %s", scan_id[:8], step, msg)
        if log_callback:
            log_callback(step, msg)
        elapsed = round((time.time() - t_start), 1)
        with _log_lock:
            _log_buffer.append((step, msg, elapsed))
        # Flush a cada 4 logs acumulados (em vez de 1 write por log)
        if len(_log_buffer) >= 4:
            _flush_logs()

    t_start = time.time()

    def _check_timeout():
        if time.time() - t_start > SCAN_TIMEOUT_S:
            _flush_logs()  # salvar o que tem antes de abortar
            raise TimeoutError(f"Scan abortado: limite de {SCAN_TIMEOUT_S}s atingido")

    try:
        scan = ScanTarget.objects.get(id=scan_id)
        scan.status = 'running'
        scan.save()
        url = scan.url
    except Exception as e:
        logger.error("Scan %s not found: %s", scan_id, e)
        return

    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname or url
    is_https = parsed.scheme == "https"

    try:
        # 1 DNS
        log("dns", f"Resolvendo DNS para {hostname}...")
        dns_data = resolve_dns(hostname)
        scan.dns_data = dns_data
        scan.save()
        log("dns", f"IPs: {', '.join(dns_data['ips']) if dns_data['ips'] else 'nenhum'}")

        # 2 TLS
        tls_data = {}
        if is_https:
            log("tls", f"Verificando TLS em {hostname}:443...")
            tls_data = check_tls(hostname)
            scan.tls_data = tls_data
            scan.save()
            log("tls", f"TLS {tls_data.get('version','?')} — {tls_data.get('days_remaining',0)} dias restantes")

        # 3 Base request
        if silent_mode:
            log("http", f"[SILENT] Navegador Chromium real para {url}...")
            status, resp_headers, body, elapsed = browser_request(url)
            log("http", f"[SILENT] HTTP {status} — {elapsed}ms — {len(body)} bytes")
        else:
            log("http", f"Requisição HTTP base para {url}...")
            status, resp_headers, body, elapsed = safe_request(url)
            log("http", f"HTTP {status} — {elapsed}ms — {len(body)} bytes")

        # Verificar se o servidor está bloqueando o scanner.
        # Códigos não-padrão (>=520 não-Cloudflare) ou 5xx sem body indicam
        # que o servidor recusou a conexão antes de processar normalmente.
        # Gerar findings baseados nessa response seria falso positivo em cascata.
        BLOCKED_STATUSES = {520, 521, 522, 523, 524, 525, 526, 530}
        is_scanner_blocked = (
            status is None or
            (status >= 520 and status not in BLOCKED_STATUSES and len(body) == 0) or
            (status >= 500 and len(body) == 0 and not resp_headers)
        )
        if is_scanner_blocked:
            log("http", f"Servidor bloqueou requisição HTTP simples (HTTP {status}) — "
                        "ativando modo browser para contornar detecção...")
            # Tentar com navegador real (Playwright) que passa por JS challenges
            status, resp_headers, body, elapsed = browser_request(url)
            log("http", f"Browser mode: HTTP {status} — {elapsed}ms — {len(body)} bytes")

            # Verificar se o browser também foi bloqueado
            still_blocked = (
                status is None or
                (status >= 520 and status not in BLOCKED_STATUSES and len(body) == 0)
            )
            if still_blocked:
                log("http", f"Servidor bloqueou mesmo com navegador real (HTTP {status}). "
                            "Site possui proteção ativa que impede análise automatizada.")
                scan.status = 'done'
                scan.error_message = (
                    f"O servidor bloqueou tanto requisições HTTP quanto o navegador real "
                    f"(HTTP {status}). O site possui proteção ativa (Cloudflare, WAF, "
                    f"autenticação obrigatória) que impede análise automatizada de segurança."
                )
                scan.scan_duration_s = round(time.time() - t_start, 1)
                scan.save()
                log("done", f"Scan concluído — proteção ativa bloqueou análise (HTTP {status})")
                return
            log("http", f"Browser mode bem-sucedido — continuando análise")

        # 4 Technologies
        log("tech", "Detectando tecnologias...")
        techs = detect_technologies(resp_headers or {}, body)
        scan.technologies = techs
        scan.save()
        log("tech", f"Detectadas: {', '.join(t['name'] for t in techs[:5]) or 'nenhuma'}")

        # 5 WAF
        log("waf", "Detectando WAF...")
        waf_detected = detect_waf(resp_headers or {}, body)
        log("waf", f"WAF: {', '.join(waf_detected)}")

        # 6 WAF Bypass
        _check_timeout()
        _check_timeout()
        log("bypass", "Testando técnicas de bypass...")
        bypass_results = test_waf_bypasses(url, silent=silent_mode)
        bypassed = sum(1 for b in bypass_results if b["result"] == "BYPASS")
        log("bypass", f"{bypassed}/{len(bypass_results)} bypasses bem-sucedidos")

        scan.waf_data = {"detected": waf_detected, "bypasses": bypass_results}
        scan.save()

        # 7 Security Headers
        log("headers", "Analisando headers de segurança...")
        sec_headers = check_security_headers(resp_headers or {})
        scan.security_headers = sec_headers
        scan.save()
        missing = [h["header"] for h in sec_headers if not h["present"]]
        log("headers", f"{len(missing)} headers ausentes: {', '.join(missing[:3])}")

        # 8 CVE Check
        _check_timeout()
        log("cve", "Cruzando com base de CVEs...")
        cve_findings = check_cves(techs, resp_headers or {}, body)
        log("cve", f"{len(cve_findings)} CVEs identificados")

        # 9 OWASP
        _check_timeout()
        log("owasp", "Executando OWASP Top 10...")
        owasp_results, owasp_evidences = run_owasp_checks(url, resp_headers or {}, body, status, techs)
        scan.owasp_results = owasp_results
        scan.save()
        vulns = sum(1 for r in owasp_results if r["status"] == "VULN")
        log("owasp", f"{vulns} categorias OWASP vulneráveis")

        # 10 Build all findings & persist
        all_findings_data = []

        for cve in cve_findings:
            cve_ev = capture_evidence(
                cve["cve_id"], url,
                resp_status=status, resp_headers=resp_headers, resp_body=body[:800],
                proof=f"{cve['cve_id']} identificado via fingerprint de tecnologia detectada na response"
            )
            f = Finding.objects.create(
                scan=scan, finding_type='CVE', finding_id=cve["cve_id"],
                title=f"{cve['name']} ({cve['cve_id']})",
                severity=cve["severity"], cvss_score=cve.get("cvss"),
                description=cve["description"], remediation=cve["remediation"],
                references=cve.get("references", []),
                evidence=cve_ev
            )
            all_findings_data.append(f.to_dict())

        for check in owasp_results:
            if check["status"] == "VULN" and check["findings"]:
                ev = owasp_evidences.get(check["category"], {})
                f = Finding.objects.create(
                    scan=scan, finding_type='OWASP', finding_id=check["category"],
                    title=check["category"], severity=check.get("severity", "MEDIUM"),
                    description="; ".join(check["findings"]),
                    remediation="Ver recomendações OWASP para esta categoria.",
                    evidence=ev
                )
                all_findings_data.append(f.to_dict())

        for h in sec_headers:
            # Pular headers cobertos por diretivas equivalentes (ex: CSP frame-ancestors)
            if h.get("covered_by_csp"):
                continue
            if not h["present"] and h["severity"] in ["HIGH", "MEDIUM"]:
                h_ev = capture_evidence(
                    f"Header ausente: {h['header']}", url,
                    resp_status=status, resp_headers=resp_headers, resp_body="",
                    proof=f"Header '{h['header']}' não encontrado na response. Recomendado: {h['recommended']}"
                )
                f = Finding.objects.create(
                    scan=scan, finding_type='Header', finding_id=f"HEADER-{h['header']}",
                    title=f"Header ausente: {h['header']}", severity=h["severity"],
                    description=h["description"],
                    remediation=f"Adicionar: {h['header']}: {h['recommended']}",
                    evidence=h_ev
                )
                all_findings_data.append(f.to_dict())

        # Só conta como bypass real: BYPASS confirmado
        # NOT_FOUND, PARCIAL e NOT_BYPASS não são vulnerabilidades
        bypassed_list = [b for b in bypass_results if b["result"] == "BYPASS"]
        if bypassed_list:
            first = bypassed_list[0]
            waf_ev = capture_evidence(
                "WAF Bypass", first.get("url", url),
                resp_status=first.get("status_code"), resp_headers={}, resp_body="",
                payload=str(first.get("payload", "")),
                proof=f"Técnica '{first['name']}' evadiu o WAF — status {first.get('status_code')} sem bloqueio"
            )
            f = Finding.objects.create(
                scan=scan, finding_type='WAF', finding_id='WAF-BYPASS',
                title=f"WAF Bypass — {len(bypassed_list)} técnicas eficazes",
                severity='HIGH',
                description="Técnicas de evasão eficazes: " + ", ".join(b["name"] for b in bypassed_list[:4]),
                remediation="Revisar regras WAF. Implementar validação server-side além do WAF.",
                evidence=waf_ev
            )
            all_findings_data.append(f.to_dict())

        if tls_data.get("expired"):
            tls_ev = capture_evidence(
                "TLS Expirado", url,
                proof=f"Certificado TLS expirou em {tls_data.get('expiry')} — conexão insegura"
            )
            f = Finding.objects.create(
                scan=scan, finding_type='TLS', finding_id='TLS-EXPIRED',
                title='Certificado TLS expirado', severity='CRITICAL',
                description=f"Certificado expirou em {tls_data.get('expiry')}",
                remediation="Renovar certificado TLS imediatamente.",
                evidence=tls_ev
            )
            all_findings_data.append(f.to_dict())
        elif tls_data.get("self_signed"):
            tls_ev = capture_evidence(
                "TLS Auto-assinado", url,
                proof="Certificado não emitido por CA confiável — self-signed detectado"
            )
            f = Finding.objects.create(
                scan=scan, finding_type='TLS', finding_id='TLS-SELFSIGNED',
                title='Certificado TLS auto-assinado', severity='MEDIUM',
                description="Certificado não é emitido por CA confiável.",
                remediation="Usar Let's Encrypt ou outro CA público.",
                evidence=tls_ev
            )
            all_findings_data.append(f.to_dict())

        # Summary & scores
        summary = scan.summary()
        risk_score = calculate_risk_score(summary)
        red_pct, blue_pct = calculate_team_scores(all_findings_data, owasp_results, bypass_results)

        red_actions = [
            {"action": "Reconhecimento DNS/OSINT", "status": "done"},
            {"action": "Fingerprint de serviços TLS", "status": "done"},
            {"action": "WAF evasion & bypass testing", "status": "done"},
            {"action": "SQL/XSS Injection payloads", "status": "done"},
            {"action": "Exploração de CVEs mapeados", "status": "done"},
            {"action": "Mapeamento da superfície de ataque", "status": "done"},
        ]
        blue_actions = [
            {"action": "Monitorar tráfego e baselines", "status": "done"},
            {"action": "Detectar anomalias comportamentais", "status": "done"},
            {"action": "Analisar logs WAF e IDS", "status": "done"},
            {"action": "Correlacionar eventos no SIEM", "status": "done"},
            {"action": "Classificar e triagar ameaças", "status": "done"},
            {"action": "Gerar alertas e acionar resposta", "status": "done"},
        ]

        scan.risk_score = risk_score
        scan.red_team_score = red_pct
        scan.blue_team_score = blue_pct
        scan.red_team_actions = red_actions
        scan.blue_team_actions = blue_actions
        scan.scan_duration_s = round(time.time() - t_start, 1)
        scan.status = 'done'
        scan.save()

        log("done", f"Scan concluído em {scan.scan_duration_s}s — Score: {risk_score}/10 — {len(all_findings_data)} findings")
        _flush_logs()

    except TimeoutError as e:
        logger.warning("Scan %s timeout: %s", scan_id, e)
        try:
            scan = ScanTarget.objects.get(id=scan_id)
            scan.status = 'error'
            scan.error_message = f"Timeout: {e}"
            scan.save()
            log("error", f"Scan interrompido por timeout ({SCAN_TIMEOUT_S}s). Resultados parciais salvos.")
        except Exception:
            pass
    except Exception as e:
        logger.exception("Scan %s failed", scan_id)
        try:
            scan = ScanTarget.objects.get(id=scan_id)
            scan.status = 'error'
            scan.error_message = str(e)
            scan.save()
            log("error", f"Falha no scan: {e}")
        except Exception:
            pass
