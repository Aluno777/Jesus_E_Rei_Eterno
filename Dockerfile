FROM mcr.microsoft.com/playwright/python:v1.44.0-jammy

LABEL maintainer="RedShield PTaaS" \
      description="Pentest as a Service — Django" \
      version="2.5.0"

# Imagem base já vem com Playwright + Chromium + todas as dependências instaladas.
# Desenvolvida pela Microsoft, compatível com Docker Desktop no Windows 11.

WORKDIR /app

# Instalar dependências Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código
COPY . .

# Criar usuário e estrutura de diretórios
RUN groupadd -r redshield && useradd -r -g redshield redshield \
    && mkdir -p db media/reports staticfiles \
    && chown -R redshield:redshield /app

USER redshield

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8000/health/ || exit 1

ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]
