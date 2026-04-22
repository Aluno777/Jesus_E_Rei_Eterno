#!/bin/bash
set -e
echo "==> Rodando migrações..."
python manage.py migrate --noinput
echo "==> Coletando estáticos..."
python manage.py collectstatic --noinput
echo "==> Iniciando servidor..."
# Gunicorn com 4 workers — resolve o congelamento da interface durante scans.
# runserver é single-threaded e bloqueia o frontend enquanto o scan roda.
# Cada worker atende requisições independentemente.
exec gunicorn redshield.wsgi:application \
  --bind 0.0.0.0:8000 \
  --workers 4 \
  --threads 2 \
  --worker-class gthread \
  --timeout 180 \
  --graceful-timeout 30 \
  --keep-alive 5 \
  --log-level info
