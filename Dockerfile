FROM python:3.15-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Atualiza pacotes do SO para reduzir CVEs detectadas pelo Trivy na imagem
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
# Instala as dependências e remove pip/setuptools/wheel: não são necessários em runtime
# e reduzem a superfície de ataque (o SBOM vendorizado do pip acusava CVE no setuptools).
RUN pip install -r requirements.txt \
    && pip uninstall -y pip setuptools wheel

COPY app ./app
COPY wsgi.py .

RUN useradd --create-home --uid 10001 appuser
USER appuser

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "wsgi:app"]
