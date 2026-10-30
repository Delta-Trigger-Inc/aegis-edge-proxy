FROM python:3.13-slim@sha256:9662417aace5ae7b8e2609cce472b72a8958e134ba372808abe9cc1a0c0125e6
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --only-binary=:all: -r requirements.txt \
    && groupadd -g 10001 aegis-proxy && useradd -u 10001 -g 10001 -M aegis-proxy
COPY proxy.py proxy_runtime.py probe.py SOURCE.json VERSION ./
COPY scripts/create_pair.py ./create_pair.py
USER 10001:10001
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "/app/proxy.py"]
CMD ["--config", "/run/aegis-proxy/config.json"]
