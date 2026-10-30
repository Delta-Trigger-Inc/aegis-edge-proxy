FROM python:3.11-slim-bookworm@sha256:94a8fee35252d06ab75856f15f12c7bae67b10e8a6da93c7fded82b2610926cd AS dependencies
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --only-binary=:all: --target=/opt/site-packages -r /tmp/requirements.txt
FROM gcr.io/distroless/python3-debian12:nonroot@sha256:7d1042ce588ab97019fe95c24ffca7bc5a82ccdac572511d5e09bda4435c89c5
WORKDIR /app
COPY --from=dependencies /opt/site-packages /opt/site-packages
COPY proxy.py proxy_runtime.py server.py server_config.py bounded_stream.py probe.py SOURCE.json VERSION ./
COPY scripts/create_pair.py /app/create_pair.py
COPY scripts/renew_pair.py /app/renew_pair.py
USER 10001:10001
ENV PYTHONPATH=/opt/site-packages:/app PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ARG SOURCE_REVISION=unknown
LABEL org.opencontainers.image.title="AEGIS Edge Proxy" org.opencontainers.image.version="1.0.0" org.opencontainers.image.revision="${SOURCE_REVISION}" org.opencontainers.image.source="https://github.com/Delta-Trigger-Inc/aegis-edge-proxy"
HEALTHCHECK --interval=5s --timeout=2s --start-period=5s --retries=3 CMD ["/usr/bin/python3", "/app/proxy.py", "--health"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/bin/python3", "/app/proxy.py"]
CMD ["--config", "/run/aegis-proxy/config.json"]
