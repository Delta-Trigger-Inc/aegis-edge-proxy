FROM debian:bookworm-slim
ARG AEGIS_INBOUND_REVISION=unknown
LABEL org.opencontainers.image.title="AEGIS inbound domain receiver" \
      org.opencontainers.image.version="0.1.0-inbound.2" \
      org.opencontainers.image.revision="${AEGIS_INBOUND_REVISION}"
RUN printf 'postfix postfix/main_mailer_type string No configuration\n' | debconf-set-selections \
    && apt-get update && apt-get install -y --no-install-recommends postfix postsrsd python3 ca-certificates openssl \
    && rm -rf /var/lib/apt/lists/*
COPY inbound/runtime.py /usr/local/lib/aegis-inbound/runtime.py
VOLUME ["/var/spool/postfix", "/var/lib/postfix", "/var/lib/postsrsd"]
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=6 \
  CMD ["python3", "/usr/local/lib/aegis-inbound/runtime.py", "health"]
ENTRYPOINT ["python3", "/usr/local/lib/aegis-inbound/runtime.py"]
CMD ["run"]
