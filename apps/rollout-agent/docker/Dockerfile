# EasySystems unix rollout agent — agent role only (no standalone/master).
FROM python:3.12-slim-bookworm

ENV ESYS_ROLLOUT_AGENT=1 \
    PYTHONUNBUFFERED=1 \
    UNIX_MONITOR_DATA=/data

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openssl \
        smartmontools \
        curl \
        iputils-ping \
        dnsutils \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY unix-monitor-agent.py /app/unix-monitor.py
COPY src/ /app/src/
COPY web/ /app/web/
RUN chmod 700 /app/unix-monitor.py

RUN useradd --create-home --shell /usr/sbin/nologin monitor \
    && mkdir -p /data \
    && chown -R monitor:monitor /data /app

EXPOSE 8787
VOLUME ["/data"]

USER monitor
ENTRYPOINT ["python3", "/app/unix-monitor.py", "--ui", "--host", "0.0.0.0", "--port", "8787"]
