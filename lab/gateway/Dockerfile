FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        dnsmasq iproute2 iptables iputils-ping procps \
    && rm -rf /var/lib/apt/lists/*
COPY dnsmasq.conf /etc/dnsmasq.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
