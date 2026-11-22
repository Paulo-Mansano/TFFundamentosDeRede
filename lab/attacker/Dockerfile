FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 tcpdump iproute2 iputils-ping procps \
    && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
