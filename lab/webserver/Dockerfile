FROM nginx:1.27-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssl iproute2 \
    && rm -rf /var/lib/apt/lists/*
COPY nginx-sites.conf /etc/nginx/conf.d/default.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
