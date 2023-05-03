FROM python:3.11-slim

ENV CERTBOT_DNS_LEXICON_PLUGIN_VERSION=1.0.11

COPY generate_certs.py /usr/local/bin/generate-certs
COPY generate_ovh_key.py /usr/local/bin/generate-ovh-key
COPY requirements.txt .

RUN pip install pip setuptools --upgrade --no-cache-dir && \
    pip install -r requirements.txt --no-cache-dir  \
    https://github.com/MaciejSzczurek/certbot-dns-lexicon/releases/download/v${CERTBOT_DNS_LEXICON_PLUGIN_VERSION}/certbot_dns_lexicon-${CERTBOT_DNS_LEXICON_PLUGIN_VERSION}-py3-none-any.whl && \
    chmod +x /usr/local/bin/generate-certs /usr/local/bin/generate-ovh-key && \
    rm -rf requirements.txt /tmp/*
