FROM openbao/openbao:2.4.1

ARG TARGETARCH

RUN mkdir -p /etc/vault/vault_plugins && mkdir -p /etc/vault/vault_plugins_checksums

COPY build/vault/plugins/vault-plugin-secrets-nats-linux-$TARGETARCH /etc/vault/vault_plugins/vault-plugin-secrets-nats

RUN sha256sum /etc/vault/vault_plugins/vault-plugin-secrets-nats > /etc/vault/vault_plugins_checksums/vault-plugin-secrets-nats.sha256 && \
    cat /etc/vault/vault_plugins_checksums/*

