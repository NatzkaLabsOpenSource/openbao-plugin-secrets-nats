FROM openbao/openbao:2.4.1

ARG TARGETARCH

RUN mkdir -p /etc/openbao/plugins && mkdir -p /etc/openbao/plugins_checksums

COPY build/openbao/plugins/openbao-plugin-secrets-nats-linux-$TARGETARCH /etc/openbao/plugins/openbao-plugin-secrets-nats

RUN sha256sum /etc/openbao/plugins/openbao-plugin-secrets-nats > /etc/openbao/plugins_checksums/openbao-plugin-secrets-nats.sha256 && \
    cat /etc/openbao/plugins_checksums/*

