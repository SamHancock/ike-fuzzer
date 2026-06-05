FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        strongswan \
        strongswan-charon \
        libstrongswan-standard-plugins \
        libstrongswan-extra-plugins \
    && rm -rf /var/lib/apt/lists/*

COPY ipsec.conf      /etc/ipsec.conf
COPY ipsec.secrets   /etc/ipsec.secrets
COPY strongswan.conf /etc/strongswan.conf

# IKE/ISAKMP
EXPOSE 500/udp
# IKE NAT-T
EXPOSE 4500/udp

CMD ["ipsec", "start", "--nofork"]
