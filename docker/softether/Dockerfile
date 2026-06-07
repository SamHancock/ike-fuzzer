FROM debian:bookworm-slim

# Build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libssl-dev \
        libreadline-dev \
        zlib1g-dev \
        wget \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Download and compile SoftEther VPN Server
# The make script asks three interactive questions (license agreement);
# piping "1\n1\n1" accepts them all non-interactively.
ARG SE_VER=v4.44-9807-rtm-2025.04.16
ARG SE_ARCH=linux-x64-64bit
ARG SE_URL=https://www.softether-download.com/files/softether/${SE_VER}-tree/Linux/SoftEther_VPN_Server/64bit_-_Intel_x64_or_AMD64/softether-vpnserver-${SE_VER}-${SE_ARCH}.tar.gz

WORKDIR /opt
RUN wget -q "${SE_URL}" -O softether.tar.gz \
    && tar xzf softether.tar.gz \
    && rm softether.tar.gz \
    && cd vpnserver \
    && printf "1\n1\n1\n" | make

COPY startup.sh /opt/startup.sh
RUN chmod +x /opt/startup.sh

# IKE: 500/udp   NAT-T: 4500/udp   L2TP: 1701/udp
# SoftEther management: 443/tcp  5555/tcp
EXPOSE 500/udp 4500/udp 1701/udp 443/tcp 5555/tcp

WORKDIR /opt/vpnserver
CMD ["/opt/startup.sh"]
