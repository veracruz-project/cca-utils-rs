FROM rust:slim

RUN set -eux; \
    apt-get update; \
    apt-get install make cpio; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
CMD make
