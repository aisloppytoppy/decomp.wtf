FROM --platform=linux/amd64 debian:trixie-slim

# Install system dependencies & 32-bit runtime for legacy game compilers
RUN apt-get update -qq && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      ca-certificates curl git xz-utils zstd unzip bzip2 file procps less nano bash python3 \
      libc6-i386 lib32stdc++6 lib32z1 locales && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set up decomp user (uid 1000) and directories
RUN useradd -m -u 1000 -s /bin/bash decomp && \
    mkdir -p /opt/decomp/toolchains /home/decomp/Decomp /home/decomp/.local/share/decompnet && \
    chown -R decomp:decomp /opt/decomp /home/decomp

USER decomp
WORKDIR /home/decomp

ENV LANG=C.UTF-8 \
    DECOMP_RUNTIME=docker \
    DECOMPNET_TOOLCHAINS=/opt/decomp/toolchains \
    PATH=/home/decomp/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Install uv directly for fast package management
RUN curl -LsSf https://astral.sh/uv/install.sh | env UV_NO_MODIFY_PATH=1 sh

# Copy repository source files
COPY --chown=decomp:decomp pyproject.toml README.md LICENSE /home/decomp/app/
COPY --chown=decomp:decomp src /home/decomp/app/src

# Install decompnet from local source and pre-install core toolchains
RUN uv tool install --python 3.12 /home/decomp/app && \
    decomp setup && \
    rm -rf /home/decomp/app

EXPOSE 6464
HEALTHCHECK --interval=30s --timeout=5s --start-period=10m CMD curl -fsS "http://127.0.0.1:${DECOMP_PORT:-6464}/health" >/dev/null || exit 1

ENTRYPOINT ["/home/decomp/.local/bin/decomp", "--no-browser"]
