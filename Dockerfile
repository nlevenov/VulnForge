# VulnForge - intentionally vulnerable learning lab.
# The image is meant to be published to loopback only (see docker-compose.yml).
FROM python:3.12-slim

# Run as a non-root user; the lab needs no elevated privileges.
RUN useradd --create-home --uid 10001 forge
WORKDIR /app

COPY pyproject.toml requirements.txt ./
COPY src ./src
RUN pip install --no-cache-dir .

USER forge
EXPOSE 8000

# Bind inside the container to 0.0.0.0 so the published port works, but the
# container itself is an isolated boundary and compose maps it to 127.0.0.1 on
# the host. The explicit opt-in acknowledges the in-container bind.
ENV VULNFORGE_HOST=0.0.0.0 \
    VULNFORGE_PORT=8000 \
    VULNFORGE_ALLOW_EXPOSURE=yes-i-understand

CMD ["vulnforge"]
