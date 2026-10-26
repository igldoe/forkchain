FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install . && useradd --create-home --uid 1000 forkchain \
    && mkdir /data && chown forkchain /data
COPY --chmod=755 docker/node-entrypoint.sh /usr/local/bin/node-entrypoint

USER forkchain
VOLUME ["/data"]
EXPOSE 8333 8332 8080
ENTRYPOINT ["forkchain"]
CMD ["--help"]
