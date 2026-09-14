# KEV-Pulse -- runs at the customer site.
#
#   docker build -t kev-pulse -f docker/Dockerfile .
#
#   # stdio (local, invoked directly by an MCP client):
#   docker run -i --rm --env-file .env -v $(pwd)/config.yaml:/app/config.yaml \
#     -v kev_pulse_state:/app/state kev-pulse serve
#
#   # streamable-http (remote, multi-agent orchestration):
#   docker run --rm -p 8000:8000 --env-file .env -v $(pwd)/config.yaml:/app/config.yaml \
#     -v kev_pulse_state:/app/state kev-pulse serve --transport streamable-http
#
#   # autonomous polling loop, no MCP transport:
#   docker run -d --env-file .env -v $(pwd)/config.yaml:/app/config.yaml \
#     -v kev_pulse_state:/app/state kev-pulse watch

FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir .

VOLUME ["/app/state"]
# Point state_db_path in your config.yaml at /app/state/kev_pulse.db
# so the audit log and feed cursors survive a container restart.

ENTRYPOINT ["kev-pulse", "--config", "/app/config.yaml"]
CMD ["serve"]
