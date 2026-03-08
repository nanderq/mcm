FROM python:3.14-slim

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ENV PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    MCM_DATA_ROOT=/var/lib/manage-api \
    MCM_WEBUI_PORT=8080

COPY pyproject.toml uv.lock ./
COPY auth.py database.py main.py schema.sql favicon.svg ./
COPY templates ./templates

RUN uv sync --frozen --no-dev

EXPOSE 8080

CMD ["uv", "run", "start"]
