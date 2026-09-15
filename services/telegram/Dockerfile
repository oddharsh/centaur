FROM python:3.13-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285
RUN pip install --no-cache-dir uv==0.9.9 && useradd --uid 10001 --create-home telegram
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev
COPY service.py store.py ./
USER 10001
ENV PYTHONDONTWRITEBYTECODE=1
EXPOSE 8000
CMD [".venv/bin/uvicorn", "service:app_factory", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--limit-concurrency", "64"]
