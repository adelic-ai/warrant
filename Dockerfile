FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml ./
COPY warrant ./warrant

RUN pip install --no-cache-dir .

ENV WARRANT_DB_PATH=/data/warrant.db
VOLUME ["/data"]

EXPOSE 8000

CMD ["uvicorn", "warrant.main:app", "--host", "0.0.0.0", "--port", "8000"]
