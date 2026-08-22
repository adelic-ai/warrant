FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml ./
COPY sage ./sage

RUN pip install --no-cache-dir .

ENV SAGE_DB_PATH=/data/sage.db
VOLUME ["/data"]

EXPOSE 8000

CMD ["uvicorn", "sage.main:app", "--host", "0.0.0.0", "--port", "8000"]
