FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f

RUN useradd --system --uid 10002 --no-create-home engine
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY sentinel_engine ./sentinel_engine
COPY models ./models

USER 10002
EXPOSE 9000 9001
ENTRYPOINT ["python", "-m", "sentinel_engine"]
