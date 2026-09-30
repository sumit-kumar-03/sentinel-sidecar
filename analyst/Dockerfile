FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f
RUN useradd --system --uid 10003 --no-create-home analyst
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY sentinel_analyst ./sentinel_analyst
USER 10003
EXPOSE 9200
ENTRYPOINT ["python", "-m", "sentinel_analyst"]
