FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f

RUN useradd --system --uid 10001 --no-create-home sentinel \
 && mkdir /rendered && chown sentinel /rendered

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY sentinel_control ./sentinel_control

USER 10001
ENTRYPOINT ["python", "-m", "sentinel_control"]
