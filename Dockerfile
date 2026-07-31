FROM python:3.12-slim

LABEL maintainer="HuaweiBE3Scrapper"
LABEL description="Scrapes Huawei WiFi BE3 router data and pushes to Zabbix"

# Prevent Python from buffering stdout/stderr
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Install dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY crypto.py .
COPY huawei_client.py .
COPY zabbix_push.py .
COPY scraper.py .

# Run as non-root user
RUN useradd --create-home --shell /bin/bash scraper
USER scraper

ENTRYPOINT ["python", "-u", "scraper.py"]
