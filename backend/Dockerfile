FROM python:3.12-slim

WORKDIR /app

ARG INSTALL_SCANNERS=false
ARG NUCLEI_VERSION=3.3.7

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev wget unzip ca-certificates \
    && if [ "$INSTALL_SCANNERS" = "true" ]; then \
      wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -O /tmp/nuclei.zip \
      && unzip /tmp/nuclei.zip -d /usr/local/bin \
      && chmod +x /usr/local/bin/nuclei \
      && rm /tmp/nuclei.zip; \
    fi \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
