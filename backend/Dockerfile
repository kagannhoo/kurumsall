FROM python:3.12-slim

WORKDIR /app

ARG INSTALL_SCANNERS=true
ARG NUCLEI_VERSION=3.3.7
ARG SUBFINDER_VERSION=2.6.7
ARG NAABU_VERSION=2.3.1

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev wget unzip ca-certificates \
    && if [ "$INSTALL_SCANNERS" = "true" ]; then \
      wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -O /tmp/nuclei.zip \
      && unzip /tmp/nuclei.zip -d /usr/local/bin \
      && chmod +x /usr/local/bin/nuclei \
      && rm /tmp/nuclei.zip \
      && wget -q "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip" -O /tmp/subfinder.zip \
      && unzip /tmp/subfinder.zip -d /usr/local/bin \
      && chmod +x /usr/local/bin/subfinder \
      && rm /tmp/subfinder.zip \
      && wget -q "https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/naabu_${NAABU_VERSION}_linux_amd64.zip" -O /tmp/naabu.zip \
      && unzip /tmp/naabu.zip -d /usr/local/bin \
      && chmod +x /usr/local/bin/naabu \
      && rm /tmp/naabu.zip \
      && nuclei -update-templates -silent || true; \
    fi \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chmod +x /app/docker-entrypoint.sh

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
