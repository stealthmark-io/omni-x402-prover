FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

COPY pyproject.toml README.md LICENSE bazaar_manifest.json ./
COPY omni_x402_prover ./omni_x402_prover

RUN pip install --no-cache-dir z3-solver==5.3.3.0 && \
    pip install --no-cache-dir --no-deps .

EXPOSE 8402

CMD ["omni-x402-http", "--host", "0.0.0.0", "--port", "8402"]
