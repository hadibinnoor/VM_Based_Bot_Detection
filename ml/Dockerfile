FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY ml/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY ml /app/ml
COPY scripts/ml-entrypoint.sh /app/ml-entrypoint.sh
RUN chmod +x /app/ml-entrypoint.sh

EXPOSE 5001

ENTRYPOINT ["/app/ml-entrypoint.sh"]
