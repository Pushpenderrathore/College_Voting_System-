FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PORT=8000

WORKDIR /app

# Install build deps (kept small); you can remove build-essential if not needed
RUN apt-get update && apt-get install -y --no-install-recommends build-essential && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

# Use eventlet worker for Socket.IO support
CMD gunicorn -k eventlet -w 1 --bind 0.0.0.0:${PORT} app:app
