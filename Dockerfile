FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PORT=8000

WORKDIR /app

# Install minimal system deps (kept small)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

EXPOSE 8000

# Gunicorn with gthread (CORRECT for Flask + threading SocketIO)
CMD ["gunicorn", "-w", "1", "--threads", "8", "--bind", "0.0.0.0:8000", "app:app"]
