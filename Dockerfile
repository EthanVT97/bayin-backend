# ────────────── Base Python ──────────────
FROM python:3.11-slim

# ────────────── Working Directory ──────────────
WORKDIR /app

# ────────────── System Dependencies ──────────────
RUN apt-get update && apt-get install -y \
    build-essential gcc curl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# ────────────── Copy Code ──────────────
COPY . /app

# ────────────── Install Dependencies ──────────────
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ────────────── Expose Port ──────────────
EXPOSE 8000

# ────────────── Entrypoint ──────────────
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
