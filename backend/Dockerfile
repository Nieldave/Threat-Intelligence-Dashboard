# 1. Base image: use official Python slim
FROM python:3.10-slim

# 2. Set workdir
WORKDIR /app

# 3. Install system dependencies (optional: for pandas, sklearn, xgboost)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential \
       libatlas-base-dev \
       gcc \
    && rm -rf /var/lib/apt/lists/*

# 4. Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 5. Copy your backend code
COPY . .

# 6. Expose the port Uvicorn will use
EXPOSE 8000

# 7. Create a non-root user and switch (optional but recommended)
RUN adduser --disabled-password appuser
USER appuser

# 8. Default command: run migrations/ingestion if needed, then start Uvicorn
# If you want ingestion on container start, uncomment the ingest line
CMD uvicorn main:app --host 0.0.0.0 --port 8000
# To automatically ingest on startup:
# CMD ["sh", "-c", "python ingest.py Cybersecurity_Dataset.csv && uvicorn main:app --host 0.0.0.0 --port 8000"]
