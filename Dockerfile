FROM python:3.14-slim

WORKDIR /app

# Install minimal runtime deps for ELF binaries and shared libraries
RUN apt-get update && \
    apt-get install -y --no-install-recommends libicu-dev && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Ensure the Linux binaries are executable
RUN chmod +x data/DepotDownloader lib/s2binlib.so

CMD ["python", "main.py"]
