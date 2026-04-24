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

# Make app dir writable for non-root users (workspace_*, output/, cache/)
RUN chmod -R a+rwX /app

# DepotDownloader (.NET) needs a writable HOME for IsolatedStorage
ENV HOME=/tmp

CMD ["python", "main.py"]
