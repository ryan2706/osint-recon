FROM ubuntu:24.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies, Python, and Go prerequisites
# We include python3-venv because Ubuntu 24.04 (managed by PEP 668) requires a venv for pip install
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    wget \
    git \
    libpcap-dev \
    curl \
    gnupg \
    python3 \
    python3-pip \
    python3-venv \
    binutils \
    libpam-modules \
    libpam0g \
    libpam-runtime \
    libcurl4 \
    libxml2-dev \
    libxslt-dev \
    libffi-dev \
    libimage-exiftool-perl \
    && apt-get remove -y --purge linux-image-* linux-headers-* || true \
    && rm -rf /var/lib/apt/lists/*

# Install Go
RUN wget https://go.dev/dl/go1.25.5.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.25.5.linux-amd64.tar.gz && \
    rm go1.25.5.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/go"
ENV PATH="${GOPATH}/bin:${PATH}"

# Install ProjectDiscovery tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install -v github.com/owasp-amass/amass/v4/cmd/amass@latest
# Clone Nuclei Templates to a fixed location
RUN git clone https://github.com/projectdiscovery/nuclei-templates.git /app/nuclei-templates

# Install theHarvester from source (pip package is often problematic)
# Install theHarvester from source (pip package is often problematic)
RUN git clone https://github.com/laramies/theHarvester.git /app/theHarvester

# Install Metagoofil from source
# Install Metagoofil from source
RUN git clone https://github.com/opsdisk/metagoofil.git /app/metagoofil

# Clean up Go module cache and build artifacts to remove test keys (fix false positives)
RUN rm -rf /go/pkg /go/src /root/.cache


# Install Node.js (for Frontend Build)
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y nodejs

# Setup Backend
WORKDIR /app/backend
COPY backend/requirements.txt .

# Create and use a virtual environment
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --upgrade pip "setuptools>=78.1.1"

# Install tool dependencies into venv
RUN cd /app/theHarvester && pip install netaddr && pip install .
RUN cd /app/metagoofil && pip install -r requirements.txt

RUN pip install --no-cache-dir -r requirements.txt


COPY backend/ .

# Setup Frontend and Build
WORKDIR /app/frontend
COPY frontend/package.json .
COPY frontend/vite.config.js .
COPY frontend/index.html .
COPY frontend/src ./src
COPY frontend/public ./public
# Create public dir if not exists (vite might need it or expects it)
RUN mkdir -p public

RUN npm install
RUN npm run build

# Remove build dependencies to reduce attack surface (fixes Trivy findings for gnupg/libxslt/icu/curl)
# We remove git, wget, curl, nodejs as they are no longer needed
RUN apt-get remove -y gnupg libxslt-dev git wget curl nodejs libcurl4 && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# Move frontend build to backend static (or configure backend to serve it)
# We will assume backend serves static files from ../frontend/dist
WORKDIR /app/backend

# Expose port
EXPOSE 8000

# Start command
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
