# OSINT Recon

A powerful, Dockerized OSINT reconnaissance web application with a "Black Hat Hacker" aesthetic. This tool aggregates results from popular reconnaissance tools like **Subfinder**, **HTTPX**, and **Nuclei** into a unified, premium dashboard.


## Features

-   **Subdomain Enumeration**: Uses `subfinder` to discover valid subdomains.
-   **Live Host Discovery**: Uses `httpx` to probe for live HTTP/HTTPS services.
-   **Vulnerability Scanning**: Uses `nuclei` with comprehensive template sets (CVEs, vulnerabilities, misconfigurations) to identify security flaws.
-   **Aggregated Results**: Automatically condenses similar vulnerabilities and groups them by host.
-   **Excel Export**: Export full scan results to a multi-tabbed Excel spreadsheet.
-   **Hacker Theme**: A high-contrast, terminal-inspired UI for that authentic cyber-security feel.

## Tech Stack

-   **Backend**: Python (FastAPI)
-   **Frontend**: React + Vite (Vanilla CSS)
-   **Containerization**: Docker
-   **Tools**: ProjectDiscovery Suite (Subfinder, HTTPX, Nuclei)

## Installation & Usage

This guide assumes you are new to Docker and command-line tools. Follow these steps carefully to get the application running.

### 1. Install Prerequisites

First, you need to install **Docker**, which is the software that allows this application to run in a self-contained environment (like a virtual machine, but lighter).

-   **Download Docker Desktop**: Go to [https://www.docker.com/products/docker-desktop/](https://www.docker.com/products/docker-desktop/) and download the version for your operating system (Windows, Mac, or Linux).
-   **Install it**: Run the installer and follow the on-screen instructions.
-   **Verify**: Open your terminal (Command Prompt on Windows, Terminal on Mac) and type `docker --version`. If it prints a version number, you are ready!

### 2. Get the Code

You need to download this project to your computer.

1.  Open your **Terminal** or **Command Prompt**.
2.  Run the following command to download the code:
    ```bash
    git clone https://github.com/yourusername/osint-recon.git
    ```
3.  Go into the project folder:
    ```bash
    cd osint-recon
    ```

### 3. Build the App

Now we need to package the application into a "Docker Image". This reads the code and sets up the environment automatically.

1.  Run this command (this may take a few minutes the first time as it downloads dependencies):
    ```bash
    docker build -t osint-app .
    ```
    *Note: If you get a "permission denied" error on Mac/Linux, try adding `sudo` in front: `sudo docker build -t osint-app .`*

### 4. Run the App

Once built, you can start the application.

1.  Run this command:
    ```bash
    docker run -p 8000:8000 osint-app
    ```
2.  You will see logs appear in the terminal. Wait until you see a message saying the server is running.

### 5. Use It!

1.  Open your web browser (Chrome, Firefox, Safari).
2.  Go to this address: [http://localhost:8000](http://localhost:8000)
3.  You should see the OSINT Recon dashboard. Enter a domain (e.g., `example.com`) and click **Scan**.

## API Endpoints

-   `POST /scan`: Start a new scan for a domain.
-   `GET /scan/{scan_id}`: Retrieve scan status and results.
-   `GET /export/{scan_id}`: Download scan results as `.xlsx`.

## Development

To run locally without Docker:

**Backend**:
```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
```

**Frontend**:
```bash
cd frontend
npm install
npm run dev
```

## Disclaimer
This tool is for educational and authorized testing purposes only. Usage of this tool for attacking targets without prior mutual consent is illegal. The developers assume no liability and are not responsible for any misuse or damage caused by this program.
