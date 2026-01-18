# OSINT Recon

<div align="center">
  <h3>⚡ The Ultimate Cyberpunk Reconnaissance Dashboard ⚡</h3>
  <p>Automated. Dockerized. Aesthetically pleasing.</p>
</div>

---

**OSINT Recon** is a powerful, containerized web application designed for offensive security professionals and bug bounty hunters. It aggregates the world's best open-source reconnaissance tools into a unified, high-contrast, terminal-inspired dashboard.

Stop running five different terminal windows. Start your recon with **one click**.

## 🚀 Features

*   **🕵️ Subdomain Enumeration**: Passive (`subfinder`) and active brute-force (`amass`) discovery.
*   **📧 Email Harvesting**: automated gathering from public sources (`theHarvester`) and document metadata analysis (`Metagoofil` + `ExifTool`).
*   **🟢 Live Host Discovery**: Intelligent probing (`httpx`) to identify live web servers, detecting titles, status codes, and web technologies.
*   **🛡️ Vulnerability Scanning**: Integrated `nuclei` scanning to detect CVEs, misconfigurations, and exposures on identified targets.
*   **📊 Smart Reporting**:
    *   **Live Dashboard**: Sort, filter, and view results in real-time.
    *   **Excel Export**: One-click download of a comprehensive `.xlsx` report with dedicated tabs for every data type.
*   **🎨 Cyberpunk UI**: A "CRT" scanline aesthetic to keep you immersed in the zone.

## 🛠️ Tech Stack

*   **Frontend**: React (Vite) + Vanilla CSS (No frameworks, pure cyberpunk style).
*   **Backend**: Python (FastAPI).
*   **Container**: Docker & Docker Compose.
*   **Core Tools**:
    *   [Subfinder](https://github.com/projectdiscovery/subfinder)
    *   [HTTPX](https://github.com/projectdiscovery/httpx)
    *   [Nuclei](https://github.com/projectdiscovery/nuclei)
    *   [Amass](https://github.com/owasp-amass/amass)
    *   [theHarvester](https://github.com/laramies/theHarvester)
    *   [Metagoofil](https://github.com/opsdisk/metagoofil)

---

## 🏁 Quick Start

**Prerequisites**: You only need [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed.

### 1. Clone the Repo
```bash
git clone https://github.com/ryan2706/osint-recon.git
cd osint-recon
```

### 2. Build & Run
Run the application with a single command:
```bash
docker-compose up --build
```
*Wait for a few minutes on the first run while it builds the environment and downloads tool binaries.*

### 3. Start Hacking
Open your browser and navigate to:
**[http://localhost:8000](http://localhost:8000)**

Enter a target domain (e.g., `example.com`) and hit **START RECON**.

---

## 📖 Usage Guide

1.  **Discovery Phase**: The tool first enumerates subdomains, finds emails, and checks for live hosts.
2.  **Target Selection**: Once discovery is complete, you will see a list of live hosts. Select the ones you want to check for vulnerabilities.
3.  **Vulnerability Scan**: Click **Remote Scan** to launch `nuclei` against the selected targets.
4.  **Reporting**: View the results on the dashboard or click **EXPORT TO EXCEL** for a professional report.

## ⚖️ Legal Disclaimer

**Usage of this tool for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.**

---
*Built with 💚 by Ryan*
