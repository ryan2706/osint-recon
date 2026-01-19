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

## 🏁 Quick Start (Beginner's Guide)

Don't worry if you've never used Docker before. Just follow these steps exactly.

### Step 1: Install Docker
1.  Download **Docker Desktop** from [docker.com](https://www.docker.com/products/docker-desktop/).
2.  Install it and open the application.
3.  **Wait** until you see the green status bar saying "Engine running" in the Docker Desktop window.

### Step 2: Get the Code
1.  Open your computer's **Terminal** (Mac/Linux) or **PowerShell** (Windows).
2.  Copy and paste this command to download the tool:
    ```bash
    git clone https://github.com/ryan2706/osint-recon.git
    ```
3.  Go into the folder:
    ```bash
    cd osint-recon
    ```

### Step 3: Run the App
1.  Copy and paste this command:
    ```bash
    docker-compose up --build
    ```
2.  **Be Patient**: You will see a lot of text scrolling on the screen. This is normal.
    *   The first time you run this, it effectively "installs" all the tools inside a virtual container.
    *   It may take **5-10 minutes** depending on your internet speed.
3.  When you see a message like `Application startup complete` or `Uvicorn running on http://0.0.0.0:8000`, it is ready.

### Step 4: Open the Dashboard
1.  Open your web browser (Chrome, Firefox, etc.).
2.  Type this address in the bar: **[http://localhost:8000](http://localhost:8000)**
3.  Enter a domain (like `example.com`) and click **START RECON**.

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
