import subprocess
import shutil
import json
import logging
import os

from typing import List, Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Scanner:
    def __init__(self):
        self.subfinder_path = shutil.which("subfinder") or "subfinder"
        self.httpx_path = shutil.which("httpx") or "httpx"
        self.nuclei_path = shutil.which("nuclei") or "nuclei"
        self.templates_dir = self._find_templates_dir()

    def _find_templates_dir(self) -> str:
        # Common default locations for nuclei templates in Docker
        potential_paths = [
            "/app/nuclei-templates",
            "/root/nuclei-templates",
            "/root/.nuclei-templates",
            "/root/.local/nuclei-templates",
            os.path.expanduser("~/nuclei-templates")
        ]
        
        for path in potential_paths:
            if os.path.exists(path):
                logger.info(f"Found Nuclei templates at: {path}")
                return path
        
        logger.warning("Could not find Nuclei templates directory. Scans may fail if paths are relative.")
        return ""

    def run_subfinder(self, domain: str) -> List[str]:
        logger.info(f"Running Subfinder on {domain}")
        try:
            # -d domain -all -recursive -silent (more comprehensive)
            process = subprocess.run(
                [self.subfinder_path, "-d", domain, "-all", "-recursive", "-silent"],
                capture_output=True,
                text=True,
                check=True
            )
            subdomains = process.stdout.strip().split('\n')
            # Filter empty strings
            subdomains = [s for s in subdomains if s]
            logger.info(f"Found {len(subdomains)} subdomains for {domain}")
            return subdomains
        except subprocess.CalledProcessError as e:
            logger.error(f"Subfinder failed: {e.stderr}")
            return []

    def run_httpx(self, subdomains: List[str]) -> List[Dict[str, Any]]:
        logger.info(f"Running HTTPX on {len(subdomains)} subdomains")
        if not subdomains:
            return []
        
        try:
            input_str = "\n".join(subdomains)
            process = subprocess.run(
                [
                    self.httpx_path,
                    "-ports", "80,443,8080,8443", 
                    "-tech-detect",
                    "-title",
                    "-status-code",
                    "-follow-redirects",
                    "-json",
                    "-silent"
                ],
                input=input_str,
                capture_output=True,
                text=True,
                check=True
            )
            
            results = []
            for line in process.stdout.strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        results.append(data)
                    except json.JSONDecodeError:
                        continue
            
            logger.info(f"HTTPX found {len(results)} live hosts")
            return results
        except subprocess.CalledProcessError as e:
            logger.error(f"HTTPX failed. Stderr: {e.stderr}")
            logger.error(f"HTTPX failed. Stdout: {e.stdout}")
            return []

    def run_nuclei(self, targets: List[str]) -> List[Dict[str, Any]]:
        logger.info(f"Running Nuclei on {len(targets)} targets")
        if not targets:
            return []
            
        try:
            # echo targets | nuclei -json -silent
            input_str = "\n".join(targets)
            
            # Construct template paths dynamically
            template_args = []
            if self.templates_dir:
                 # Check if specific folders exist
                 cves_path = os.path.join(self.templates_dir, "http", "cves")
                 if not os.path.exists(cves_path):
                     cves_path = os.path.join(self.templates_dir, "cves")

                 vuln_path = os.path.join(self.templates_dir, "http", "vulnerabilities")
                 if not os.path.exists(vuln_path):
                     vuln_path = os.path.join(self.templates_dir, "vulnerabilities")
                 
                 misc_path = os.path.join(self.templates_dir, "http", "misconfiguration")
                 if not os.path.exists(misc_path):
                     misc_path = os.path.join(self.templates_dir, "misconfiguration")

                 # If we found specific folders, use them. Otherwise just use the root.
                 if os.path.exists(cves_path):
                     template_args.extend(["-t", cves_path])
                 if os.path.exists(vuln_path):
                     template_args.extend(["-t", vuln_path])
                 if os.path.exists(misc_path):
                     template_args.extend(["-t", misc_path])
                 
                 # If no specific args added (structure changed?), fallback to root
                 if not template_args:
                     template_args.extend(["-t", self.templates_dir])
            else:
                # Fallback to defaults or relative if not found
                template_args.extend(["-t", "cves/", "-t", "vulnerabilities/", "-t", "misconfiguration/"])

            cmd = [
                self.nuclei_path,
                *template_args,
                "-rl", "50",
                "-j",
                "-silent",
                "-nc"
            ]
            
            process = subprocess.run(
                cmd,
                input=input_str,
                capture_output=True,
                text=True,
                check=True
            )
            
            results = []
            for line in process.stdout.strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        # Normalize keys (kebab-case to snake_case)
                        normalized_data = {}
                        for k, v in data.items():
                            new_key = k.replace('-', '_')
                            normalized_data[new_key] = v
                        results.append(normalized_data)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to decode Nuclei JSON line: {line[:100]}... Error: {e}")
                        continue
            
            logger.info(f"Nuclei found {len(results)} issues")
            return results
        except subprocess.CalledProcessError as e:
            logger.error(f"Nuclei failed. Stderr: {e.stderr}")
            logger.error(f"Nuclei failed. Stdout: {e.stdout}")
            return []

    def scan_domain(self, domain: str) -> Dict[str, Any]:
        """
        Runs the full scan chain: Subfinder -> HTTPX -> Nuclei
        """
        # 1. Subfinder
        subdomains = self.run_subfinder(domain)
        
        # 2. HTTPX
        live_hosts_data = self.run_httpx(subdomains)
        # Extract URLs for nuclei
        live_urls = [h.get('url') for h in live_hosts_data if h.get('url')]
        logger.info(f"Targets for Nuclei: {live_urls}")
        
        # 3. Nuclei
        vulnerabilities = self.run_nuclei(live_urls)
        
        return {
            "domain": domain,
            "subdomains": subdomains,
            "live_hosts": live_hosts_data,
            "vulnerabilities": vulnerabilities
        }
