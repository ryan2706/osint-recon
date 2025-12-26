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
                "-severity", "info,low,medium,high,critical",
                "-rl", "50",
                "-j",
                "-silent",
                "-nc"
            ]

            # Log the full command for debugging
            logger.info(f"Executing Nuclei command: {' '.join(cmd)}")
            
            process = subprocess.run(
                cmd,
                input=input_str,
                capture_output=True,
                text=True
            )
            
            if process.returncode != 0:
                logger.error(f"Nuclei process failed with return code {process.returncode}")
                logger.error(f"Stderr: {process.stderr}")
                logger.error(f"Stdout: {process.stdout}")
                # We don't raise immediately to allow returning partial results if any, 
                # but with check=False (implied by removing check=True above) we handle it here.
                return []

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
            
            logger.info(f"Nuclei stderr output (info/warning): {process.stderr}")
            logger.info(f"Nuclei raw findings: {len(results)}")

            # Aggregate results
            aggregated_results = {}
            for item in results:
                # Create a unique key based on template_id and where it matched
                # We use the template_id and matched_at as the primary key
                # Some templates might match same URL multiple times with different matchers
                template_id = item.get("template_id", "")
                matched_at = item.get("matched_at", "")
                
                key = f"{template_id}|{matched_at}"

                if key not in aggregated_results:
                    # Initialize with the first occurrence
                    aggregated_results[key] = item.copy()
                    aggregated_results[key]["matchers"] = []
                    aggregated_results[key]["extracted_results_list"] = []

                # Merge matcher_name
                matcher = item.get("matcher_name")
                if matcher and matcher not in aggregated_results[key]["matchers"]:
                    aggregated_results[key]["matchers"].append(matcher)

                # Merge extracted_results
                extracted = item.get("extracted_results")
                if extracted:
                    if isinstance(extracted, list):
                        for ex in extracted:
                            if ex not in aggregated_results[key]["extracted_results_list"]:
                                aggregated_results[key]["extracted_results_list"].append(ex)
                    else:
                        if extracted not in aggregated_results[key]["extracted_results_list"]:
                             aggregated_results[key]["extracted_results_list"].append(extracted)

            final_results = list(aggregated_results.values())
            logger.info(f"Nuclei aggregated findings: {len(final_results)}")
            return final_results
        except Exception as e:
            logger.exception(f"Exception while running Nuclei: {e}")
            return []

    def run_discovery(self, domain: str) -> Dict[str, Any]:
        """
        Runs the discovery chain: Subfinder -> HTTPX
        """
        # 1. Subfinder
        subdomains = self.run_subfinder(domain)
        
        # 2. HTTPX
        live_hosts_data = self.run_httpx(subdomains)
        
        return {
            "domain": domain,
            "subdomains": subdomains,
            "live_hosts": live_hosts_data
        }

    def run_nuclei_scan(self, targets: List[str]) -> List[Dict[str, Any]]:
        """
        Runs Nuclei on specific targets
        """
        logger.info(f"Targets for Nuclei: {targets}")
        vulnerabilities = self.run_nuclei(targets)
        return vulnerabilities
