import subprocess
import shutil
import json
import logging
import os
import re
import uuid

from typing import List, Dict, Any, Tuple, Callable

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Scanner:
    def __init__(self):
        self.subfinder_path = self._get_binary_path("subfinder")
        self.amass_path = self._get_binary_path("amass")
        self.httpx_path = self._get_binary_path("httpx")
        self.nuclei_path = self._get_binary_path("nuclei")
        self.theharvester_path = shutil.which("theHarvester") or "theHarvester"
        self.metagoofil_path = "/app/metagoofil/metagoofil.py" 
        self.exiftool_path = shutil.which("exiftool") or "exiftool"
        self.templates_dir = self._find_templates_dir()





    def _get_binary_path(self, tool_name: str) -> str:
        # Prioritize Go bin paths (Docker environment)
        # Verify both existence and execution permission
        go_path = f"/go/bin/{tool_name}"
        if os.path.exists(go_path) and os.access(go_path, os.X_OK):
            return go_path
        
        # Fallback to standard PATH lookup
        return shutil.which(tool_name) or tool_name


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

    def run_amass(self, domain: str) -> Tuple[List[str], List[Dict[str, str]]]:
        logger.info(f"Running Amass on {domain}")
        output_file = f"amass_results_{uuid.uuid4()}.txt"
        
        try:
            # Command: amass enum -active -brute -d target.com -o amass_results.txt
            cmd = [
                self.amass_path, "enum", 
                "-active", 
                "-brute", 
                "-d", domain, 
                "-o", output_file
            ]
            
            logger.info(f"Executing Amass command: {' '.join(cmd)}")
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            if process.returncode != 0:
                logger.error(f"Amass process returned non-zero exit code: {process.returncode}")
                # Log stderr, though amass often prints to stdout or the log file
                logger.error(f"Amass stderr: {process.stderr}")

            raw_lines = []
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    raw_lines = [line.strip() for line in f if line.strip()]
                
                # Cleanup
                os.remove(output_file)
            else:
                logger.warning("Amass output file was not created.")

            # Parse Results
            subdomains = []
            mx_records = []
            
            # Regex patterns
            # Pattern for MX: truelight.org.sg (FQDN) --> mx_record --> alt1.aspmx.l.google.com (FQDN)
            mx_pattern = re.compile(r'(.+?)\s+\(FQDN\)\s+-->\s+mx_record\s+-->\s+(.+?)\s+\(FQDN\)')
            # Pattern for simple subdomain (loose check, just exclude arrows)
            # Lines with arrows are relationships, not direct subdomains list items (unless we parse left side)
            # Amass output can be mixed. We will assume any line NOT matching the relationship pattern 
            # AND looking like a domain is a subdomain.
            # However, in arrow lines, the left side IS a subdomain.
            
            for line in raw_lines:
                # Check MX record
                mx_match = mx_pattern.match(line)
                if mx_match:
                    src_domain = mx_match.group(1).strip()
                    mx_server = mx_match.group(2).strip()
                    mx_records.append({"domain": src_domain, "mx_server": mx_server})
                    
                    # Also add the source domain to subdomains list if valid
                    subdomains.append(src_domain)
                    continue
                
                # Skip other relationship lines (e.g. ns_record, ptr_record) to avoid polluting subdomains
                if " --> " in line:
                    continue

                # Plain subdomain line
                subdomains.append(line)

            # Deduplicate locally
            subdomains = list(set(subdomains))
            logger.info(f"Amass found {len(subdomains)} subdomains and {len(mx_records)} MX records for {domain}")
            return subdomains, mx_records

        except Exception as e:
            logger.exception(f"Amass failed: {e}")
            if os.path.exists(output_file):
                os.remove(output_file)
            return [], []


            
    def run_theharvester(self, domain: str) -> Tuple[List[str], List[str]]:
        logger.info(f"Running theHarvester on {domain}")
        output_file = f"theharvester_results_{uuid.uuid4()}" 
        
        try:
            cmd = [self.theharvester_path]
            # ... (omitting path detection logic for brevity if not changing, but wait, I need to keep it)
            # Actually, I should just replace the whole method to be clean and safe.
            
            # Path Logic: Prefer strict source execution to avoid entrypoint issues
            # We cloned it to /app/theHarvester
            source_path = "/app/theHarvester/theHarvester.py"
            if os.path.exists(source_path):
                 logger.info(f"Using theHarvester source script: {source_path}")
                 cmd = ["python3", source_path]
            elif self.theharvester_path == "theHarvester" and not shutil.which("theHarvester"):
                 # Fallback if not found and system binary missing
                 logger.warning("theHarvester source not found. Falling back to module.")
                 cmd = ["python3", "-m", "theHarvester"]

            # Sources configured for v4.10.0 (removed unsupported ones like threatminer, bing, etc)
            sources = "baidu,crtsh,duckduckgo,hackertarget,rapiddns,subdomaincenter,subdomainfinderc99,thc,urlscan,yahoo"
            cmd.extend(["-d", domain, "-b", sources, "-l", "500", "-f", output_file])
            logger.info(f"Executing theHarvester command: {' '.join(cmd)}")
            
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            # Application Logic: Parse Results
            json_output_path = f"{output_file}.json"
            xml_output_path = f"{output_file}.xml"
            
            emails = []
            hosts = []
            
            if os.path.exists(json_output_path):
                with open(json_output_path, 'r') as f:
                    try:
                        data = json.load(f)
                        emails = data.get("emails", []) or []
                        hosts = data.get("hosts", []) or []
                    except json.JSONDecodeError:
                        logger.error("Failed to parse theHarvester JSON output")
                os.remove(json_output_path)
            elif os.path.exists(xml_output_path):
                os.remove(xml_output_path)
                logger.warning("theHarvester produced XML. Parsing skipped.")
            else:
                 logger.warning("theHarvester output file not found. attempting to parse stdout.")
                 email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
                 raw_emails = email_pattern.findall(process.stdout)
                 
                 # Filter out tool noise (author emails, defaults)
                 excluded_emails = {"cmartorella@edge-security.com"}
                 emails = [e for e in raw_emails if e.lower() not in excluded_emails and "example.com" not in e]

            emails = list(set(emails))
            hosts = list(set(hosts))
            
            # Debugging: Log warning if no results found
            if not emails and not hosts:
                logger.warning("theHarvester found 0 results.")
            
            if process.returncode != 0:
                 if emails or hosts:
                     logger.info(f"theHarvester exited with code {process.returncode} but found results (likely partial source failure). This is normal.")
                 else:
                     logger.warning(f"theHarvester process returned non-zero exit code: {process.returncode}")
                     if process.stderr:
                         logger.warning(f"theHarvester Stderr: {process.stderr}")

            logger.info(f"theHarvester found {len(emails)} emails and {len(hosts)} hosts for {domain}")
            return emails, hosts
            
        except Exception as e:
            logger.exception(f"theHarvester failed: {e}")
            for ext in ['.json', '.xml']:
                if os.path.exists(f"{output_file}{ext}"):
                    os.remove(f"{output_file}{ext}")
            return [], []



    def run_metagoofil(self, domain: str) -> List[str]:
        logger.info(f"Running Metagoofil on {domain}")
        if not os.path.exists(self.metagoofil_path):
            logger.warning(f"Metagoofil not found at {self.metagoofil_path}. Skipping.")
            return []
            
        if not shutil.which("exiftool"):
            logger.warning("Exiftool not found. Skipping Metagoofil processing.")
            return []

        temp_dir = f"metagoofil_{uuid.uuid4()}"
        os.makedirs(temp_dir, exist_ok=True)
        
        try:
            # 1. Download files
            # python3 metagoofil.py -d <domain> -t <types> -n <limit> -o <dir> -w (download)
            cmd_download = [
                "python3", self.metagoofil_path,
                "-d", domain,
                "-t", "pdf,doc,docx,xls,xlsx",
                "-n", "20",
                "-o", temp_dir,
                "-w"
            ]
            logger.info(f"Executing Metagoofil Download: {' '.join(cmd_download)}")
            
            subprocess.run(
                cmd_download,
                capture_output=True,
                text=True,
                check=False # Don't crash if it fails to find files
            )
            
            # Check if any files were downloaded
            files = os.listdir(temp_dir)
            if not files:
                logger.info("Metagoofil found no files to download.")
                shutil.rmtree(temp_dir, ignore_errors=True)
                return []
                
            logger.info(f"Metagoofil downloaded {len(files)} files. Extracting metadata...")

            # 2. Extract Metadata with Exiftool
            cmd_exif = [self.exiftool_path, "-r", temp_dir]
            
            process = subprocess.run(
                cmd_exif,
                capture_output=True,
                text=True
            )
            
            # 3. Parse Emails from Exiftool output
            # Use stricter regex as suggested by user to avoid partial matches
            # Pattern: \b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}\b
            email_pattern = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}\b')
            emails = email_pattern.findall(process.stdout)
            
            # Filter garbage (common in metadata)
            cleaned_emails = []
            for email in emails:
                if domain in email: # Optional: Strict mode? No, let's keep all valid looking emails
                    cleaned_emails.append(email)
                else:
                    # Still keep it, might be third party provider
                    cleaned_emails.append(email)

            cleaned_emails = list(set(cleaned_emails))
            logger.info(f"Metagoofil/Exiftool found {len(cleaned_emails)} emails")
            
            return cleaned_emails

        except Exception as e:
            logger.exception(f"Metagoofil failed: {e}")
            return []
        finally:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

    def run_httpx(self, subdomains: List[str]) -> List[Dict[str, Any]]:
        logger.info(f"Running HTTPX on {len(subdomains)} subdomains")
        if not subdomains:
            return []
        
        try:
            # Clean inputs rigorously
            cleaned_subdomains = [s.strip().lower() for s in subdomains if s.strip()]
            input_str = "\n".join(cleaned_subdomains)
            logger.info(f"HTTPX Input:\n{input_str}")
            
            # Optimized Command for Docker Environment
            # Note: -ip and custom ports (8080/8443) are disabled as they caused network failures in this specific container setup.
            cmd = [
                self.httpx_path,
                "-tech-detect",
                "-title",
                "-status-code",
                "-follow-redirects",
                "-json",
                "-retries", "2",
                "-timeout", "10",
                "-random-agent",
            ]
            logger.info(f"Executing HTTPX command (Stable): {' '.join(cmd)}")
            
            # Use temporary file for input instead of stdin to avoid potential pipe issues
            input_file = f"httpx_input_{uuid.uuid4()}.txt"
            with open(input_file, "w") as f:
                f.write(input_str)
            
            cmd.extend(["-l", input_file])
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False
            )
            
            if os.path.exists(input_file):
                os.remove(input_file)
            
            if process.stderr:
                 logger.info(f"HTTPX Stderr: {process.stderr}")
            


            results = []
            for line in process.stdout.strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        # Normalize IP: httpx might return 'ip' (string) or 'a' (list of IPs)
                        # If 'ip' is missing but 'a' exists, use the first A record.
                        if "ip" not in data or not data["ip"]:
                            if "a" in data and isinstance(data["a"], list) and len(data["a"]) > 0:
                                data["ip"] = data["a"][0]
                            else:
                                data["ip"] = None # Explicitly set to None if missing
                        
                        results.append(data)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse HTTPX line: {line}. Error: {e}")
                        continue
            
            logger.info(f"HTTPX found {len(results)} live hosts")
            

            
            return results
        except subprocess.CalledProcessError as e:
            logger.error(f"HTTPX failed. Stderr: {e.stderr}")
            logger.error(f"HTTPX failed. Stdout: {e.stdout}")
            return []

    def run_nuclei(self, targets: List[str], status_callback: Callable[[str], None] = None) -> List[Dict[str, Any]]:
        logger.info(f"Running Nuclei on {len(targets)} targets")
        if not targets:
            return []
            
        try:
            if status_callback:
                status_callback(f"Running Nuclei (Scanning {len(targets)} targets for vulnerabilities)...")

            # echo targets | nuclei -json -silent
            input_str = "\n".join(targets)
            
            # Construct template paths dynamically
            # To ensure no findings are missed, we should scan the entire 'http' directory if it exists,
            # rather than cherry-picking subfolders like cves/ or misconfiguration/.
            template_args = []
            if self.templates_dir:
                 http_path = os.path.join(self.templates_dir, "http")
                 
                 if os.path.exists(http_path):
                     # Best case: Scan all HTTP templates
                     logger.info(f"Using full HTTP template collection at: {http_path}")
                     template_args.extend(["-t", http_path])
                 else:
                     # Fallback: Just use the root templates dir and let Nuclei decide
                     # output might include dns/ssl/file/etc but ensures we don't miss anything.
                     logger.info(f"HTTP folder not found. Using root templates dir: {self.templates_dir}")
                     template_args.extend(["-t", self.templates_dir])
            else:
                # Fallback to defaults or relative if not found
                template_args.extend(["-t", "cves/", "-t", "vulnerabilities/", "-t", "misconfiguration/", "-t", "exposures/", "-t", "miscellaneous/"])

            cmd = [
                self.nuclei_path,
                *template_args,
                "-severity", "unknown,info,low,medium,high,critical",
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
                # Log stderr but continue to parse stdout for partial results
                logger.error(f"Stderr: {process.stderr}")
                logger.debug(f"Stdout (partial potentially): {process.stdout}")
                # Do NOT return [] here. We want to capture any partial findings.

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

    def run_discovery(self, domain: str, status_callback: Callable[[str], None] = None) -> Dict[str, Any]:
        """
        Runs the discovery chain: Subfinder -> HTTPX
        """


        # 1. Subfinder
        if status_callback:
            status_callback("Running Subfinder (Subdomain Enumeration)...")
        subfinder_results = self.run_subfinder(domain)
        
        # 2. Amass
        if status_callback:
             status_callback("Running Amass (Active Enumeration & Brute Force)...")
        amass_subdomains, amass_mx_records = self.run_amass(domain)

        if status_callback:
            status_callback("Running theHarvester (Email & Subdomain Enumeration)...")
        emails, th_subdomains = self.run_theharvester(domain)

        # 2.6 Metagoofil (Email Enumeration via Metadata)
        if status_callback:
             status_callback("Running Metagoofil (Document Metadata Analysis)...")
        meta_emails = self.run_metagoofil(domain)
        
        # Merge Emails
        total_emails = list(set(emails + meta_emails))
        logger.info(f"Total unique emails found: {len(total_emails)}")

        # Merge and deduplicate
        # Convert both lists to a set to remove duplicates, then back to list
        combined_subdomains = list(set(subfinder_results + amass_subdomains + th_subdomains))
        
        # Ensure root domain is always included in the probe list
        if domain not in combined_subdomains:
            combined_subdomains.append(domain)

        logger.info(f"Total unique subdomains found: {len(combined_subdomains)}")
        
        # 3. HTTPX
        if status_callback:
             status_callback(f"Running HTTPX (Probing {len(combined_subdomains)} possible hosts)...")
        live_hosts_data = self.run_httpx(combined_subdomains)
        
        return {
            "domain": domain,
            "subdomains": combined_subdomains,
            "live_hosts": live_hosts_data,
            "mx_records": amass_mx_records,
            "mx_records": amass_mx_records,
            "emails": total_emails
        }
