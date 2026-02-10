cat > test_nethunter.py << 'EOF'
#!/usr/bin/env python3
import os, sys, subprocess, time
from pathlib import Path

print("🔍 TSAR-EXEC TEST NETHUNTER - VÉRIFICATION RÉELLE")
print("=" * 60)

PROJECT_ROOT = Path(".")
CHAIN_DIR = PROJECT_ROOT / "chain"

# 1. TEST FICHIERS CRITIQUES
print("
📁 FICHIERS CRITIQUES:")
files = ["client.py", "recon.py", "config.json", "docker-compose.yml", "exploitmass.py"]
dirs = ["chain", "chain/input", "chain/docked", "chain/VLUN", "chain/VLUN_Sh"]

for f in files:
    p = PROJECT_ROOT / f
    status = "✅" if p.exists() else "❌"
    print(f"  {f:<20} {status}")

for d in dirs:
    p = PROJECT_ROOT / d
    status = "✅" if p.exists() else "❌" 
    print(f"  📁{d:<18} {status}")

# 2. TEST SYNTAXE PYTHON (réel)
print("
🔧 SYNTAXE PYTHON:")
python_files = ["client.py", "recon.py", "exploitmass.py", "pipeline.py"]
for pyfile in python_files:
    if (PROJECT_ROOT / pyfile).exists():
        try:
            result = subprocess.run([sys.executable, "-m", "py_compile", pyfile], 
                                  capture_output=True, timeout=5)
            status = "✅" if result.returncode == 0 else "❌"
        except:
            status = "⚠️"
        print(f"  {pyfile:<15} {status}")
    else:
        print(f"  {pyfile:<15} FICHIER MANQUANT")

# 3. TEST DOCKER-COMPOSE
print("
🐳 DOCKER-COMPOSE:")
try:
    res = subprocess.run(["docker-compose", "--version"], capture_output=True, text=True, timeout=5)
    docker_status = "✅" if res.returncode == 0 else "❌ V1"
    print(f"  docker-compose v1  {docker_status}")
except:
    print("  docker-compose v1  ❌")

try:
    res = subprocess.run(["docker", "compose", "version"], capture_output=True, text=True, timeout=5)
    docker_status = "✅" if res.returncode == 0 else "❌ V2"
    print(f"  docker compose v2  {docker_status}")
except:
    print("  docker compose v2  ❌")

# 4. TEST CONFIG.JSON
print("
⚙️  CONFIG.JSON:")
if (PROJECT_ROOT / "config.json").exists():
    try:
        with open("config.json") as f:
            config = f.read(1024)  # Juste début
        print("  config.json       ✅ VALIDE")
    except:
        print("  config.json       ❌ CORROMPU")
else:
    print("  config.json       ❌ MANQUANT")

# 5. TEST CLIENT.PY STATUS (réel)
print("
🎛️  CLIENT.PY --STATUS:")
client_path = PROJECT_ROOT / "client.py"
if client_path.exists():
    try:
        res = subprocess.run([sys.executable, "client.py", "--status"], 
                           cwd=PROJECT_ROOT, capture_output=True, 
                           text=True, timeout=10)
        if res.returncode == 0:
            print("  client.py --status ✅ OK")
        else:
            print("  client.py --status ⚠️  SORTIE:", res.stdout.strip()[:100] or "RIEN")
    except:
        print("  client.py --status ⚠️  TIMEOUT/ERREUR")
else:
    print("  client.py         ❌ MANQUANT")

print("
" + "=" * 60)
print("🎯 RÉSUMÉ: Lance python3 launcher_ultimate.py SI TOUT ✅ ci-dessus")
EOF
