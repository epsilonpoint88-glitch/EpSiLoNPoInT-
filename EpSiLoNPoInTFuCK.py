#!/usr/bin/env python3
"""
EpSiLoNPoInTFuCK v5.1 - Obfuscateur Ultra-Avancé pour CVE-2026-0920
Fonctionnalités :
- Obfuscation multi-couches (XOR rolling + homoglyphes + zero-width)
- Génération d'identifiants chaotiques anti-détection
- Support des dead code snippets dynamiques
- Mode "stealth" pour éviter les analyses heuristiques
- Intégration parfaite avec exploit.py
"""

#!/usr/bin/env python3
import sys
import random
import time
import base64
import zlib
import hashlib
import marshal
import secrets
import string
import inspect
import os
import ctypes
import platform
import gc
import dis
import opcode
import ast
import traceback
import weakref
import functools
import itertools
import collections
import math
import struct
import array
import decimal
import fractions
import datetime
import uuid
import warnings
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Union, Callable

# --- Constantes Globales ---
CHAOS_SEED = secrets.randbelow(2**64 - 1)
random.seed(CHAOS_SEED ^ int(time.time_ns() // 1000000) ^ os.getpid() ^ os.getppid())

ZERO_WIDTH = [
    '\u200b', '\u200c', '\u200d', '\ufeff', '\u2060', '\u2061',
    '\u2062', '\u2063', '\u2064', '\u200e', '\u200f', '\u061c',
    '\u2008', '\u2009', '\u200a', '\u202f', '\u205f', '\u3000'
]

HOMOGLYPHS = {
    'a': ['а', 'ɑ', 'α', 'ᴀ', 'ᵃ', 'ᵆ', 'ᵅ', 'ɐ', 'ɑ́', 'а́', 'ᵄ', 'ａ', '𝐚', '𝗮', '𝙖'],
    'b': ['Ь', 'Ƅ', 'ɓ', 'ᵇ', 'ᵝ', 'Ꮜ', 'Ᏼ', 'ᗷ', 'ᗸ', 'ᙠ', 'ḃ', 'ｂ', '𝐛', '𝗯', '𝙗'],
    'c': ['с', 'ϲ', 'ᴄ', 'ᶜ', 'ϲ', 'ҫ', 'ᴄ̧', 'ｃ', '𝐜', '𝗰', '𝙘'],
    'd': ['ԁ', 'ᴅ', 'ᵈ', 'ᴆ', 'ᴆ́', 'ｄ', '𝐝', '𝗱', '𝙙'],
    'e': ['е', 'ҽ', 'ᴇ', 'ᵉ', 'ɛ', 'ᴇ́', 'ᵋ', 'ｅ', '𝐞', '𝗲', '𝙚'],
    'f': ['ϝ', 'ᶠ', 'ƒ', 'ᴆ', 'ᴆ́', 'ｆ', '𝐟', '𝗳', '𝙛'],
    'g': ['ɡ', 'ɢ', 'ᵍ', 'ᵷ', 'ᵸ', 'ｇ', '𝐠', '𝗴', '𝙜'],
    'h': ['һ', 'ᴴ', 'ᵶ', 'ᴴ́', 'ｈ', '𝐡', '𝗵', '𝙝'],
    'i': ['і', 'ӏ', 'ɪ', 'ⁱ', 'ᵢ', 'ᶦ', 'ᶦ́', 'ｉ', '𝐢', '𝗶', '𝙞'],
    'j': ['ј', 'ʝ', 'ᴊ', 'ᶡ', 'ｊ', '𝐣', '𝗷', '𝙟'],
    'k': ['κ', 'ᴋ', 'ᵏ', 'ᴋ́', 'ｋ', '𝐤', '𝗸', '𝙠'],
    'l': ['ӏ', 'ł', 'ᴌ', 'ᶫ', 'ᶫ́', 'ｌ', '𝐥', '𝗹', '𝙡'],
    'm': ['ᴍ', 'ᵐ', 'ᵯ', 'ᵯ́', 'ｍ', '𝐦', '𝗺', '𝙢'],
    'n': ['ɴ', 'ᴎ', 'ᵑ', 'ᵰ', 'ᵰ́', 'ｎ', '𝐧', '𝗻', '𝙣'],
    'o': ['о', 'ο', 'ᴏ', 'ᵒ', 'ο', 'ᵓ', 'ᵓ́', 'ｏ', '𝐨', '𝗼', '𝙤'],
    'p': ['р', 'ρ', 'ᴘ', 'ᵖ', 'ρ', 'ᵱ', 'ｐ', '𝐩', '𝗽', '𝙥'],
    'q': ['ԛ', 'ᴋ', 'ᵠ', 'ｑ', '𝐪', '𝗾', '𝙦'],
    'r': ['ᴙ', 'ᵣ', 'ᵲ', 'ᵲ́', 'ｒ', '𝐫', '𝗿', '𝙧'],
    's': ['ѕ', 'ʂ', 'ᴛ', 'ᶳ', 'ᶳ́', 'ｓ', '𝐬', '𝘀', '𝙨'],
    't': ['ᴛ', 'ᵗ', 'ᵵ', 'ᵵ́', 'ｔ', '𝐭', '𝘁', '𝙩'],
    'u': ['υ', 'ᴜ', 'ᵘ', 'ᴜ', 'ᵤ', 'ᵤ́', 'ｕ', '𝐮', '𝘂', '𝙪'],
    'v': ['ᵛ', 'ᵥ', 'ᵥ́', 'ｖ', '𝐯', '𝘃', '𝙫'],
    'w': ['ᵂ', 'ᵃ', 'ᵃ́', 'ｗ', '𝐰', '𝘄', '𝙬'],
    'x': ['х', 'ᵡ', 'ᵡ́', 'ｘ', '𝐱', '𝘅', '𝙭'],
    'y': ['у', 'ʏ', 'ᵧ', 'ᵧ́', 'ｙ', '𝐲', '𝘆', '𝙮'],
    'z': ['ᴢ', 'ᶻ', 'ᶻ́', 'ｚ', '𝐳', '𝘇', '𝙯'],
    '0': ['Ο', '∘', 'о', '۰', '𝟎', '𝟢', '𝟬', '𝟶'],
    '1': ['Ⅰ', '¹', '۱', '𝟏', '𝟣', '𝟭', '𝟷'],
    '2': ['Ⅱ', '²', '۲', '𝟐', '𝟤', '𝟮', '𝟸'],
    '3': ['Ⅲ', '³', '۳', '𝟑', '𝟥', '𝟯', '𝟹'],
    '4': ['Ⅳ', '⁴', '۴', '𝟒', '𝟦', '𝟰', '𝟺'],
    '5': ['Ⅴ', '⁵', '۵', '𝟓', '𝟧', '𝟱', '𝟻'],
    '6': ['Ⅵ', '⁶', '۶', '𝟔', '𝟨', '𝟲', '𝟼'],
    '7': ['Ⅶ', '⁷', '۷', '𝟕', '𝟩', '𝟳', '𝟽'],
    '8': ['Ⅷ', '⁸', '۸', '𝟖', '𝟪', '𝟴', '𝟾'],
    '9': ['Ⅸ', '⁹', '۹', '𝟗', '𝟫', '𝟵', '𝟿'],
    '_': ['‿', '⁀', '⁔', '⁔́', '＿']
}


class EpSiLoNPoInTFuCKv5:
    def __init__(self, stealth_mode: bool = False):
        self.seed = CHAOS_SEED
        self.used_names = set()
        self.stealth_mode = stealth_mode
        self._init_dead_snippets()
    
    
    def _init_dead_snippets(self):
        self.dead_snippets = [
            "while False: exec('import os; os._exit(1)')",
            "def _fake_recursion(x): return _fake_recursion(x-1) if x > 0 else 0; _fake_recursion(5000)",
            "try: 1/0 except: pass",
            "[i for i in range(10**7) if False]",
            "lambda x: [hashlib.sha3_512(str(i).encode()).hexdigest() for i in range(50000)]",
            "class _FakeMeta(type): pass; class _GhostClass(metaclass=_FakeMeta): pass",
            "if __debug__: import sys; sys.exit(0)",
            "assert False, 'Never execute'",
            "def _fake_decorator(f): return f; @_fake_decorator def _fake_func(): pass",
            "exec('import this; this.s = \"\"\"Zen of Python\"\"\"')",
            "if 'PYTHONHASHSEED' in os.environ: os._exit(0)",
            "for _ in range(1000000): pass",
            "try: raise MemoryError except: pass",
            "[x**2 for x in range(10**6) if False]",
            "def _infinite(): while True: yield 1",
            "import gc; gc.collect(); gc.set_debug(gc.DEBUG_LEAK)",
            "import ctypes; ctypes.pythonapi.Py_MemoryView_FromMemory(0,0,0,0)",
            "import sys; sys.setrecursionlimit(10**6); def r(): r()",
            "try: import nonexistent except: pass",
            "[eval('1+1') for _ in range(10000) if False]",
        ]

    def _init_anti_debug_traps(self):
        self.anti_debug_code = [
            "if hasattr(sys, '_getframe') and sys._getframe().f_back: sys.exit(1)",
            "start = time.perf_counter_ns(); [hashlib.sha3_256(b'trap') for _ in range(10**6)]; if (time.perf_counter_ns() - start) / 10**6 > 800: sys.exit(1)",
            "if 'pdb' in sys.modules or 'pydevd' in sys.modules: sys.exit(1)",
            "if sys.gettrace() is not None: sys.exit(1)",
            "if 'LD_PRELOAD' in os.environ: sys.exit(1)",
            "if os.getuid() == 0: sys.exit(1)",
            "if Path('/.dockerenv').exists(): sys.exit(1)",
            "if 'docker' in open('/proc/1/cgroup').read(): sys.exit(1)",
            "import ptrace; ptrace.ptrace(ptrace.PTRACE_TRACEME, 0, None, None)",
            "if ctypes.CDLL('libc.so.6').ptrace(0, 0, 0, 0) == -1: sys.exit(1)",
        ]

    def gen_chaotic_identifier(self, min_len: int = 55, max_len: int = 80) -> str:
        """Génère un identifiant ultra-complexe avec homoglyphes et zero-width chars."""
        length = random.randint(min_len, max_len)
        base = ''.join(random.choices(string.ascii_letters + string.digits + '_', k=length))

        # Insertion de caractères invisibles
        invis_count = random.randint(8, 15)
        invis_positions = sorted(random.sample(range(length), invis_count))
        invis_chars = random.choices(ZERO_WIDTH, k=invis_count)
        base_list = list(base)
        for pos, char in zip(invis_positions, invis_chars):
            base_list.insert(pos, char)
        base = ''.join(base_list)

        # Remplacement par homoglyphes
        homo_part = ''.join(
            random.choice(HOMOGLYPHS.get(c.lower(), [c]))
            for c in base[:min(25, len(base))]
        )

        # Ajout de suffixe aléatoire
        suffix = f"__{secrets.token_hex(8)}"

        # Construction finale avec préfixe
        name = f"__{homo_part}{suffix}__"

        # Évite les collisions
        while name in self.used_names:
            name += self.gen_chaotic_identifier(10, 15)
        self.used_names.add(name)

        return name

    def rolling_xor_encrypt(self, data: bytes, chunk_size: int = 64) -> Tuple[str, int]:
        """Chiffrement XOR rolling avec clé dynamique par chunk + compression zlib."""
        key = secrets.randbits(8)
        out = bytearray()
        current_key = key

        for i, b in enumerate(data):
            out.append(b ^ current_key)
            current_key = (current_key * 31 + i + 1) % 256

            # En mode stealth, on modifie la clé tous les chunks
            if self.stealth_mode and i % chunk_size == 0:
                current_key ^= int(hashlib.sha256(out[-chunk_size:]).hexdigest()[:2], 16)

        # Compression finale
        compressed = zlib.compress(bytes(out), level=9)
        return base64.urlsafe_b64encode(compressed).decode(), key

    def inject_dead_code(self, code: str, density: float = 0.3) -> str:
        """Injecte des snippets de code mort aléatoires."""
        lines = code.split('\n')
        if not lines:
            return code

        # Détermine le nombre de lignes à injecter
        inject_count = max(1, int(len(lines) * density))
        inject_positions = sorted(random.sample(range(len(lines) + 1), inject_count))

        # Insertion
        result = []
        pos = 0
        for i, line in enumerate(lines):
            while pos < len(inject_positions) and inject_positions[pos] == i:
                result.append(random.choice(self.dead_snippets))
                pos += 1
            result.append(line)

        # Ajoute les restes
        while pos < len(inject_positions):
            result.append(random.choice(self.dead_snippets))
            pos += 1

        return '\n'.join(result)

    def unicode_escape_obfuscate(self, code: str) -> str:
        """Obfuscation via unicode escape sequences."""
        obfuscated = []
        for char in code:
            if random.random() < 0.15:  # 15% de chance d'obfusquer le caractère
                obfuscated.append(f"\\u{ord(char):04x}")
            else:
                obfuscated.append(char)
        return ''.join(obfuscated)

    def string_slicing_obfuscate(self, code: str) -> str:
        """Obfuscation via string slicing dynamique."""
        lines = code.split('\n')
        obfuscated_lines = []

        for line in lines:
            if len(line.strip()) == 0 or line.strip().startswith(('#', '//')):
                obfuscated_lines.append(line)
                continue

            # Découpe les mots en slices aléatoires
            words = line.split()
            obfuscated_words = []

            for word in words:
                if len(word) < 4 or any(c in word for c in '()[]{}:.,;'):
                    obfuscated_words.append(word)
                    continue

                # Génère une expression de slicing complexe
                slices = []
                start = 0
                while start < len(word):
                    end = min(start + random.randint(1, 3), len(word))
                    slices.append(f"{word[start:end]}")
                    start = end

                if len(slices) > 1:
                    obfuscated_word = '+' + '+'.join(
                        f"'{s}'" if random.random() < 0.5 else f"{word}.__getitem__(slice({word.find(s)}, {word.find(s)+len(s)}))"
                        for s in slices
                    )
                    obfuscated_words.append(obfuscated_word)
                else:
                    obfuscated_words.append(word)

            obfuscated_lines.append(' '.join(obfuscated_words))

        return '\n'.join(obfuscated_lines)

    def base64_marshal_obfuscate(self, code: str) -> str:
        """Obfuscation via marshal + base64 (niveau maximal)."""
        try:
            # Compile le code en bytecode
            compiled = compile(code, '<string>', 'exec')

            # Sérialise avec marshal
            marshalled = marshal.dumps(compiled)

            # Compresse et encode
            compressed = zlib.compress(marshalled, level=9)
            encoded = base64.urlsafe_b64encode(compressed).decode()

            # Génère un loader dynamique
            loader = f"""
import base64, zlib, marshal, types
exec(marshal.loads(zlib.decompress(base64.urlsafe_b64decode({encoded!r}))), {{'__builtins__': __builtins__}}))
"""
            return loader
        except:
            return code  # Fallback silencieux

    def obfuscate(self, input_file: str, output_file: str = None, mode: str = 'extreme') -> str:
        """
        Obfuscation complète d'un script Python.
        Modes disponibles: 'light', 'medium', 'hard', 'extreme'
        """
        if not Path(input_file).exists():
            raise FileNotFoundError(f"Fichier {input_file} introuvable")

        with open(input_file, 'r', encoding='utf-8') as f:
            original_code = f.read()

        # Applique les transformations selon le mode
        if mode == 'extreme':
            code = self.base64_marshal_obfuscate(original_code)
            code = self.inject_dead_code(code, density=0.4)
            code = self.unicode_escape_obfuscate(code)
            code = self.string_slicing_obfuscate(code)
        elif mode == 'hard':
            code = self.inject_dead_code(original_code, density=0.3)
            code = self.string_slicing_obfuscate(code)
            code = self.unicode_escape_obfuscate(code)
        elif mode == 'medium':
            code = self.inject_dead_code(original_code, density=0.2)
            code = self.unicode_escape_obfuscate(code)
        else:  # light
            code = self.inject_dead_code(original_code, density=0.1)

        # Remplacement des noms de variables/fonctions
        if mode in ('hard', 'extreme'):
            code = self._obfuscate_identifiers(code)

        # Ajout d'un header anti-analyse
        header = f"""# Obfuscated by EpSiLoNPoInTFuCK v5.1 (God-Tier 2026)
# Seed: {self.seed}
# Timestamp: {int(time.time())}
# Warning: This file is protected by anti-debug and anti-tamper mechanisms
# Any attempt to analyze or modify this code will trigger self-destruct sequences

import sys, time, random, hashlib, secrets
if hasattr(sys, '_getframe') and sys._getframe().f_back:
    if random.random() < 0.01:  # 1% de chance de déclencher un faux positif
        print("DEBUG DETECTED - Self-destruct initiated")
        sys.exit(1)

# Anti-sandbox delay
time.sleep(random.uniform(0.1, 0.5))
"""
        code = header + code

        # Sauvegarde
        output_file = output_file or f"obfuscated_{Path(input_file).name}"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(code)

        return output_file

    def _obfuscate_identifiers(self, code: str) -> str:
        """Remplace tous les identifiants par des noms chaotiques."""
        import tokenize
        from io import BytesIO

        # Analyse le code pour trouver les identifiants
        tokens = []
        try:
            for tok in tokenize.tokenize(BytesIO(code.encode('utf-8')).readline):
                tokens.append((tok.type, tok.string, tok.start, tok.end))
        except:
            return code

        # Génère une mapping des identifiants à remplacer
        identifier_map = {}
        for token_type, string, _, _ in tokens:
            if token_type == tokenize.NAME and string not in {
                'and', 'as', 'assert', 'break', 'class', 'continue', 'def', 'del',
                'elif', 'else', 'except', 'finally', 'for', 'from', 'global', 'if',
                'import', 'in', 'is', 'lambda', 'nonlocal', 'not', 'or', 'pass',
                'raise', 'return', 'try', 'while', 'with', 'yield', 'True', 'False', 'None'
            }:
                if string not in identifier_map:
                    identifier_map[string] = self.gen_chaotic_identifier()

        # Remplace dans le code
        new_code = code
        for old, new in identifier_map.items():
            # Évite les remplacements partiels
            if len(old) > 2:  # Ne remplace pas les noms trop courts
                new_code = re.sub(r'\b' + re.escape(old) + r'\b', new, new_code)

        return new_code

    def generate_anti_debug(self) -> str:
        """Génère du code anti-debug dynamique."""
        techniques = [
            # 1. Vérification des frames
            """if hasattr(sys, '_getframe'):
    if sys._getframe().f_back:
        print("DEBUGGER DETECTED")
        sys.exit(1)""",

            # 2. Vérification du temps d'exécution
            f"""start_time = time.time()
if (time.time() - start_time) > 0.5:  # {random.uniform(0.1, 0.8):.2f} seconds threshold
    print("SANDBOX DETECTED - Execution too slow")
    sys.exit(1)""",

            # 3. Vérification des modules suspects
            """suspect_modules = ['pdb', 'pydevd', 'IPython', 'ptvsd']
for module in suspect_modules:
    if module in sys.modules:
        print(f"DEBUG MODULE DETECTED: {module}")
        sys.exit(1)""",

            # 4. Vérification des arguments
            """if len(sys.argv) > 1 and any(arg.lower() in ('--debug', '-d', '--pdb') for arg in sys.argv):
    print("DEBUG ARGUMENTS DETECTED")
    sys.exit(1)""",

            # 5. Vérification des variables d'environnement
            """debug_envs = ['PYDEV_DEBUG', 'WERKZEUG_DEBUG_PIN', 'FLASK_DEBUG']
for env in debug_envs:
    if env in os.environ:
        print(f"DEBUG ENV DETECTED: {env}")
        sys.exit(1)""",

            # 6. Piège à exceptions
            """try:
    raise ZeroDivisionError
except:
    if sys.exc_info()[2].tb_frame.f_back:
        print("DEBUGGER TRAP TRIGGERED")
        sys.exit(1)""",

            # 7. Vérification des attributs Python
            """if hasattr(sys, 'gettrace') and sys.gettrace() is not None:
    print("TRACER DETECTED")
    sys.exit(1)""",

            # 8. Vérification des signaux
            """import signal
def anti_signal(*args):
    print("SIGNAL TRAP TRIGGERED")
    sys.exit(1)
signal.signal(signal.SIGINT, anti_signal)
signal.signal(signal.SIGTERM, anti_signal)"""
        ]

        selected = random.sample(techniques, min(3, len(techniques)))
        return "\n".join(selected)

    def add_stealth_features(self, code: str) -> str:
        """Ajoute des fonctionnalités furtives avancées."""
        features = [
            # 1. Délai aléatoire anti-sandbox
            f"time.sleep({random.uniform(0.1, 0.8):.3f})",

            # 2. Vérification de l'environnement
            """if not hasattr(sys, 'argv'):
    sys.exit(1)""",

            # 3. Vérification des modules de base
            """required_modules = ['sys', 'time', 'random']
for module in required_modules:
    if module not in sys.modules:
        __import__(module)""",

            # 4. Protection contre l'import
            """if __name__ != '__main__':
    print("DIRECT EXECUTION REQUIRED")
    sys.exit(1)""",

            # 5. Vérification de l'intégrité
            """import hashlib
current_hash = hashlib.sha256(open(__file__, 'rb').read()).hexdigest()
if current_hash != '{hashlib.sha256(code.encode()).hexdigest()}':
    print("FILE TAMPERING DETECTED")
    sys.exit(1)""",

            # 6. Brouillage des traces
            """import gc
gc.collect()
for i in range(1, 4):
    try:
        del sys.modules[f'_obfuscated_module_{i}']
    except:
        pass""",

            # 7. Protection mémoire
            """import ctypes
try:
    ctypes.pythonapi.Py_MemoryView_FromMemory(
        ctypes.py_object(bytes), id(bytes), len(bytes), ctypes.py_object(None)
    )
except:
    pass"""
        ]

        selected = random.sample(features, min(2, len(features)))
        return code + "\n\n# === STEALTH FEATURES ===\n" + "\n".join(selected)

# --- Fonction Principale ---
def main():
    import argparse
    parser = argparse.ArgumentParser(description='EpSiLoNPoInTFuCK v5.1 - Obfuscateur Ultra-Avancé')
    parser.add_argument('input_file', help='Fichier Python à obfusquer')
    parser.add_argument('-o', '--output', help='Fichier de sortie (optionnel)')
    parser.add_argument('-m', '--mode', choices=['light', 'medium', 'hard', 'extreme'],
                         default='extreme', help='Niveau d\'obfuscation (default: extreme)')
    parser.add_argument('-s', '--stealth', action='store_true', help='Active le mode stealth (anti-détection)')
    parser.add_argument('-d', '--dead-code', type=float, default=0.3,
                         help='Densité de code mort à injecter (0.0-1.0)')
    args = parser.parse_args()

    print(f"""{Fore.CYAN}
╔════════════════════════════════════════════════════════════════════════════════════════════════════
CVE-2026-23550 EXPLOIT OBFUSCATION ACTIVE{Style.RESET_ALL}
╚════════════════════════════════════════════════════════════════════════════════════════════════════""")
