# src/tsar/settings.py
"""
Configuration centralisée TSAR-EXEC v7.1
- pydantic-settings v2 (pas de dotenv manuel ni os.getenv brut)
- Typage strict partout
- Validation + coercion automatique
- Support .env + variables d'environnement + defaults sécurisés
- Secrets masqués dans les repr/logs
- Niveau : top-tier redteam (aucune fuite accidentelle possible)
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal, Optional, Union

from pydantic import (
    AnyHttpUrl,
    BaseModel,
    Field,
    HttpUrl,
    IPvAnyAddress,
    PositiveInt,
    SecretStr,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict


class ProxyConfig(BaseModel):
    """Configuration d'un proxy individuel (HTTP/SOCKS5)"""

    url: AnyHttpUrl | str = Field(..., description="URL complète du proxy (ex: socks5://user:pass@host:1080)")
    weight: float = Field(1.0, ge=0.1, le=10.0, description="Poids pour la sélection pondérée")
    username: Optional[SecretStr] = None
    password: Optional[SecretStr] = None
    timeout: PositiveInt = 8
    max_errors: PositiveInt = 3
    country_code: Optional[str] = Field(None, pattern=r"^[A-Z]{2}$", description="Code ISO 3166-1 alpha-2")

    @field_validator("url", mode="before")
    @classmethod
    def normalize_proxy_url(cls, v: str) -> str:
        if v.startswith(("http://", "https://", "socks4://", "socks5://")):
            return v
        if "://" not in v:
            return f"http://{v}"
        return v


class TorConfig(BaseModel):
    """Configuration Tor spécifique"""

    enabled: bool = True
    socks_port: PositiveInt = 9050
    control_port: Optional[PositiveInt] = None
    data_directory: Path = Path("/var/lib/tor-tsar")
    torrc_path: Path = Path("/etc/tor/torrc")
    renew_identity_interval: PositiveInt = 600  # secondes
    max_circuit_failures: PositiveInt = 5


class ExecutionConfig(BaseModel):
    """Paramètres d'exécution globale"""

    max_threads: PositiveInt = Field(120, le=300, description="Threads max ThreadPoolExecutor")
    default_timeout: PositiveInt = 12
    stealth_jitter_min: float = Field(1.8, ge=0.5, le=10.0)
    stealth_jitter_max: float = Field(4.5, ge=1.0, le=30.0)
    retry_attempts: PositiveInt = 4
    retry_backoff_multiplier: float = 1.8
    user_agent_rotate: bool = True
    proxy_rotation_enabled: bool = True
    proxy_health_check_interval: PositiveInt = 300  # secondes
    dock_threshold: PositiveInt = Field(70, ge=0, le=100)


class LoggingConfig(BaseModel):
    """Configuration logging structuré"""

    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    json_format: bool = True
    console_colors: bool = True
    log_file: Optional[Path] = Path("chain/logs/tsar.jsonl")
    max_file_size_mb: PositiveInt = 50
    backup_count: PositiveInt = 7
    sentry_dsn: Optional[SecretStr] = None


class SecurityConfig(BaseModel):
    """Paramètres de sécurité / anti-forensic"""

    anti_debug: bool = True
    anti_sandbox_checks: bool = True
    wipe_logs_on_exit: bool = True
    secure_delete_method: Literal["shred", "srm", "zero", "unlink"] = "zero"
    ephemeral_keys: bool = True  # régénère clés XOR/session à chaque run


class PathsConfig(BaseModel):
    """Chemins critiques (relatifs ou absolus)"""

    base_dir: Path = Path(__file__).parent.parent.parent
    chain_dir: Path = Field(default_factory=lambda: Path("chain"))
    input_dir: Path = Field(default_factory=lambda: Path("chain/input"))
    docked_dir: Path = Field(default_factory=lambda: Path("chain/docked"))
    vlun_dir: Path = Field(default_factory=lambda: Path("chain/VLUN"))
    shells_dir: Path = Field(default_factory=lambda: Path("chain/VLUN_Sh"))
    logs_dir: Path = Field(default_factory=lambda: Path("chain/logs"))
    targets_file: Path = Field(default_factory=lambda: Path("chain/input/targets.txt"))
    proxies_file: Path = Field(default_factory=lambda: Path("chain/input/proxies.txt"))
    bypass_payloads: Path = Field(default_factory=lambda: Path("bypass_payloads.txt"))


class TsarSettings(BaseSettings):
    """
    Configuration globale TSAR-EXEC – singleton-like via pydantic-settings
    Priorité : .env > variables d'environnement > defaults
    """

    model_config = SettingsConfigDict(
        env_file=(".env", ".env.local", ".env.secrets"),
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        env_prefix="TSAR_",
        case_sensitive=False,
        extra="ignore",
        protected_namespaces=(),
    )

    # ─── Sections principales ────────────────────────────────────────────────────
    execution: ExecutionConfig = ExecutionConfig()
    logging: LoggingConfig = LoggingConfig()
    security: SecurityConfig = SecurityConfig()
    paths: PathsConfig = PathsConfig()
    tor: TorConfig = TorConfig()

    proxies: list[ProxyConfig] = Field(
        default_factory=list,
        description="Liste des proxies (chargée depuis proxies.txt si vide)"
    )

    # ─── Computed / post-validation ─────────────────────────────────────────────
    @model_validator(mode="after")
    def validate_paths_exist(self) -> "TsarSettings":
        for p in [
            self.paths.chain_dir,
            self.paths.input_dir,
            self.paths.docked_dir,
            self.paths.vlun_dir,
            self.paths.shells_dir,
            self.paths.logs_dir,
        ]:
            p.mkdir(parents=True, exist_ok=True)
        return self

    @model_validator(mode="after")
    def load_proxies_if_empty(self) -> "TsarSettings":
        if not self.proxies and self.paths.proxies_file.is_file():
            with self.paths.proxies_file.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith(("#", "//")):
                        try:
                            self.proxies.append(ProxyConfig(url=line))
                        except Exception as e:
                            print(f"[WARNING] Proxy invalide ignoré : {line} → {e}")
        return self

    @model_validator(mode="after")
    def validate_jitter(self) -> "TsarSettings":
        if self.execution.stealth_jitter_min > self.execution.stealth_jitter_max:
            raise ValueError("stealth_jitter_min doit être ≤ stealth_jitter_max")
        return self

    def __repr__(self) -> str:
        """Masque les secrets dans les logs/repr"""
        data = self.model_dump(mode="json")
        if "proxies" in data:
            for p in data["proxies"]:
                if "username" in p:
                    p["username"] = "****"
                if "password" in p:
                    p["password"] = "****"
        if "tor" in data and "password" in data["tor"]:
            data["tor"]["password"] = "****"
        return f"TsarSettings({data})"


# Singleton global – à importer partout
settings = TsarSettings()
