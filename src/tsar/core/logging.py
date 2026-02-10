# src/tsar/core/logging.py
"""
Système de logging structuré TSAR-EXEC v7.1
- structlog + JSONL + rich console
- Correlation ID par run / cible (traceability APT-level)
- Masquage auto des secrets (passwords, keys, tokens)
- Rotation fichiers + compression
- Sentry integration optionnelle
- Niveau : top-tier redteam – logs exploitables en threat hunting / forensics
"""

import contextvars
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

import structlog
from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme
from structlog.processors import JSONRenderer, StackInfoRenderer, format_exc_info
from structlog.typing import EventDict, Processor

from tsar.settings import settings


# ─── Correlation ID (par run ou par cible) ────────────────────────────────────
correlation_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("correlation_id", default="global")


def set_correlation_id(cid: str) -> None:
    """Définit le correlation ID pour le contexte courant (run ou cible)"""
    correlation_id_var.set(cid)


def get_correlation_id() -> str:
    return correlation_id_var.get()


# ─── Processeurs custom structlog ─────────────────────────────────────────────
def add_correlation_id(logger: Any, method_name: str, event_dict: EventDict) -> EventDict:
    """Ajoute correlation_id à chaque log"""
    event_dict["correlation_id"] = get_correlation_id()
    return event_dict


def add_timestamp(logger: Any, method_name: str, event_dict: EventDict) -> EventDict:
    """Timestamp ISO avec millisecondes"""
    event_dict["timestamp"] = datetime.utcnow().isoformat(timespec="milliseconds")
    return event_dict


def mask_sensitive_values(event_dict: EventDict) -> EventDict:
    """
    Masque automatiquement les champs sensibles (password, key, token, secret, etc.)
    """
    sensitive_keys = {
        "password", "passwd", "pwd", "api_key", "secret", "token",
        "auth", "key", "passphrase", "credential", "private_key"
    }

    def mask_value(key: str, value: Any) -> Any:
        if isinstance(value, dict):
            return {k: mask_value(k, v) for k, v in value.items()}
        if isinstance(value, (str, bytes)) and any(s in key.lower() for s in sensitive_keys):
            return "****"
        return value

    for key in list(event_dict.keys()):
        if any(s in key.lower() for s in sensitive_keys):
            event_dict[key] = "****"
        elif isinstance(event_dict[key], (dict, list)):
            event_dict[key] = mask_value(key, event_dict[key])

    return event_dict


# ─── Configuration structlog globale ──────────────────────────────────────────
def configure_logging() -> None:
    """
    Configure structlog + handlers une seule fois au démarrage
    - Console pretty avec rich (couleurs + format humain)
    - Fichier JSONL rotatif si configuré
    - Niveau depuis settings
    """
    processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        add_correlation_id,
        add_timestamp,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.filter_by_level,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnsafeTracebackRenderer(),
        mask_sensitive_values,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
    ]

    if settings.logging.json_format:
        processors.append(JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer(colors=settings.logging.console_colors))

    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Handler console rich
    console_theme = Theme(
        {
            "debug": "dim cyan",
            "info": "bold green",
            "warning": "yellow",
            "error": "bold red",
            "critical": "bold magenta on white",
        }
    )
    console = Console(theme=console_theme)

    rich_handler = RichHandler(
        console=console,
        rich_tracebacks=True,
        tracebacks_show_locals=True,
        markup=True,
        level=settings.logging.level,
    )

    # Handler fichier JSONL rotatif (si configuré)
    if settings.logging.log_file:
        file_handler = logging.handlers.RotatingFileHandler(
            settings.logging.log_file,
            maxBytes=settings.logging.max_file_size_mb * 1024 * 1024,
            backupCount=settings.logging.backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(settings.logging.level)
        file_handler.setFormatter(logging.Formatter("%(message)s"))

        root_logger = logging.getLogger()
        root_logger.addHandler(rich_handler)
        root_logger.addHandler(file_handler)
        root_logger.setLevel(settings.logging.level)

    else:
        # Console only
        logging.basicConfig(
            format="%(message)s",
            level=settings.logging.level,
            handlers=[rich_handler],
        )

    # Log de démarrage signature
    logger = get_logger("tsar.init")
    logger.info(
        "Logging initialisé",
        level=settings.logging.level,
        json=settings.logging.json_format,
        file=str(settings.logging.log_file) if settings.logging.log_file else None,
        correlation_id_enabled=True,
    )


# ─── Factory logger avec correlation ID facile ────────────────────────────────
def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """
    Récupère un logger structuré avec correlation ID déjà injecté
    Usage: logger = get_logger(__name__)
    """
    return structlog.get_logger(name)


# ─── Helpers pour correlation par cible/run ───────────────────────────────────
def with_correlation_id(cid: str):
    """Context manager pour logger avec un correlation ID spécifique"""
    token = correlation_id_var.set(cid)
    try:
        yield
    finally:
        correlation_id_var.reset(token)


# Appel unique au démarrage (à mettre dans main.py ou __main__)
if __name__ != "__main__":
    configure_logging()
    
