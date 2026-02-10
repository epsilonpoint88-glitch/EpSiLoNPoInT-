# src/tsar/core/models.py
"""
Modèles Pydantic centraux TSAR-EXEC v7.1
- Tous les objets métier (Target, ExploitResult, RiskScore, Payload, etc.)
- Validation stricte + coercion + exemples JSON embeddés
- Discriminants pour polymorphismes (ex: différents types de payloads)
- Calculs dérivés (risk_score pondéré, severity mapping)
- Immutabilité partielle (frozen sur champs critiques)
- Niveau : top-tier threat intel – prêt pour sérialisation, validation API, logs structurés
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Union

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
    computed_field,
)

from tsar.settings import settings


class SeverityLevel(str, Enum):
    """Niveaux de sévérité CVSS-like"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Vulnerability(BaseModel):
    """Représentation d'une vulnérabilité détectée"""

    cve: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,7}$")
    severity: SeverityLevel
    description: str = Field(..., min_length=10)
    cvss_score: float = Field(..., ge=0.0, le=10.0)
    exploitability: float = Field(..., ge=0.0, le=10.0, description="Score exploitabilité EPSS-like")
    detected_at: datetime = Field(default_factory=datetime.utcnow)

    model_config = ConfigDict(frozen=True, extra="forbid")


class EndpointStatus(str, Enum):
    """Statuts possibles d'un endpoint"""

    VERIFIED = "verified"
    POTENTIAL = "potential"
    BLOCKED = "blocked"
    TIMEOUT = "timeout"
    ERROR = "error"


class Endpoint(BaseModel):
    """Endpoint détecté sur la cible"""

    path: str = Field(..., min_length=1)
    method: Literal["GET", "POST", "HEAD", "OPTIONS"] = "GET"
    params: Dict[str, Any] = Field(default_factory=dict)
    status: EndpointStatus = EndpointStatus.POTENTIAL
    response_code: Optional[int] = None
    fingerprint: Optional[str] = None  # ex: "modular_ds_v2.5.1"

    @computed_field
    @property
    def full_url(self) -> str:
        return f"{settings.execution.target_base_url.rstrip('/')}{self.path.lstrip('/')}"


class Target(BaseModel):
    """Cible principale (docked ou en recon)"""

    url: str = Field(..., pattern=r"^https?://[^\s/\( .?#].[^\s]* \)")
    ip: Optional[str] = Field(None, pattern=r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
    country_code: Optional[str] = Field(None, pattern=r"^[A-Z]{2}$")
    asn: Optional[str] = None
    version_detected: Optional[str] = Field(None, pattern=r"^\d+\.\d+\.\d+$")
    wp_detected: bool = False
    modular_ds_detected: bool = False
    waf_detected: bool = False
    endpoints: List[Endpoint] = Field(default_factory=list)
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    risk_score: float = Field(0.0, ge=0.0, le=100.0)
    docked_at: datetime = Field(default_factory=datetime.utcnow)
    last_checked: Optional[datetime] = None
    status: Literal["pending", "docked", "exploited", "failed", "patched"] = "pending"

    @field_validator("risk_score", mode="after")
    @classmethod
    def compute_risk_score(cls, v: float, info) -> float:
        """Calcul pondéré automatique si non fourni"""
        if v > 0:
            return v  # déjà fourni

        score = 0.0
        data = info.data

        if data.get("wp_detected"):
            score += 10
        if data.get("modular_ds_detected"):
            score += 40
        if data.get("version_detected", "").startswith("2.5."):
            score += 50
        if data.get("endpoints"):
            score += 20 * len(data["endpoints"])
        if data.get("waf_detected"):
            score -= 30
        if data.get("vulnerabilities"):
            score += sum(v.cvss_score for v in data["vulnerabilities"])

        return min(max(score, 0.0), 100.0)

    @model_validator(mode="after")
    def update_status(self) -> "Target":
        if self.vulnerabilities and any(v.severity == SeverityLevel.CRITICAL for v in self.vulnerabilities):
            self.status = "docked"
        return self

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "url": "https://target-vuln.fr",
                    "ip": "185.220.101.12",
                    "country_code": "FR",
                    "version_detected": "2.5.1",
                    "wp_detected": True,
                    "modular_ds_detected": True,
                    "endpoints": [
                        {"path": "/api/modular-connector/login/?origin=mo", "method": "GET", "status": "verified"}
                    ],
                    "vulnerabilities": [
                        {
                            "cve": "CVE-2026-23550",
                            "severity": "critical",
                            "description": "Auth bypass via modular_ds_upload",
                            "cvss_score": 10.0,
                            "exploitability": 9.8,
                        }
                    ],
                    "risk_score": 95.0,
                    "status": "docked",
                }
            ]
        }
    )


class PayloadType(str, Enum):
    BASIC = "basic"
    OBFUSCATED = "obfuscated"
    POLYMORPHIC = "polymorphic"
    FILELESS = "fileless"
    LOTL = "lotl"


class Payload(BaseModel):
    """Payload d'exploitation (webshell, RCE, etc.)"""

    name: str = Field(..., min_length=3)
    type: PayloadType
    content: str = Field(..., min_length=10)
    obfuscated: bool = False
    size: int = Field(..., ge=1)
    description: str = ""
    success_markers: List[str] = Field(default_factory=list)  # ex: "W.P.E.F|Poloss"
    bypass_techniques: List[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=datetime.utcnow)

    model_config = ConfigDict(frozen=True)


class ExploitResult(BaseModel):
    """Résultat d'une tentative d'exploitation"""

    target_url: str
    payload_used: Payload
    success: bool
    shell_url: Optional[str] = None
    beacon_received: bool = False
    http_status: Optional[int] = None
    response_snippet: Optional[str] = None
    error: Optional[str] = None
    executed_at: datetime = Field(default_factory=datetime.utcnow)
    duration_ms: Optional[float] = None

    @computed_field
    @property
    def summary(self) -> str:
        if self.success:
            return f"[SUCCESS] {self.target_url} → {self.shell_url or 'beacon OK'}"
        return f"[FAIL] {self.target_url} → {self.error or 'no response'}"

    model_config = ConfigDict(json_encoders={datetime: lambda v: v.isoformat()})


class StatsSummary(BaseModel):
    """Statistiques globales du pipeline"""

    total_targets: int = 0
    docked: int = 0
    exploited: int = 0
    shells_live: int = 0
    success_rate: float = 0.0
    avg_risk_score: float = 0.0
    waf_bypassed: int = 0
    last_updated: datetime = Field(default_factory=datetime.utcnow)

