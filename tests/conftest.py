# tests/conftest.py
"""
Fixtures globales pour les tests TSAR-EXEC v7.1
- Isolation maximale (mock requests, filesystem, env)
- Fixtures pour settings, proxies, Tor, HTTP sessions
- Markers custom : @pytest.mark.online, @pytest.mark.slow, @pytest.mark.integration
- Async support via pytest-asyncio
- Niveau : boutique redteam – zéro side-effect, zéro appel réseau non contrôlé
"""

import json
from pathlib import Path
from typing import Any, AsyncGenerator, Generator

import httpx
import pytest
import pytest_asyncio
import respx
from _pytest.fixtures import FixtureRequest
from pydantic import SecretStr

from tsar.settings import ProxyConfig, TsarSettings


# ─── Markers custom ───────────────────────────────────────────────────────────
def pytest_configure(config: Any) -> None:
    config.addinivalue_line("markers", "online: tests nécessitant un accès réseau réel")
    config.addinivalue_line("markers", "slow: tests lents (désactiver avec -m 'not slow')")
    config.addinivalue_line("markers", "integration: chaîne complète recon+exploit simulé")
    config.addinivalue_line("markers", "exploit: tests payloads/heavy mocking")


# ─── Settings de test isolés (PAS de pollution globale) ───────────────────────
@pytest.fixture(scope="session")
def test_settings() -> TsarSettings:
    """
    Crée une instance de settings dédiée aux tests :
    - Pas de log fichier
    - Pas de Tor réel
    - Proxy fictif
    - Chemins temporaires /tmp/
    - Isolation complète : ne touche JAMAIS au settings global
    """
    test_base = Path("/tmp/tsar-test-chain")
    test_base.mkdir(parents=True, exist_ok=True)

    settings = TsarSettings(
        # Forcer override sans .env
        model_config=TsarSettings.model_config.copy(update={"env_file": None}),
        execution__max_threads=5,
        execution__default_timeout=3,
        execution__stealth_jitter_min=0.1,
        execution__stealth_jitter_max=0.3,
        logging__level="DEBUG",
        logging__json_format=False,
        logging__log_file=None,
        logging__console_colors=True,
        security__anti_debug=False,
        security__anti_sandbox_checks=False,
        tor__enabled=False,
        paths__base_dir=test_base,
        paths__chain_dir=test_base / "chain",
        paths__input_dir=test_base / "chain/input",
        paths__docked_dir=test_base / "chain/docked",
        paths__vlun_dir=test_base / "chain/VLUN",
        paths__shells_dir=test_base / "chain/VLUN_Sh",
        paths__logs_dir=test_base / "chain/logs",
        paths__targets_file=test_base / "chain/input/targets.txt",
        paths__proxies_file=test_base / "chain/input/proxies.txt",
        paths__bypass_payloads=test_base / "bypass_payloads.txt",
        proxies=[
            ProxyConfig(
                url="http://mock.proxy:8080",
                username=SecretStr("testuser"),
                password=SecretStr("testpass"),
                weight=1.0,
                timeout=2,
            )
        ],
    )

    yield settings

    # Nettoyage session-level
    import shutil
    shutil.rmtree(test_base, ignore_errors=True)


# ─── Injection settings dans les modules qui en ont besoin ────────────────────
@pytest.fixture(autouse=True)
def inject_test_settings(monkeypatch: pytest.MonkeyPatch, test_settings: TsarSettings):
    """
    Injecte proprement la config de test dans le module settings
    → Pas de variable globale modifiée directement
    """
    import tsar.settings

    monkeypatch.setattr(tsar.settings, "settings", test_settings)


# ─── Mock HTTP (isolation réseau 100%) ────────────────────────────────────────
@pytest.fixture
def mock_http() -> Generator[respx.Router, None, None]:
    """Mock synchrone httpx via respx – tous les appels sont interceptés"""
    with respx.mock as router:
        yield router


@pytest_asyncio.fixture
async def mock_async_http() -> AsyncGenerator[respx.Router, None]:
    """Mock asynchrone httpx via respx – instance explicite"""
    router = respx.mock()
    async with router:
        yield router


@pytest.fixture
def fake_httpx_client(mock_http: respx.Router) -> httpx.Client:
    return httpx.Client(transport=httpx.HTTPTransport(mock_http))


@pytest_asyncio.fixture
async def fake_async_httpx_client(mock_async_http: respx.Router) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(mock_async_http))


# ─── Fixtures données de test ─────────────────────────────────────────────────
@pytest.fixture(scope="session")
def sample_target_dict() -> dict[str, Any]:
    return {
        "url": "https://example-vuln.local",
        "ip": "192.0.2.1",
        "version": "2.5.1",
        "risk_score": 92,
        "endpoints": [
            "/wp-admin/admin-ajax.php?action=modular_ds_auth_bypass",
            "/api/modular-connector/login/?origin=mo",
        ],
        "vulnerabilities": [{"cve": "CVE-2026-23550", "severity": "critical"}],
    }


@pytest.fixture(scope="session")
def sample_docked_json(sample_target_dict: dict) -> str:
    return json.dumps([sample_target_dict])


@pytest.fixture
def temp_targets_file(test_settings: TsarSettings, sample_docked_json: str) -> Path:
    file = test_settings.paths.targets_file
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text("https://test1.local\nhttps://test2.local\n")
    yield file
    file.unlink(missing_ok=True)


@pytest.fixture
def temp_proxies_file(test_settings: TsarSettings) -> Path:
    file = test_settings.paths.proxies_file
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(
        "socks5://user:pass@proxy1.local:1080\n"
        "http://proxy2.local:8080\n"
        "# comment\n"
    )
    yield file
    file.unlink(missing_ok=True)


# ─── Skip automatique intelligent ─────────────────────────────────────────────
@pytest.fixture(autouse=True)
def skip_marked_tests(request: FixtureRequest):
    """
    Auto-skip si marqué online/slow et options non activées
    """
    if "online" in request.keywords and not request.config.getoption("--run-online"):
        pytest.skip("Test online – utiliser --run-online")
    if "slow" in request.keywords and not request.config.getoption("--run-slow"):
        pytest.skip("Test lent – utiliser --run-slow")


def pytest_addoption(parser):
    parser.addoption("--run-online", action="store_true", default=False, help="Exécuter les tests réseau réels")
    parser.addoption("--run-slow", action="store_true", default=False, help="Exécuter les tests lents")

