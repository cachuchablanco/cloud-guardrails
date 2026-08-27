from __future__ import annotations

from pathlib import Path

import pytest

from cloud_guardrails.models import ScanResult
from cloud_guardrails.scanner import scan

ROOT = Path(__file__).resolve().parents[1]
INSECURE = ROOT / "fixtures" / "insecure"
SECURE = ROOT / "fixtures" / "secure"


@pytest.fixture(scope="session")
def insecure() -> ScanResult:
    return scan(INSECURE)


@pytest.fixture(scope="session")
def secure() -> ScanResult:
    return scan(SECURE)
