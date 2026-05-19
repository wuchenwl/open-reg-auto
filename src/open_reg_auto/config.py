from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BASE_DIR / "data"
LOG_DIR = BASE_DIR / "logs"


@dataclass
class MailConfig:
    request_timeout: int = 30
    wait_timeout: int = 30
    wait_interval: int = 2
    providers: list[dict] = field(default_factory=list)
    proxy: str = ""


@dataclass
class RegisterConfig:
    proxy: str = ""
    total: int = 1
    threads: int = 1
    mail: MailConfig = field(default_factory=MailConfig)


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
