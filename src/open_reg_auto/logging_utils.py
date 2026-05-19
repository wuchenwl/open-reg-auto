from __future__ import annotations

from datetime import datetime


def log(text: str) -> None:
    print(f"{datetime.now().strftime('%H:%M:%S')} {text}")
