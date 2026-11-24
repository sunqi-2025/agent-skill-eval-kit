"""Synthetic compliant script fixture for testing skill_auditor.py."""
import os
from typing import Iterable, List


def check_required_keys(payload: dict, required_keys: Iterable[str]) -> List[str]:
    return [k for k in required_keys if k not in payload or payload[k] in (None, "")]


def get_token_from_env() -> str:
    return os.environ.get("API_TOKEN", "")
