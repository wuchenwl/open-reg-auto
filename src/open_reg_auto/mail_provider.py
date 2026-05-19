from __future__ import annotations

import random
import re
import string
import time
from typing import Any

import requests


CODE_PATTERNS = [
    re.compile(r"\b(\d{6})\b"),
    re.compile(r"code[^\d]{0,10}(\d{6})", re.I),
    re.compile(r"verification[^\d]{0,10}(\d{6})", re.I),
]


def _request(method: str, url: str, *, timeout: int = 30, **kwargs):
    return requests.request(method.upper(), url, timeout=timeout, **kwargs)


def _extract_code(text: str) -> str | None:
    content = str(text or "")
    for pattern in CODE_PATTERNS:
        match = pattern.search(content)
        if match:
            return match.group(1)
    return None


def _random_local_part(length: int = 10) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "oc" + "".join(random.choice(alphabet) for _ in range(length))


def _create_1secmail_mailbox(username: str | None = None) -> dict[str, Any]:
    login = (username or _random_local_part()).strip().lower()
    domain = random.choice(["1secmail.com", "1secmail.org", "1secmail.net"])
    return {
        "provider": "1secmail",
        "email": f"{login}@{domain}",
        "login": login,
        "domain": domain,
    }


def _maliapi_request(base_url: str, api_key: str, method: str, path: str, *, timeout: int = 30, json_body: dict | None = None, params: dict | None = None):
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
    }
    if api_key:
        headers["X-API-Key"] = api_key
    resp = _request(method, f"{base_url.rstrip('/')}{path}", timeout=timeout, headers=headers, json=json_body, params=params)
    try:
        payload = resp.json()
    except Exception:
        payload = {}
    if resp.status_code >= 400:
        if isinstance(payload, dict):
            msg = str(payload.get("error") or payload or resp.text).strip()
            code = str(payload.get("errorCode") or "").strip()
            raise RuntimeError(f"MaliAPI 请求失败: {msg}{f' ({code})' if code else ''}")
        raise RuntimeError(f"MaliAPI 请求失败: HTTP {resp.status_code}")
    if isinstance(payload, dict) and "data" in payload:
        return payload.get("data")
    return payload


def _create_maliapi_mailbox(provider: dict[str, Any], username: str | None = None) -> dict[str, Any]:
    api_key = str(provider.get("api_key") or "").strip()
    if not api_key:
        raise RuntimeError("MaliAPI 未配置 api_key")
    base_url = str(provider.get("base_url") or "https://maliapi.215.im/v1").strip()
    body: dict[str, Any] = {}
    domain = str(provider.get("domain") or "").strip()
    strategy = str(provider.get("auto_domain_strategy") or "").strip()
    if domain:
        body["domain"] = domain
    if strategy:
        body["autoDomainStrategy"] = strategy
    if username:
        body["name"] = username.strip().lower()
    data = _maliapi_request(base_url, api_key, "post", "/accounts", json_body=body)
    if not isinstance(data, dict):
        raise RuntimeError(f"MaliAPI 返回异常: {data}")
    email = str(data.get("address") or data.get("email") or "").strip()
    if not email:
        raise RuntimeError(f"MaliAPI 返回空邮箱: {data}")
    return {
        "provider": "maliapi",
        "email": email,
        "account_id": str(data.get("id") or "").strip(),
        "temp_token": str(data.get("tempToken") or data.get("temp_token") or data.get("token") or "").strip(),
        "base_url": base_url,
        "api_key": api_key,
    }


def _wait_1secmail_code(mailbox: dict[str, Any], timeout: int, interval: int) -> str | None:
    login = str(mailbox.get("login") or "").strip()
    domain = str(mailbox.get("domain") or "").strip()
    if not login or not domain:
        return None
    started = time.time()
    while time.time() - started <= timeout:
        resp = _request(
            "get",
            "https://www.1secmail.com/api/v1/",
            params={"action": "getMessages", "login": login, "domain": domain},
        )
        if resp.status_code == 200:
            try:
                items = resp.json()
            except Exception:
                items = []
            for item in items if isinstance(items, list) else []:
                msg_id = item.get("id")
                if not msg_id:
                    continue
                detail = _request(
                    "get",
                    "https://www.1secmail.com/api/v1/",
                    params={"action": "readMessage", "login": login, "domain": domain, "id": msg_id},
                )
                if detail.status_code != 200:
                    continue
                try:
                    data = detail.json()
                except Exception:
                    data = {}
                text = "\n".join(
                    [
                        str(data.get("subject") or ""),
                        str(data.get("textBody") or ""),
                        str(data.get("htmlBody") or ""),
                    ]
                )
                code = _extract_code(text)
                if code:
                    return code
        time.sleep(max(1, interval))
    return None


def create_mailbox(config: dict[str, Any], username: str | None = None) -> dict[str, Any]:
    providers = config.get("providers") if isinstance(config, dict) else None
    if isinstance(providers, list) and providers:
        provider = providers[0] if isinstance(providers[0], dict) else {}
        provider_type = str(provider.get("type") or "").strip().lower()
        if provider_type == "maliapi":
            return _create_maliapi_mailbox(provider, username=username)
        if provider_type == "1secmail":
            return _create_1secmail_mailbox(username=username)
    return _create_1secmail_mailbox(username=username)


def _wait_maliapi_code(mailbox: dict[str, Any], timeout: int, interval: int) -> str | None:
    api_key = str(mailbox.get("api_key") or "").strip()
    base_url = str(mailbox.get("base_url") or "https://maliapi.215.im/v1").strip()
    email = str(mailbox.get("email") or "").strip()
    if not api_key or not email:
        return None
    started = time.time()
    seen: set[str] = set()
    while time.time() - started <= timeout:
        data = _maliapi_request(base_url, api_key, "get", "/messages", params={"address": email}, timeout=timeout)
        messages = data.get("messages", []) if isinstance(data, dict) else data
        for item in messages if isinstance(messages, list) else []:
            message_id = str(item.get("id") or "").strip()
            if not message_id or message_id in seen:
                continue
            seen.add(message_id)
            detail = _maliapi_request(base_url, api_key, "get", f"/messages/{message_id}", timeout=timeout)
            if isinstance(detail, dict) and isinstance(detail.get("message"), dict):
                detail = detail.get("message")
            text = "\n".join([
                str((detail or {}).get("subject") or item.get("subject") or ""),
                str((detail or {}).get("text") or ""),
                str((detail or {}).get("html") or ""),
                str(item.get("snippet") or ""),
            ])
            code = _extract_code(text)
            if code:
                return code
        time.sleep(max(1, interval))
    return None


def wait_for_code(config: dict[str, Any], mailbox: dict[str, Any]) -> str | None:
    timeout = int(config.get("wait_timeout") or 30) if isinstance(config, dict) else 30
    interval = int(config.get("wait_interval") or 2) if isinstance(config, dict) else 2
    provider = str(mailbox.get("provider") or "").strip().lower()
    if provider == "maliapi":
        return _wait_maliapi_code(mailbox, timeout=timeout, interval=interval)
    if provider == "1secmail":
        return _wait_1secmail_code(mailbox, timeout=timeout, interval=interval)
    return None
