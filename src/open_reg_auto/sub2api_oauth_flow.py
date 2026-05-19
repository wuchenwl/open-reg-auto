from __future__ import annotations

import json
import secrets
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from .config import DATA_DIR
from .register_core import (
    RegistrationResult,
    PlatformRegistrar,
    _generate_pkce,
    _decode_jwt_payload,
    auth_base,
    platform_oauth_audience,
    platform_oauth_client_id,
    save_result,
    exchange_platform_tokens,
    extract_oauth_callback_params_from_url,
)


DEFAULT_SUB2API_EXPORT_NAME = "export_accounts.json"
DEFAULT_ACCOUNT_ARCHIVE_NAME = "last_sub2api_account_archive.json"


@dataclass
class HeroSMSConfig:
    api_key: str = ""
    base_url: str = "https://hero-sms.com/cn/api"
    country: str = "CO"
    max_price: float = 0.05
    wait_timeout: int = 180
    wait_interval: int = 5


@dataclass
class Sub2APIOAuthFlowConfig:
    proxy: str = ""
    redirect_uri: str = "http://localhost:1455/auth/callback"
    login_hint: str = ""
    account_name: str = ""
    concurrency: int = 10
    priority: int = 1
    rate_multiplier: int = 1
    auto_pause_on_expired: bool = True
    plan_type: str = "free"
    privacy_mode: str = "training_off"
    export_name: str = DEFAULT_SUB2API_EXPORT_NAME
    archive_name: str = DEFAULT_ACCOUNT_ARCHIVE_NAME
    organization_id: str = ""
    hero_sms: HeroSMSConfig | None = None


@dataclass
class Sub2APIOAuthPrepared:
    authorize_url: str
    state: str
    nonce: str
    device_id: str
    code_verifier: str
    code_challenge: str
    client_id: str
    redirect_uri: str
    login_hint: str = ""


@dataclass
class Sub2APIOAuthFlowResult:
    ok: bool
    authorize_url: str = ""
    callback_url: str = ""
    code: str = ""
    export_path: str = ""
    archive_path: str = ""
    saved_result: str = ""
    email: str = ""
    error: str = ""
    payload: dict[str, Any] | None = None
    archive: dict[str, Any] | None = None
    tokens: RegistrationResult | None = None


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _merge_url_query(url: str, **params: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    for key, value in params.items():
        if value is None:
            continue
        query[key] = [str(value)]
    merged = urlencode(query, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, merged, parsed.fragment))


def build_openai_oauth_authorize_url(config: Sub2APIOAuthFlowConfig) -> Sub2APIOAuthPrepared:
    """Build the manual authorize URL + PKCE bundle for phase-1 OAuth handoff."""
    registrar = PlatformRegistrar(config.proxy)
    try:
        registrar.session.cookies.set("oai-did", registrar.device_id, domain=".auth.openai.com")
        registrar.session.cookies.set("oai-did", registrar.device_id, domain="auth.openai.com")
        code_verifier, code_challenge = _generate_pkce()
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        params = {
            "issuer": auth_base,
            "client_id": platform_oauth_client_id,
            "audience": platform_oauth_audience,
            "redirect_uri": config.redirect_uri,
            "device_id": registrar.device_id,
            "screen_hint": "login_or_signup",
            "max_age": "0",
            "scope": "openid profile email offline_access",
            "response_type": "code",
            "response_mode": "query",
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "auth0Client": "eyJuYW1lIjoiYXV0aDAtc3BhLWpzIiwidmVyc2lvbiI6IjEuMjEuMCJ9",
        }
        if config.login_hint:
            params["login_hint"] = config.login_hint
        authorize_url = f"{auth_base}/api/accounts/authorize?" + "&".join(
            f"{key}={__import__('requests').utils.quote(str(value), safe='')}" for key, value in params.items()
        )
        return Sub2APIOAuthPrepared(
            authorize_url=authorize_url,
            state=state,
            nonce=nonce,
            device_id=registrar.device_id,
            code_verifier=code_verifier,
            code_challenge=code_challenge,
            client_id=platform_oauth_client_id,
            redirect_uri=config.redirect_uri,
            login_hint=config.login_hint,
        )
    finally:
        registrar.close()


def normalize_callback_url(callback_or_code: str, redirect_uri: str, state: str = "") -> tuple[str, str]:
    """Accept either a full callback URL or a raw code and normalize both forms."""
    raw = str(callback_or_code or "").strip()
    if not raw:
        raise ValueError("empty_callback_or_code")
    callback_params = extract_oauth_callback_params_from_url(raw)
    if callback_params:
        callback_url = raw
        code = str(callback_params.get("code") or "").strip()
        return callback_url, code
    code = raw
    callback_url = _merge_url_query(redirect_uri, code=code, state=state)
    return callback_url, code


def exchange_callback_code(config: Sub2APIOAuthFlowConfig, prepared: Sub2APIOAuthPrepared, callback_or_code: str) -> RegistrationResult:
    """Exchange the returned callback/code into tokens, with direct token fallback."""
    callback_url, code = normalize_callback_url(callback_or_code, prepared.redirect_uri, prepared.state)
    primary_registrar = PlatformRegistrar(config.proxy)
    fallback_registrar: PlatformRegistrar | None = None
    try:
        result = exchange_platform_tokens(primary_registrar.session, prepared.device_id, prepared.code_verifier, callback_url, config.proxy)
        if not result.callback_url:
            result.callback_url = callback_url
        if not result.ok and code:
            # Fallback: direct token exchange for localhost callback links that do not need session continuation.
            fallback_registrar = PlatformRegistrar(config.proxy)
            resp = fallback_registrar.session.post(
                f"{auth_base}/oauth/token",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": prepared.redirect_uri,
                    "client_id": prepared.client_id,
                    "code_verifier": prepared.code_verifier,
                },
                verify=False,
                timeout=60,
            )
            try:
                data = resp.json()
                if not isinstance(data, dict):
                    data = {}
            except Exception:
                data = {}
            if resp.status_code == 200:
                result = RegistrationResult(
                    ok=True,
                    email=str((_decode_jwt_payload(str(data.get("id_token") or "")) or {}).get("email") or (_decode_jwt_payload(str(data.get("access_token") or "")) or {}).get("https://api.openai.com/profile", {}).get("email") or "").strip(),
                    access_token=str(data.get("access_token") or "").strip(),
                    refresh_token=str(data.get("refresh_token") or "").strip(),
                    id_token=str(data.get("id_token") or "").strip(),
                    callback_url=callback_url,
                )
            else:
                result = RegistrationResult(ok=False, callback_url=callback_url, error=f"oauth_token_http_{resp.status_code}")
        return result
    finally:
        primary_registrar.close()
        if fallback_registrar is not None:
            fallback_registrar.close()


def _extract_account_identity(result: RegistrationResult, organization_id: str = "", plan_type: str = "free") -> dict[str, Any]:
    access_payload = _decode_jwt_payload(result.access_token or "") or {}
    id_payload = _decode_jwt_payload(result.id_token or "") or {}
    auth_payload = access_payload.get("https://api.openai.com/auth") or {}
    profile_payload = access_payload.get("https://api.openai.com/profile") or {}
    account_id = ""
    mailbox = result.mailbox or {}
    if isinstance(mailbox, dict):
        account_id = str(mailbox.get("account_id") or "").strip()
    return {
        "email": str(result.email or profile_payload.get("email") or id_payload.get("email") or "").strip(),
        "chatgpt_account_id": account_id,
        "chatgpt_user_id": str(auth_payload.get("user_id") or "").strip(),
        "client_id": str(access_payload.get("client_id") or platform_oauth_client_id).strip(),
        "expires_at": int(access_payload.get("exp") or 0),
        "organization_id": str(organization_id or "").strip(),
        "plan_type": str(plan_type or "free").strip() or "free",
        "name": str(id_payload.get("name") or "").strip(),
    }


def build_sub2api_import_payload(
    result: RegistrationResult,
    *,
    concurrency: int = 10,
    priority: int = 1,
    rate_multiplier: int = 1,
    auto_pause_on_expired: bool = True,
    organization_id: str = "",
    plan_type: str = "free",
    privacy_mode: str = "training_off",
    account_name: str = "",
) -> dict[str, Any]:
    identity = _extract_account_identity(result, organization_id=organization_id, plan_type=plan_type)
    email = identity["email"]
    return {
        "exported_at": _utc_now_iso(),
        "proxies": [],
        "accounts": [
            {
                "name": account_name or email,
                "platform": "openai",
                "type": "oauth",
                "credentials": {
                    "access_token": result.access_token,
                    "chatgpt_account_id": identity["chatgpt_account_id"],
                    "chatgpt_user_id": identity["chatgpt_user_id"],
                    "client_id": identity["client_id"],
                    "email": email,
                    "expires_at": identity["expires_at"],
                    "id_token": result.id_token,
                    "organization_id": identity["organization_id"],
                    "plan_type": identity["plan_type"],
                    "refresh_token": result.refresh_token,
                },
                "extra": {
                    "email": email,
                    "openai_oauth_responses_websockets_v2_enabled": False,
                    "openai_oauth_responses_websockets_v2_mode": "off",
                    "privacy_mode": privacy_mode,
                },
                "concurrency": int(concurrency),
                "priority": int(priority),
                "rate_multiplier": int(rate_multiplier),
                "auto_pause_on_expired": bool(auto_pause_on_expired),
            }
        ],
    }


def build_account_archive(
    prepared: Sub2APIOAuthPrepared,
    result: RegistrationResult,
    *,
    callback_url: str,
    phone_number: str = "",
    phone_country: str = "CO",
    hero_sms_order_id: str = "",
    hero_sms_price: float | None = None,
    email_password: str = "",
    mail_provider_name: str = "",
    organization_id: str = "",
    plan_type: str = "free",
) -> dict[str, Any]:
    identity = _extract_account_identity(result, organization_id=organization_id, plan_type=plan_type)
    callback_params = extract_oauth_callback_params_from_url(callback_url) or {}
    return {
        "created_at": _utc_now_iso(),
        "platform": "openai",
        "signup_method": "oauth_manual_or_browser_assist",
        "phone": {
            "country": phone_country,
            "phone_number": phone_number,
            "provider": "hero-sms" if phone_number or hero_sms_order_id else "",
            "order_id": hero_sms_order_id,
            "price": hero_sms_price,
        },
        "email": {
            "address": identity["email"],
            "password": email_password,
            "mail_provider": mail_provider_name,
        },
        "oauth": {
            "authorize_url": prepared.authorize_url,
            "callback_url": callback_url,
            "code": str(callback_params.get("code") or "").strip(),
            "state": prepared.state,
            "redirect_uri": prepared.redirect_uri,
            "client_id": prepared.client_id,
            "device_id": prepared.device_id,
        },
        "tokens": {
            "access_token": result.access_token,
            "refresh_token": result.refresh_token,
            "id_token": result.id_token,
        },
        "profile": {
            "chatgpt_user_id": identity["chatgpt_user_id"],
            "chatgpt_account_id": identity["chatgpt_account_id"],
            "client_id": identity["client_id"],
            "organization_id": identity["organization_id"],
            "expires_at": identity["expires_at"],
            "plan_type": identity["plan_type"],
            "name": identity["name"],
        },
    }


def save_sub2api_export(payload: dict[str, Any], filename: str = DEFAULT_SUB2API_EXPORT_NAME) -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    path = DATA_DIR / filename
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def save_account_archive(archive: dict[str, Any], filename: str = DEFAULT_ACCOUNT_ARCHIVE_NAME) -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    path = DATA_DIR / filename
    path.write_text(json.dumps(archive, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def run_sub2api_oauth_flow(
    config: Sub2APIOAuthFlowConfig,
    *,
    callback_or_code: str,
    phone_number: str = "",
    hero_sms_order_id: str = "",
    hero_sms_price: float | None = None,
    email_password: str = "",
    mail_provider_name: str = "",
) -> Sub2APIOAuthFlowResult:
    prepared = build_openai_oauth_authorize_url(config)
    callback_url, code = normalize_callback_url(callback_or_code, prepared.redirect_uri, prepared.state)
    result = exchange_callback_code(config, prepared, callback_or_code)
    if not result.ok:
        return Sub2APIOAuthFlowResult(
            ok=False,
            authorize_url=prepared.authorize_url,
            callback_url=callback_url,
            code=code,
            error=result.error,
            tokens=result,
        )
    payload = build_sub2api_import_payload(
        result,
        concurrency=config.concurrency,
        priority=config.priority,
        rate_multiplier=config.rate_multiplier,
        auto_pause_on_expired=config.auto_pause_on_expired,
        organization_id=config.organization_id,
        plan_type=config.plan_type,
        privacy_mode=config.privacy_mode,
        account_name=config.account_name,
    )
    archive = build_account_archive(
        prepared,
        result,
        callback_url=callback_url,
        phone_number=phone_number,
        phone_country=(config.hero_sms.country if config.hero_sms else "CO"),
        hero_sms_order_id=hero_sms_order_id,
        hero_sms_price=hero_sms_price,
        email_password=email_password,
        mail_provider_name=mail_provider_name,
        organization_id=config.organization_id,
        plan_type=config.plan_type,
    )
    export_path = save_sub2api_export(payload, config.export_name)
    archive_path = save_account_archive(archive, config.archive_name)
    saved_result = save_result(result)
    return Sub2APIOAuthFlowResult(
        ok=True,
        authorize_url=prepared.authorize_url,
        callback_url=callback_url,
        code=code,
        export_path=str(export_path),
        archive_path=str(archive_path),
        saved_result=str(saved_result),
        email=result.email,
        payload=payload,
        archive=archive,
        tokens=result,
    )


def generate_authorize_bundle(config: Sub2APIOAuthFlowConfig) -> dict[str, Any]:
    """Return a JSON-serializable authorize bundle for manual/browser-assisted OAuth."""
    prepared = build_openai_oauth_authorize_url(config)
    return asdict(prepared)
