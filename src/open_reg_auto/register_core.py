from __future__ import annotations

import base64
import hashlib
import json
import random
import secrets
import string
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse, urlencode, urlunparse

import requests
import urllib3
from curl_cffi import requests as curl_requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .config import DATA_DIR, RegisterConfig
from .logging_utils import log
from . import mail_provider

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

auth_base = "https://auth.openai.com"
platform_base = "https://platform.openai.com"
platform_oauth_client_id = "app_2SKx67EdpoN0G6j64rFvigXD"
platform_oauth_redirect_uri = f"{platform_base}/auth/callback"
platform_oauth_audience = "https://api.openai.com/v1"
user_agent = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/145.0.0.0 Safari/537.36"
)
sec_ch_ua = '"Google Chrome";v="145", "Not?A_Brand";v="8", "Chromium";v="145"'
sec_ch_ua_full_version_list = '"Chromium";v="145.0.0.0", "Not:A-Brand";v="99.0.0.0", "Google Chrome";v="145.0.0.0"'
default_timeout = 30

common_headers = {
    "accept": "application/json",
    "accept-language": "en-US,en;q=0.9",
    "content-type": "application/json",
    "origin": auth_base,
    "priority": "u=1, i",
    "user-agent": user_agent,
    "sec-ch-ua": sec_ch_ua,
    "sec-ch-ua-arch": '"x86_64"',
    "sec-ch-ua-bitness": '"64"',
    "sec-ch-ua-full-version-list": sec_ch_ua_full_version_list,
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-model": '""',
    "sec-ch-ua-platform": '"Windows"',
    "sec-ch-ua-platform-version": '"10.0.0"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin",
}

navigate_headers = {
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "accept-language": "en-US,en;q=0.9",
    "user-agent": user_agent,
    "sec-ch-ua": sec_ch_ua,
    "sec-ch-ua-arch": '"x86_64"',
    "sec-ch-ua-bitness": '"64"',
    "sec-ch-ua-full-version-list": sec_ch_ua_full_version_list,
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-model": '""',
    "sec-ch-ua-platform": '"Windows"',
    "sec-ch-ua-platform-version": '"10.0.0"',
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "same-origin",
    "sec-fetch-user": "?1",
    "upgrade-insecure-requests": "1",
}


@dataclass
class RegistrationResult:
    ok: bool
    email: str = ""
    password: str = ""
    access_token: str = ""
    refresh_token: str = ""
    id_token: str = ""
    mailbox: dict[str, Any] | None = None
    callback_url: str = ""
    error: str = ""


def _make_trace_headers() -> dict[str, str]:
    trace_id = str(random.getrandbits(64))
    parent_id = str(random.getrandbits(64))
    return {
        "traceparent": f"00-{uuid.uuid4().hex}-{format(int(parent_id), '016x')}-01",
        "tracestate": "dd=s:1;o:rum",
        "x-datadog-origin": "rum",
        "x-datadog-parent-id": parent_id,
        "x-datadog-sampling-priority": "1",
        "x-datadog-trace-id": trace_id,
    }


def _generate_pkce() -> tuple[str, str]:
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode("ascii")
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


def _random_password(length: int = 16) -> str:
    chars = string.ascii_letters + string.digits + "!@#$%"
    value = list(
        secrets.choice(string.ascii_uppercase)
        + secrets.choice(string.ascii_lowercase)
        + secrets.choice(string.digits)
        + secrets.choice("!@#$%")
        + "".join(secrets.choice(chars) for _ in range(max(0, length - 4)))
    )
    random.shuffle(value)
    return "".join(value)


def _random_name() -> tuple[str, str]:
    return random.choice(["James", "Robert", "John", "Michael", "David", "Mary", "Emma", "Olivia"]), random.choice(
        ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller"]
    )


def _random_birthdate() -> str:
    return f"{random.randint(1996, 2006):04d}-{random.randint(1, 12):02d}-{random.randint(1, 28):02d}"


def _response_json(resp) -> dict:
    try:
        data = resp.json()
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _decode_jwt_payload(token: str) -> dict:
    try:
        payload = token.split(".")[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


def _merge_url_query(url: str, **params: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    for key, value in params.items():
        if value is None:
            continue
        query[key] = [str(value)]
    merged = urlencode(query, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, merged, parsed.fragment))


def _cookie_snapshot(session: Any) -> dict[str, str]:
    wanted = [
        "oai-did",
        "oai-client-auth-session",
        "oai-auth-token",
        "__cf_bm",
        "cf_clearance",
        "_cfuvid",
        "did",
        "did_compat",
        "auth_session",
    ]
    jar = getattr(session, "cookies", None)
    values: dict[str, str] = {}
    if jar is None:
        return values
    for name in wanted:
        try:
            val = jar.get(name)
        except Exception:
            val = None
        if val:
            values[name] = str(val)
            continue
        try:
            for cookie in jar:
                if getattr(cookie, "name", "") == name:
                    values[name] = str(getattr(cookie, "value", ""))
                    break
        except Exception:
            continue
    return values


def _summarize_cookie_snapshot(snapshot: dict[str, str]) -> dict[str, Any]:
    summary: dict[str, Any] = {"present": sorted(snapshot.keys())}
    raw = str(snapshot.get("oai-client-auth-session") or "").strip()
    if raw:
        try:
            first_part = raw.split(".")[0]
            padding = 4 - len(first_part) % 4
            if padding != 4:
                first_part += "=" * padding
            payload = json.loads(base64.urlsafe_b64decode(first_part))
            summary["client_auth_session"] = {
                "keys": sorted(payload.keys()) if isinstance(payload, dict) else [],
                "has_workspaces": bool((payload or {}).get("workspaces")) if isinstance(payload, dict) else False,
                "has_session_id": bool((payload or {}).get("session_id")) if isinstance(payload, dict) else False,
            }
        except Exception as exc:
            summary["client_auth_session_decode_error"] = str(exc)
    return summary


def create_mailbox(config: RegisterConfig, username: str | None = None) -> dict:
    return mail_provider.create_mailbox(asdict(config.mail), username)


def wait_for_code(config: RegisterConfig, mailbox: dict) -> str | None:
    return mail_provider.wait_for_code(asdict(config.mail), mailbox)


class SentinelTokenGenerator:
    MAX_ATTEMPTS = 500000
    ERROR_PREFIX = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"

    def __init__(self, device_id: str, ua: str):
        self.device_id = device_id
        self.user_agent = ua
        self.sid = str(uuid.uuid4())

    @staticmethod
    def _fnv1a_32(text: str) -> str:
        h = 2166136261
        for ch in text:
            h ^= ord(ch)
            h = (h * 16777619) & 0xFFFFFFFF
        h ^= h >> 16
        h = (h * 2246822507) & 0xFFFFFFFF
        h ^= h >> 13
        h = (h * 3266489909) & 0xFFFFFFFF
        h ^= h >> 16
        return format(h & 0xFFFFFFFF, "08x")

    def _get_config(self) -> list:
        perf_now = random.uniform(1000, 50000)
        return [
            "1920x1080",
            time.strftime("%a %b %d %Y %H:%M:%S GMT+0000 (Coordinated Universal Time)", time.gmtime()),
            4294705152,
            random.random(),
            self.user_agent,
            "https://sentinel.openai.com/sentinel/20260124ceb8/sdk.js",
            None,
            None,
            "en-US",
            random.random(),
            random.choice(["vendorSub-undefined", "plugins-undefined", "mimeTypes-undefined", "hardwareConcurrency-undefined"]),
            random.choice(["location", "implementation", "URL", "documentURI", "compatMode"]),
            random.choice(["Object", "Function", "Array", "Number", "parseFloat", "undefined"]),
            perf_now,
            self.sid,
            "",
            random.choice([4, 8, 12, 16]),
            time.time() * 1000 - perf_now,
        ]

    @staticmethod
    def _b64(data) -> str:
        return base64.b64encode(json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).decode("ascii")

    def generate_requirements_token(self) -> str:
        data = self._get_config()
        data[3] = 1
        data[9] = round(random.uniform(5, 50))
        return "gAAAAAC" + self._b64(data)

    def generate_token(self, seed: str, difficulty: str) -> str:
        start = time.time()
        data = self._get_config()
        difficulty = str(difficulty or "0")
        for i in range(self.MAX_ATTEMPTS):
            data[3] = i
            data[9] = round((time.time() - start) * 1000)
            payload = self._b64(data)
            if self._fnv1a_32(seed + payload)[: len(difficulty)] <= difficulty:
                return "gAAAAAB" + payload + "~S"
        return "gAAAAAB" + self.ERROR_PREFIX + self._b64(str(None))


def build_sentinel_token(session: requests.Session, device_id: str, flow: str) -> str:
    generator = SentinelTokenGenerator(device_id, user_agent)
    resp = session.post(
        "https://sentinel.openai.com/backend-api/sentinel/req",
        data=json.dumps({"p": generator.generate_requirements_token(), "id": device_id, "flow": flow}),
        headers={
            "Content-Type": "text/plain;charset=UTF-8",
            "Referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html",
            "Origin": "https://sentinel.openai.com",
            "User-Agent": user_agent,
            "sec-ch-ua": sec_ch_ua,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        },
        timeout=20,
        verify=False,
    )
    data = _response_json(resp)
    token = str(data.get("token") or "").strip()
    if resp.status_code != 200 or not token:
        raise RuntimeError(f"sentinel_req_failed_{resp.status_code}")
    pow_data = data.get("proofofwork") or {}
    p_value = (
        generator.generate_token(str(pow_data.get("seed") or ""), str(pow_data.get("difficulty") or "0"))
        if pow_data.get("required") and pow_data.get("seed")
        else generator.generate_requirements_token()
    )
    return json.dumps({"p": p_value, "t": "", "c": token, "id": device_id, "flow": flow}, separators=(",", ":"))


def _is_socks_proxy(proxy: str) -> bool:
    candidate = str(proxy or "").strip().lower()
    return candidate.startswith("socks5://") or candidate.startswith("socks5h://")


def create_session(proxy: str = "") -> Any:
    if _is_socks_proxy(proxy):
        return curl_requests.Session(impersonate="chrome", verify=False, proxy=proxy)
    session = requests.Session()
    retry = Retry(total=2, connect=2, read=2, backoff_factor=0.5, status_forcelist=(429, 500, 502, 503, 504))
    adapter = HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=50)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.verify = False
    if proxy:
        session.proxies.update({"http": proxy, "https": proxy})
    return session


def request_with_local_retry(session: requests.Session, method: str, url: str, retry_attempts: int = 3, **kwargs):
    last_error = ""
    for _ in range(max(1, retry_attempts)):
        try:
            return session.request(method.upper(), url, timeout=default_timeout, **kwargs), ""
        except Exception as error:
            last_error = str(error)
            time.sleep(1)
    return None, last_error


def validate_otp(session: requests.Session, device_id: str, code: str):
    headers = dict(common_headers)
    headers["referer"] = f"{auth_base}/create-account/email-verification"
    headers["oai-device-id"] = device_id
    headers.update(_make_trace_headers())
    try:
        headers["openai-sentinel-token"] = build_sentinel_token(session, device_id, "authorize_continue")
    except Exception:
        pass
    resp, error = request_with_local_retry(
        session,
        "post",
        f"{auth_base}/api/accounts/email-otp/validate",
        json={"code": str(code).strip()},
        headers=headers,
        verify=False,
    )
    return resp, error


def extract_oauth_callback_params_from_url(url: str) -> dict[str, str] | None:
    if not url:
        return None
    try:
        params = parse_qs(urlparse(url).query)
    except Exception:
        return None
    code = str((params.get("code") or [""])[0]).strip()
    if not code:
        return None
    return {"code": code, "state": str((params.get("state") or [""])[0]).strip(), "scope": str((params.get("scope") or [""])[0]).strip()}


def extract_oauth_callback_params_from_consent_session(session: requests.Session, consent_url: str, device_id: str) -> dict[str, str] | None:
    if consent_url.startswith("/"):
        consent_url = f"{auth_base}{consent_url}"
    current_url = consent_url
    for _ in range(10):
        response = session.get(current_url, headers=navigate_headers, verify=False, timeout=30, allow_redirects=False)
        callback_params = extract_oauth_callback_params_from_url(str(response.url)) or extract_oauth_callback_params_from_url(str(response.headers.get("Location") or "").strip())
        if callback_params:
            return callback_params
        location = str(response.headers.get("Location") or "").strip()
        if response.status_code not in (301, 302, 303, 307, 308) or not location:
            break
        current_url = f"{auth_base}{location}" if location.startswith("/") else location
    raw = session.cookies.get("oai-client-auth-session", domain=".auth.openai.com") or session.cookies.get("oai-client-auth-session")
    if not raw:
        return None
    try:
        first_part = raw.split(".")[0]
        padding = 4 - len(first_part) % 4
        if padding != 4:
            first_part += "=" * padding
        payload = json.loads(base64.urlsafe_b64decode(first_part))
        workspace_id = payload["workspaces"][0]["id"]
    except Exception:
        return None
    headers = dict(common_headers)
    headers["referer"] = consent_url
    headers["oai-device-id"] = device_id
    headers.update(_make_trace_headers())
    ws_resp = session.post(f"{auth_base}/api/accounts/workspace/select", json={"workspace_id": workspace_id}, headers=headers, verify=False, timeout=30, allow_redirects=False)
    callback_params = extract_oauth_callback_params_from_url(str(ws_resp.headers.get("Location") or "").strip())
    if callback_params:
        return callback_params
    ws_data = _response_json(ws_resp)
    orgs = ((ws_data.get("data") or {}).get("orgs") or []) if isinstance(ws_data, dict) else []
    if not orgs:
        return None
    org_id = str((orgs[0] or {}).get("id") or "").strip()
    project_id = str(((orgs[0] or {}).get("projects") or [{}])[0].get("id") or "").strip()
    if not org_id:
        return None
    org_headers = dict(common_headers)
    org_headers["referer"] = str(ws_data.get("continue_url") or consent_url)
    org_headers["oai-device-id"] = device_id
    org_headers.update(_make_trace_headers())
    body = {"org_id": org_id}
    if project_id:
        body["project_id"] = project_id
    org_resp = session.post(f"{auth_base}/api/accounts/organization/select", json=body, headers=org_headers, verify=False, timeout=30, allow_redirects=False)
    return extract_oauth_callback_params_from_url(str(org_resp.headers.get("Location") or "").strip())


def exchange_platform_tokens(session: requests.Session, device_id: str, code_verifier: str, consent_url: str, proxy: str = "") -> RegistrationResult:
    callback_params = extract_oauth_callback_params_from_consent_session(session, consent_url, device_id)
    if not callback_params:
        try:
            r = session.get(consent_url, headers=navigate_headers, allow_redirects=True, verify=False, timeout=30)
            final_url = str(r.url)
            callback_params = extract_oauth_callback_params_from_url(final_url)
            if not callback_params:
                for hist in getattr(r, "history", []) or []:
                    loc = str(hist.headers.get("Location") or "")
                    callback_params = extract_oauth_callback_params_from_url(loc)
                    if callback_params:
                        break
        except Exception as exc:
            return RegistrationResult(ok=False, error=f"consent_redirect_failed:{exc}")
    if not callback_params:
        return RegistrationResult(ok=False, error="missing_oauth_callback")
    code = str(callback_params.get("code") or "").strip()
    resp = create_session(proxy).post(
        f"{auth_base}/oauth/token",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": platform_oauth_redirect_uri,
            "client_id": platform_oauth_client_id,
            "code_verifier": code_verifier,
        },
        verify=False,
        timeout=60,
    )
    data = _response_json(resp)
    if resp.status_code != 200:
        return RegistrationResult(ok=False, callback_url=consent_url, error=f"oauth_token_http_{resp.status_code}")
    access_token = str(data.get("access_token") or "").strip()
    refresh_token = str(data.get("refresh_token") or "").strip()
    id_token = str(data.get("id_token") or "").strip()
    if not access_token or not refresh_token or not id_token:
        return RegistrationResult(ok=False, callback_url=consent_url, error="missing_tokens")
    payload = _decode_jwt_payload(id_token) or _decode_jwt_payload(access_token)
    return RegistrationResult(
        ok=True,
        email=str(payload.get("email") or "").strip(),
        access_token=access_token,
        refresh_token=refresh_token,
        id_token=id_token,
        callback_url=consent_url,
    )


def save_result(result: RegistrationResult) -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    path = DATA_DIR / "last_result.json"
    path.write_text(json.dumps(asdict(result), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


class PlatformRegistrar:
    def __init__(self, proxy: str = "") -> None:
        self.session = create_session(proxy)
        self.device_id = str(uuid.uuid4())
        self.proxy = proxy
        self.last_authorize: dict[str, Any] = {}
        self.sentinel_tokens: dict[str, str] = {}

    def close(self) -> None:
        self.session.close()

    def start_authorize(self, email: str) -> dict[str, str]:
        self.session.cookies.set("oai-did", self.device_id, domain=".auth.openai.com")
        self.session.cookies.set("oai-did", self.device_id, domain="auth.openai.com")
        code_verifier, code_challenge = _generate_pkce()
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        params = {
            "issuer": auth_base,
            "client_id": platform_oauth_client_id,
            "audience": platform_oauth_audience,
            "redirect_uri": platform_oauth_redirect_uri,
            "device_id": self.device_id,
            "screen_hint": "login_or_signup",
            "max_age": "0",
            "login_hint": email,
            "scope": "openid profile email offline_access",
            "response_type": "code",
            "response_mode": "query",
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "auth0Client": "eyJuYW1lIjoiYXV0aDAtc3BhLWpzIiwidmVyc2lvbiI6IjEuMjEuMCJ9",
        }
        url = f"{auth_base}/api/accounts/authorize?" + "&".join(f"{k}={requests.utils.quote(str(v), safe='')}" for k, v in params.items())
        response, error = request_with_local_retry(
            self.session,
            "get",
            url,
            headers=navigate_headers,
            allow_redirects=True,
            verify=False,
        )
        if response is None:
            raise RuntimeError(error or "authorize_request_failed")
        cookie_snapshot = _cookie_snapshot(self.session)
        self.last_authorize = {
            "email": email,
            "state": state,
            "nonce": nonce,
            "code_verifier": code_verifier,
            "code_challenge": code_challenge,
            "final_url": str(response.url),
            "status": str(response.status_code),
            "cookie_snapshot": cookie_snapshot,
            "cookie_summary": _summarize_cookie_snapshot(cookie_snapshot),
        }
        return {
            "code_verifier": code_verifier,
            "final_url": str(response.url),
            "status": str(response.status_code),
            "cookie_summary": self.last_authorize.get("cookie_summary") or {},
        }

    def _ensure_sentinel_token(self, flow: str) -> str:
        cached = str(self.sentinel_tokens.get(flow) or "").strip()
        if cached:
            return cached
        token = build_sentinel_token(self.session, self.device_id, flow)
        self.sentinel_tokens[flow] = token
        return token

    def _build_accounts_headers(self, referer_path: str, flow: str) -> dict[str, str]:
        headers = dict(common_headers)
        headers["referer"] = f"{auth_base}{referer_path}"
        headers["oai-device-id"] = self.device_id
        headers["accept"] = "application/json"
        headers["x-requested-with"] = "XMLHttpRequest"
        headers["sec-fetch-site"] = "same-origin"
        headers["sec-fetch-mode"] = "cors"
        headers["sec-fetch-dest"] = "empty"
        headers.update(_make_trace_headers())
        try:
            headers["OpenAI-Sentinel-Token"] = self._ensure_sentinel_token(flow)
        except Exception as exc:
            headers["x-openai-sentinel-error"] = str(exc)
        return headers

    def _post_accounts_payload(self, payload: dict[str, Any], referer_path: str, candidates: list[tuple[str, str]] | None = None) -> dict[str, Any]:
        flow = "auth" if str(payload.get("origin_page_type") or "").startswith("login") else "signup"
        headers = self._build_accounts_headers(referer_path, flow)
        state = str(self.last_authorize.get("state") or "").strip()
        referer_url = f"{auth_base}{referer_path}"
        default_candidates = [
            (f"{auth_base}/api/accounts", "json"),
            (referer_url, "json"),
            (referer_url, "form"),
            (_merge_url_query(referer_url, _data="routes/u/signup/identifier"), "json"),
            (_merge_url_query(referer_url, _data="routes/u/signup/identifier"), "form"),
            (_merge_url_query(referer_url, _data="routes/u/signup/password"), "json"),
            (_merge_url_query(referer_url, _data="routes/u/signup/password"), "form"),
            (_merge_url_query(f"{auth_base}/u/signup/identifier", _data="routes/u/signup/identifier"), "json"),
            (_merge_url_query(f"{auth_base}/u/signup/identifier", _data="routes/u/signup/identifier"), "form"),
            (_merge_url_query(f"{auth_base}/u/signup/password", _data="routes/u/signup/password"), "json"),
            (_merge_url_query(f"{auth_base}/u/signup/password", _data="routes/u/signup/password"), "form"),
        ]
        if state:
            default_candidates.extend(
                [
                    (_merge_url_query(f"{auth_base}/u/signup/identifier", state=state, _data="routes/u/signup/identifier"), "json"),
                    (_merge_url_query(f"{auth_base}/u/signup/identifier", state=state, _data="routes/u/signup/identifier"), "form"),
                    (_merge_url_query(f"{auth_base}/u/signup/password", state=state, _data="routes/u/signup/password"), "json"),
                    (_merge_url_query(f"{auth_base}/u/signup/password", state=state, _data="routes/u/signup/password"), "form"),
                ]
            )
        attempts: list[dict[str, Any]] = []
        cookie_snapshot = _cookie_snapshot(self.session)
        cookie_summary = _summarize_cookie_snapshot(cookie_snapshot)
        for url, body_mode in (candidates or default_candidates):
            try_headers = dict(headers)
            kwargs: dict[str, Any] = {"headers": try_headers, "verify": False}
            if body_mode == "form":
                try_headers["content-type"] = "application/x-www-form-urlencoded;charset=UTF-8"
                kwargs["data"] = {
                    "payload": json.dumps(payload, separators=(",", ":"), ensure_ascii=False),
                    "state": state,
                    "origin_page_type": str(payload.get("origin_page_type") or ""),
                }
            else:
                kwargs["json"] = payload
            resp, error = request_with_local_retry(
                self.session,
                "post",
                url,
                **kwargs,
            )
            body = {}
            text = ""
            status = 0
            final_url = url
            if resp is not None:
                status = int(getattr(resp, "status_code", 0) or 0)
                body = _response_json(resp)
                final_url = str(getattr(resp, "url", url) or url)
                try:
                    text = resp.text[:2000]
                except Exception:
                    text = ""
            attempt = {
                "url": url,
                "body_mode": body_mode,
                "ok": resp is not None and 200 <= status < 300,
                "status": status,
                "json": body,
                "text": text,
                "error": error,
                "final_url": final_url,
                "cookie_summary": cookie_summary,
                "referer": headers.get("referer") or "",
                "state": state,
                "sentinel_token_present": bool(try_headers.get("OpenAI-Sentinel-Token")),
                "sentinel_error": try_headers.get("x-openai-sentinel-error") or "",
            }
            attempts.append(attempt)
            if attempt["ok"] or status in (401, 403, 405, 422):
                return {**attempt, "payload": payload, "attempts": attempts, "authorize": self.last_authorize}
        last = attempts[-1] if attempts else {"ok": False, "status": 0, "json": {}, "text": "", "error": "no_attempts", "url": "", "final_url": "", "body_mode": "json", "cookie_summary": cookie_summary, "referer": headers.get("referer") or "", "state": state}
        return {**last, "payload": payload, "attempts": attempts, "authorize": self.last_authorize}

    def establish_signup_session(self) -> dict[str, Any]:
        state = str(self.last_authorize.get("state") or "").strip()
        final_url = str(self.last_authorize.get("final_url") or "").strip() or f"{auth_base}/u/signup"
        headers = dict(navigate_headers)
        headers["oai-device-id"] = self.device_id
        headers.update(_make_trace_headers())
        try:
            headers["OpenAI-Sentinel-Token"] = self._ensure_sentinel_token("signup")
        except Exception as exc:
            headers["x-openai-sentinel-error"] = str(exc)
        probes: list[dict[str, Any]] = []
        nav_candidates = [
            final_url,
            f"{auth_base}/u/signup",
            f"{auth_base}/u/signup?state={state}" if state else f"{auth_base}/u/signup",
            f"{auth_base}/u/signup/identifier?state={state}" if state else f"{auth_base}/u/signup/identifier",
            f"{auth_base}/u/signup/password?state={state}" if state else f"{auth_base}/u/signup/password",
            f"{auth_base}/api/auth/session",
            f"{auth_base}/api/auth/session?state={state}" if state else f"{auth_base}/api/auth/session",
            f"{auth_base}/api/client_auth_session_dump",
            f"{auth_base}/api/client_auth_session_dump?state={state}" if state else f"{auth_base}/api/client_auth_session_dump",
        ]
        xhr_headers = self._build_accounts_headers(f"/u/signup/password?state={state}" if state else "/u/signup/password", "signup")
        xhr_headers["accept"] = "application/json"
        xhr_candidates = [
            (_merge_url_query(f"{auth_base}/u/signup", _data="routes/u/signup", state=state) if state else _merge_url_query(f"{auth_base}/u/signup", _data="routes/u/signup"), "get"),
            (_merge_url_query(f"{auth_base}/u/signup/identifier", _data="routes/u/signup/identifier", state=state) if state else _merge_url_query(f"{auth_base}/u/signup/identifier", _data="routes/u/signup/identifier"), "get"),
            (_merge_url_query(f"{auth_base}/u/signup/password", _data="routes/u/signup/password", state=state) if state else _merge_url_query(f"{auth_base}/u/signup/password", _data="routes/u/signup/password"), "get"),
            (f"{auth_base}/api/auth/session", "get"),
            (f"{auth_base}/api/client_auth_session_dump", "get"),
        ]
        for url in nav_candidates:
            resp, error = request_with_local_retry(
                self.session,
                "get",
                url,
                headers=headers,
                verify=False,
                allow_redirects=False,
            )
            body = {}
            text = ""
            status = 0
            content_type = ""
            location = ""
            final_probe_url = url
            if resp is not None:
                status = int(getattr(resp, "status_code", 0) or 0)
                body = _response_json(resp)
                final_probe_url = str(getattr(resp, "url", url) or url)
                content_type = str(getattr(resp, "headers", {}).get("Content-Type") or "")
                location = str(getattr(resp, "headers", {}).get("Location") or "")
                try:
                    text = resp.text[:2000]
                except Exception:
                    text = ""
            probes.append(
                {
                    "probe_type": "navigate",
                    "url": url,
                    "status": status,
                    "content_type": content_type,
                    "location": location,
                    "json": body,
                    "text": text,
                    "error": error,
                    "final_url": final_probe_url,
                    "is_html_shell": "<html" in text.lower() or "auth-cdn.oaistatic.com/assets/" in text,
                }
            )
        for url, method in xhr_candidates:
            resp, error = request_with_local_retry(
                self.session,
                method,
                url,
                headers=xhr_headers,
                verify=False,
                allow_redirects=False,
            )
            body = {}
            text = ""
            status = 0
            content_type = ""
            location = ""
            final_probe_url = url
            if resp is not None:
                status = int(getattr(resp, "status_code", 0) or 0)
                body = _response_json(resp)
                final_probe_url = str(getattr(resp, "url", url) or url)
                content_type = str(getattr(resp, "headers", {}).get("Content-Type") or "")
                location = str(getattr(resp, "headers", {}).get("Location") or "")
                try:
                    text = resp.text[:2000]
                except Exception:
                    text = ""
            probes.append(
                {
                    "probe_type": "xhr",
                    "url": url,
                    "method": method,
                    "status": status,
                    "content_type": content_type,
                    "location": location,
                    "json": body,
                    "text": text,
                    "error": error,
                    "final_url": final_probe_url,
                    "is_html_shell": "<html" in text.lower() or "auth-cdn.oaistatic.com/assets/" in text,
                }
            )
        cookie_snapshot = _cookie_snapshot(self.session)
        cookie_summary = _summarize_cookie_snapshot(cookie_snapshot)
        result = {
            "ok": bool(cookie_snapshot.get("oai-client-auth-session") or cookie_snapshot.get("auth_session") or cookie_snapshot.get("oai-auth-token")),
            "state": state,
            "cookie_summary": cookie_summary,
            "cookie_snapshot": cookie_snapshot,
            "sentinel_token_present": bool(headers.get("OpenAI-Sentinel-Token")),
            "sentinel_error": headers.get("x-openai-sentinel-error") or "",
            "probes": probes,
        }
        self.last_authorize["session_establishment"] = result
        return result

    def create_account_start(self, email: str) -> dict[str, Any]:
        payload = {
            "origin_page_type": "create_account_start",
            "data": {
                "kind": "username",
                "username": {"value": email, "kind": "email"},
            },
        }
        state = self.last_authorize.get("state") or ""
        return self._post_accounts_payload(payload, f"/u/signup/identifier?state={state}")

    def register_user(self, email: str, password: str) -> dict[str, Any]:
        headers = dict(common_headers)
        headers["referer"] = f"{auth_base}/create-account/password"
        headers["oai-device-id"] = self.device_id
        headers.update(_make_trace_headers())
        try:
            headers["openai-sentinel-token"] = self._ensure_sentinel_token("username_password_create")
        except Exception as exc:
            headers["x-openai-sentinel-error"] = str(exc)
        resp, error = request_with_local_retry(
            self.session,
            "post",
            f"{auth_base}/api/accounts/user/register",
            json={"username": email, "password": password},
            headers=headers,
            verify=False,
        )
        status = int(getattr(resp, "status_code", 0) or 0) if resp is not None else 0
        body = _response_json(resp) if resp is not None else {}
        text = ""
        final_url = f"{auth_base}/api/accounts/user/register"
        if resp is not None:
            final_url = str(getattr(resp, "url", final_url) or final_url)
            try:
                text = resp.text[:2000]
            except Exception:
                text = ""
        return {
            "ok": resp is not None and 200 <= status < 300,
            "status": status,
            "json": body,
            "text": text,
            "error": error,
            "final_url": final_url,
            "payload": {"username": email, "password": password},
            "authorize": self.last_authorize,
            "sentinel_token_present": bool(headers.get("openai-sentinel-token") or headers.get("OpenAI-Sentinel-Token")),
            "sentinel_error": headers.get("x-openai-sentinel-error") or "",
        }

    def send_otp(self) -> dict[str, Any]:
        headers = dict(navigate_headers)
        headers["referer"] = f"{auth_base}/create-account/password"
        resp, error = request_with_local_retry(
            self.session,
            "get",
            f"{auth_base}/api/accounts/email-otp/send",
            headers=headers,
            allow_redirects=True,
            verify=False,
        )
        status = int(getattr(resp, "status_code", 0) or 0) if resp is not None else 0
        body = _response_json(resp) if resp is not None else {}
        text = ""
        final_url = f"{auth_base}/api/accounts/email-otp/send"
        if resp is not None:
            final_url = str(getattr(resp, "url", final_url) or final_url)
            try:
                text = resp.text[:2000]
            except Exception:
                text = ""
        return {
            "ok": resp is not None and status in (200, 302),
            "status": status,
            "json": body,
            "text": text,
            "error": error,
            "final_url": final_url,
            "authorize": self.last_authorize,
        }

    def validate_signup_otp(self, code: str) -> dict[str, Any]:
        resp, error = validate_otp(self.session, self.device_id, code)
        status = int(getattr(resp, "status_code", 0) or 0) if resp is not None else 0
        body = _response_json(resp) if resp is not None else {}
        text = ""
        final_url = f"{auth_base}/api/accounts/email-otp/validate"
        if resp is not None:
            final_url = str(getattr(resp, "url", final_url) or final_url)
            try:
                text = resp.text[:2000]
            except Exception:
                text = ""
        return {
            "ok": resp is not None and 200 <= status < 300,
            "status": status,
            "json": body,
            "text": text,
            "error": error,
            "final_url": final_url,
            "authorize": self.last_authorize,
        }

    def create_account(self, name: str, birthdate: str) -> dict[str, Any]:
        headers = dict(common_headers)
        headers["referer"] = f"{auth_base}/about-you"
        headers["oai-device-id"] = self.device_id
        headers.update(_make_trace_headers())
        try:
            headers["openai-sentinel-token"] = self._ensure_sentinel_token("oauth_create_account")
        except Exception as exc:
            headers["x-openai-sentinel-error"] = str(exc)
        resp, error = request_with_local_retry(
            self.session,
            "post",
            f"{auth_base}/api/accounts/create_account",
            json={"name": name, "birthdate": birthdate},
            headers=headers,
            verify=False,
            allow_redirects=False,
        )
        status = int(getattr(resp, "status_code", 0) or 0) if resp is not None else 0
        body = _response_json(resp) if resp is not None else {}
        text = ""
        final_url = f"{auth_base}/api/accounts/create_account"
        location = ""
        if resp is not None:
            final_url = str(getattr(resp, "url", final_url) or final_url)
            location = str(getattr(resp, "headers", {}).get("Location") or "")
            try:
                text = resp.text[:2000]
            except Exception:
                text = ""
        return {
            "ok": resp is not None and status in (200, 302),
            "status": status,
            "json": body,
            "text": text,
            "error": error,
            "final_url": final_url,
            "location": location,
            "payload": {"name": name, "birthdate": birthdate},
            "authorize": self.last_authorize,
            "sentinel_token_present": bool(headers.get("openai-sentinel-token") or headers.get("OpenAI-Sentinel-Token")),
            "sentinel_error": headers.get("x-openai-sentinel-error") or "",
        }

    def exchange_platform_tokens(self, code_verifier: str, callback_url: str) -> RegistrationResult:
        return exchange_platform_tokens(self.session, self.device_id, code_verifier, callback_url, self.proxy)


def run_placeholder(config: RegisterConfig) -> RegistrationResult:
    mailbox = create_mailbox(config)
    email = str(mailbox.get("email") or "").strip()
    password = _random_password()
    first_name, last_name = _random_name()
    birthdate = _random_birthdate()
    full_name = f"{first_name} {last_name}"
    log(f"已创建邮箱: {email}")
    log(f"已生成占位资料: password={password}, name={full_name}, birthdate={birthdate}")
    registrar = PlatformRegistrar(proxy=config.proxy)
    try:
        info = registrar.start_authorize(email=email)
        log(f"authorize 已启动: status={info.get('status')} final_url={info.get('final_url')}")
        establish_info = registrar.establish_signup_session()
        log(f"session establishment 已尝试: ok={establish_info.get('ok')} cookies={((establish_info.get('cookie_summary') or {}).get('present') or [])}")
        if not establish_info.get("ok"):
            result = RegistrationResult(
                ok=False,
                email=email,
                password=password,
                mailbox=mailbox,
                callback_url=str(info.get("final_url") or ""),
                error="session_establishment_failed",
            )
            save_result(result)
            return result
        register_info = registrar.register_user(email=email, password=password)
        log(f"register_user 已尝试: status={register_info.get('status')} ok={register_info.get('ok')}")
        otp_info = registrar.send_otp()
        log(f"send_otp 已尝试: status={otp_info.get('status')} ok={otp_info.get('ok')} final_url={otp_info.get('final_url')}")
        code = wait_for_code(config, mailbox)
        if not code:
            result = RegistrationResult(
                ok=False,
                email=email,
                password=password,
                mailbox=mailbox,
                callback_url=str(register_info.get("json", {}).get("continue_url") or info.get("final_url") or ""),
                error="wait_for_code_timeout",
            )
            save_result(result)
            return result
        log(f"已收到验证码: {code}")
        validate_info = registrar.validate_signup_otp(code)
        log(f"validate_signup_otp 已尝试: status={validate_info.get('status')} ok={validate_info.get('ok')} continue_url={((validate_info.get('json') or {}).get('continue_url') or '')}")
        if not validate_info.get("ok"):
            result = RegistrationResult(
                ok=False,
                email=email,
                password=password,
                mailbox=mailbox,
                callback_url=str(((validate_info.get("json") or {}).get("continue_url") or info.get("final_url") or "")),
                error=f"validate_signup_otp_{validate_info.get('status')}",
            )
            save_result(result)
            return result
        create_info = registrar.create_account(full_name, birthdate)
        log(f"create_account 已尝试: status={create_info.get('status')} ok={create_info.get('ok')} location={create_info.get('location')} final_url={create_info.get('final_url')}")
        callback_url = str(((create_info.get("json") or {}).get("continue_url") or create_info.get("location") or validate_info.get("json", {}).get("continue_url") or info.get("final_url") or ""))
        if not create_info.get("ok"):
            result = RegistrationResult(
                ok=False,
                email=email,
                password=password,
                mailbox=mailbox,
                callback_url=callback_url,
                error=f"create_account_{create_info.get('status')}",
            )
            save_result(result)
            return result
        if create_info.get("ok") and callback_url:
            token_result = registrar.exchange_platform_tokens(str(info.get("code_verifier") or ""), callback_url)
            if token_result.ok:
                token_result.password = password
                token_result.mailbox = mailbox
                save_result(token_result)
                return token_result
            save_result(token_result)
            return token_result
        error = f"register_{register_info.get('status')}_otp_{otp_info.get('status')}_validate_{validate_info.get('status')}_create_{create_info.get('status')}"
        result = RegistrationResult(
            ok=False,
            email=email,
            password=password,
            mailbox=mailbox,
            callback_url=callback_url,
            error=error,
        )
        save_result(result)
        return result
    finally:
        registrar.close()
