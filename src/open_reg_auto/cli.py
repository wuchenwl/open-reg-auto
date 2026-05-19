from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from .config import MailConfig, RegisterConfig, ensure_dirs
from .register_core import run_placeholder, save_result
from .sub2api_oauth_flow import HeroSMSConfig, Sub2APIOAuthFlowConfig, generate_authorize_bundle, run_sub2api_oauth_flow


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="open-reg-auto", description="Standalone register protocol extractor")
    subparsers = parser.add_subparsers(dest="command")

    register_parser = subparsers.add_parser("register", help="run the original mailbox + OTP registration flow")
    register_parser.add_argument("--config", default="", help="path to JSON config file")
    register_parser.add_argument("--proxy", default="", help="http/https/socks5 proxy")
    register_parser.add_argument("--total", type=int, default=1)
    register_parser.add_argument("--threads", type=int, default=1)

    oauth_parser = subparsers.add_parser("sub2api-oauth", help="prepare or finalize the manual OAuth phase-1 flow for sub2api")
    oauth_parser.add_argument("--config", default="", help="path to JSON config file")
    oauth_parser.add_argument("--proxy", default="", help="http/https/socks5 proxy")
    oauth_parser.add_argument("--redirect-uri", default="", help="OAuth redirect URI used during authorize/token exchange")
    oauth_parser.add_argument("--login-hint", default="", help="prefill email/login hint")
    oauth_parser.add_argument("--account-name", default="", help="sub2api account display name")
    oauth_parser.add_argument("--concurrency", type=int, default=10)
    oauth_parser.add_argument("--priority", type=int, default=1)
    oauth_parser.add_argument("--rate-multiplier", type=int, default=1)
    oauth_parser.add_argument("--auto-pause-on-expired", dest="auto_pause_on_expired", action="store_true", default=True)
    oauth_parser.add_argument("--no-auto-pause-on-expired", dest="auto_pause_on_expired", action="store_false")
    oauth_parser.add_argument("--plan-type", default="free")
    oauth_parser.add_argument("--privacy-mode", default="training_off")
    oauth_parser.add_argument("--export-name", default="")
    oauth_parser.add_argument("--archive-name", default="")
    oauth_parser.add_argument("--organization-id", default="")
    oauth_parser.add_argument("--callback-url", default="", help="full callback URL containing code=...")
    oauth_parser.add_argument("--code", default="", help="raw OAuth authorization code as callback substitute")
    oauth_parser.add_argument("--phone-number", default="")
    oauth_parser.add_argument("--hero-sms-order-id", default="")
    oauth_parser.add_argument("--hero-sms-price", type=float, default=None)
    oauth_parser.add_argument("--email-password", default="")
    oauth_parser.add_argument("--mail-provider-name", default="")
    oauth_parser.add_argument("--hero-sms-api-key", default="")
    oauth_parser.add_argument("--hero-sms-base-url", default="")
    oauth_parser.add_argument("--hero-sms-country", default="")
    oauth_parser.add_argument("--hero-sms-max-price", type=float, default=None)
    oauth_parser.add_argument("--hero-sms-wait-timeout", type=int, default=None)
    oauth_parser.add_argument("--hero-sms-wait-interval", type=int, default=None)

    return parser


def load_config(args: argparse.Namespace) -> RegisterConfig:
    cfg = RegisterConfig(proxy=args.proxy, total=max(1, args.total), threads=max(1, args.threads))
    config_path = str(getattr(args, "config", "") or "").strip()
    if not config_path:
        return cfg
    data = json.loads(Path(config_path).read_text(encoding="utf-8"))
    mail_data = data.get("mail") or {}
    cfg = RegisterConfig(
        proxy=str(data.get("proxy") or cfg.proxy),
        total=max(1, int(data.get("total") or cfg.total)),
        threads=max(1, int(data.get("threads") or cfg.threads)),
        mail=MailConfig(
            request_timeout=int(mail_data.get("request_timeout") or 30),
            wait_timeout=int(mail_data.get("wait_timeout") or 30),
            wait_interval=int(mail_data.get("wait_interval") or 2),
            providers=list(mail_data.get("providers") or []),
            proxy=str(mail_data.get("proxy") or ""),
        ),
    )
    if args.proxy:
        cfg.proxy = args.proxy
    if getattr(args, "total", None):
        cfg.total = max(1, int(args.total))
    if getattr(args, "threads", None):
        cfg.threads = max(1, int(args.threads))
    return cfg


def _load_json_config(path: str) -> dict:
    config_path = str(path or "").strip()
    if not config_path:
        return {}
    return json.loads(Path(config_path).read_text(encoding="utf-8"))


def _build_hero_sms_config(raw: dict, args: argparse.Namespace) -> HeroSMSConfig | None:
    hero_raw = raw.get("hero_sms") or {}
    has_any = any(
        [
            hero_raw,
            getattr(args, "hero_sms_api_key", ""),
            getattr(args, "hero_sms_base_url", ""),
            getattr(args, "hero_sms_country", ""),
            getattr(args, "hero_sms_max_price", None) is not None,
            getattr(args, "hero_sms_wait_timeout", None) is not None,
            getattr(args, "hero_sms_wait_interval", None) is not None,
        ]
    )
    if not has_any:
        return None
    return HeroSMSConfig(
        api_key=str(getattr(args, "hero_sms_api_key", "") or hero_raw.get("api_key") or ""),
        base_url=str(getattr(args, "hero_sms_base_url", "") or hero_raw.get("base_url") or HeroSMSConfig.base_url),
        country=str(getattr(args, "hero_sms_country", "") or hero_raw.get("country") or HeroSMSConfig.country),
        max_price=float(
            getattr(args, "hero_sms_max_price", None)
            if getattr(args, "hero_sms_max_price", None) is not None
            else hero_raw.get("max_price", HeroSMSConfig.max_price)
        ),
        wait_timeout=int(
            getattr(args, "hero_sms_wait_timeout", None)
            if getattr(args, "hero_sms_wait_timeout", None) is not None
            else hero_raw.get("wait_timeout", HeroSMSConfig.wait_timeout)
        ),
        wait_interval=int(
            getattr(args, "hero_sms_wait_interval", None)
            if getattr(args, "hero_sms_wait_interval", None) is not None
            else hero_raw.get("wait_interval", HeroSMSConfig.wait_interval)
        ),
    )


def load_sub2api_oauth_config(args: argparse.Namespace) -> Sub2APIOAuthFlowConfig:
    raw = _load_json_config(getattr(args, "config", ""))
    hero_sms = _build_hero_sms_config(raw, args)
    cfg = Sub2APIOAuthFlowConfig(
        proxy=str(getattr(args, "proxy", "") or raw.get("proxy") or ""),
        redirect_uri=str(getattr(args, "redirect_uri", "") or raw.get("redirect_uri") or Sub2APIOAuthFlowConfig.redirect_uri),
        login_hint=str(getattr(args, "login_hint", "") or raw.get("login_hint") or ""),
        account_name=str(getattr(args, "account_name", "") or raw.get("account_name") or ""),
        concurrency=max(1, int(getattr(args, "concurrency", 10) or raw.get("concurrency") or 10)),
        priority=int(getattr(args, "priority", 1) if getattr(args, "priority", None) is not None else raw.get("priority", 1)),
        rate_multiplier=max(1, int(getattr(args, "rate_multiplier", 1) or raw.get("rate_multiplier") or 1)),
        auto_pause_on_expired=bool(getattr(args, "auto_pause_on_expired", True) if hasattr(args, "auto_pause_on_expired") else raw.get("auto_pause_on_expired", True)),
        plan_type=str(getattr(args, "plan_type", "") or raw.get("plan_type") or "free"),
        privacy_mode=str(getattr(args, "privacy_mode", "") or raw.get("privacy_mode") or "training_off"),
        export_name=str(getattr(args, "export_name", "") or raw.get("export_name") or Sub2APIOAuthFlowConfig.export_name),
        archive_name=str(getattr(args, "archive_name", "") or raw.get("archive_name") or Sub2APIOAuthFlowConfig.archive_name),
        organization_id=str(getattr(args, "organization_id", "") or raw.get("organization_id") or ""),
        hero_sms=hero_sms,
    )
    return cfg


def run_register_command(args: argparse.Namespace) -> None:
    cfg = load_config(args)
    result = run_placeholder(cfg)
    path = save_result(result)
    summary = {
        "ok": bool(result.ok),
        "email": str(result.email or ""),
        "error": str(result.error or ""),
        "callback_url": str(result.callback_url or ""),
        "has_access_token": bool(result.access_token),
        "saved_result": str(path),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))


def run_sub2api_oauth_command(args: argparse.Namespace) -> None:
    cfg = load_sub2api_oauth_config(args)
    callback_or_code = str(getattr(args, "callback_url", "") or getattr(args, "code", "") or "").strip()
    if not callback_or_code:
        prepared = generate_authorize_bundle(cfg)
        output = {"ok": True, "stage": "authorize_prepared", **prepared}
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return
    result = run_sub2api_oauth_flow(
        cfg,
        callback_or_code=callback_or_code,
        phone_number=str(getattr(args, "phone_number", "") or ""),
        hero_sms_order_id=str(getattr(args, "hero_sms_order_id", "") or ""),
        hero_sms_price=getattr(args, "hero_sms_price", None),
        email_password=str(getattr(args, "email_password", "") or ""),
        mail_provider_name=str(getattr(args, "mail_provider_name", "") or ""),
    )
    output = {
        "ok": bool(result.ok),
        "stage": "token_exchanged" if result.ok else "token_exchange_failed",
        "authorize_url": str(result.authorize_url or ""),
        "callback_url": str(result.callback_url or ""),
        "code": str(result.code or ""),
        "email": str(result.email or ""),
        "error": str(result.error or ""),
        "export_path": str(result.export_path or ""),
        "archive_path": str(result.archive_path or ""),
        "saved_result": str(result.saved_result or ""),
        "has_access_token": bool(result.tokens and result.tokens.access_token),
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    ensure_dirs()
    if args.command in (None, "register"):
        run_register_command(args)
        return
    if args.command == "sub2api-oauth":
        run_sub2api_oauth_command(args)
        return
    parser.error(f"unknown command: {args.command}")


if __name__ == "__main__":
    main()
