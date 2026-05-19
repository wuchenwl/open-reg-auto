# open-reg-auto

## 当前状态

当前版本已经实测打通完整注册链，并成功换出 token。

已验证成功的稳定主链为：

1. `/api/accounts/authorize`
2. `/api/accounts/user/register`
3. `/api/accounts/email-otp/send`
4. `/api/accounts/email-otp/validate`
5. `/api/accounts/create_account`
6. `platform.openai.com/auth/callback -> oauth/token`

已完成的能力：

- `authorize` / PKCE / session establishment
- `MaliAPI` 邮箱创建与收码
- 注册提交 / 发验证码 / 验证码校验 / about-you / create_account
- callback 提取与 token exchange
- CLI `--config` 正式入口
- 结果落盘到 `data/last_result.json`

## 安装

```bash
cd /www/wwwroot/open-reg-auto
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## CLI 用法

### 查看帮助

```bash
cd /www/wwwroot/open-reg-auto
.venv/bin/python -m open_reg_auto.cli --help
```

### 使用配置文件运行一次完整注册链

```bash
cd /www/wwwroot/open-reg-auto
.venv/bin/python -m open_reg_auto.cli register --config /path/to/config.json
```

### 直接覆盖代理

```bash
cd /www/wwwroot/open-reg-auto
.venv/bin/python -m open_reg_auto.cli register \
  --config /path/to/config.json \
  --proxy 'socks5://user:pass@host:port'
```

### 仅生成 sub2api OAuth 第一阶段授权链接

```bash
cd /www/wwwroot/open-reg-auto
.venv/bin/python -m open_reg_auto.cli sub2api-oauth \
  --redirect-uri 'http://localhost:1455/auth/callback' \
  --login-hint 'example@example.com'
```

会输出 `authorize_url / state / nonce / device_id / code_verifier` 等字段，供手动浏览器流或上层编排保存。

### 使用 callback/code 完成 token 换取并导出 sub2api JSON

```bash
cd /www/wwwroot/open-reg-auto
.venv/bin/python -m open_reg_auto.cli sub2api-oauth \
  --config /path/to/sub2api_oauth.json \
  --callback-url 'http://localhost:1455/auth/callback?code=XXX&state=YYY'
```

也可以只传裸 `code`：

```bash
cd /www/wwwroot/open-reg-auto
.venv/bin/python -m open_reg_auto.cli sub2api-oauth \
  --config /path/to/sub2api_oauth.json \
  --code 'XXX'
```

## 标准配置模板

可以直接参考：

- `data/test_config.example.json`

示例：

```json
{
  "proxy": "socks5://resip_xxx:password@host:port",
  "mail": {
    "request_timeout": 30,
    "wait_timeout": 60,
    "wait_interval": 2,
    "providers": [
      {
        "type": "maliapi",
        "base_url": "https://maliapi.215.im/v1",
        "api_key": "AC-REPLACE_ME",
        "auto_domain_strategy": "balanced"
      }
    ]
  }
}
```

## 输出结果

CLI 成功或失败后都会输出一个 JSON 摘要，例如：

```json
{
  "ok": true,
  "email": "example@domain.t-sa.xyz",
  "error": "",
  "callback_url": "https://platform.openai.com/auth/callback?...",
  "has_access_token": true,
  "saved_result": "/www/wwwroot/open-reg-auto/data/last_result.json"
}
```

同时完整结果会保存到：

- `data/last_result.json`

其中通常包含：

- `email`
- `password`
- `access_token`
- `refresh_token`
- `id_token`
- `mailbox`
- `callback_url`
- `error`

sub2api OAuth 第一阶段完成后还会额外落盘：

- `data/export_accounts.json`：可直接供 sub2api 导入的账号 JSON
- `data/last_sub2api_account_archive.json`：完整账号档案（authorize/callback/tokens/profile）

## MaliAPI 说明

当前 `src/open_reg_auto/mail_provider.py` 已支持 provider type = `maliapi`。

推荐显式提供：

- `type = maliapi`
- `base_url = https://maliapi.215.im/v1`
- `api_key = 你的_api_key`

## sub2api OAuth 配置示例

```json
{
  "proxy": "socks5://user:pass@host:port",
  "redirect_uri": "http://localhost:1455/auth/callback",
  "login_hint": "example@example.com",
  "account_name": "demo-openai-oauth",
  "concurrency": 10,
  "priority": 1,
  "rate_multiplier": 1,
  "auto_pause_on_expired": true,
  "plan_type": "free",
  "privacy_mode": "training_off",
  "organization_id": "",
  "export_name": "export_accounts.json",
  "archive_name": "last_sub2api_account_archive.json"
}
```

## 当前验证结论

当前这版在目标环境下已连续多次完整回归成功，主链稳定性已达到“基本可用”状态。

如果后续要继续增强，优先方向建议是：

1. 批量执行入口
2. 结果归档/轮转
3. 失败重试与阶段级诊断输出
