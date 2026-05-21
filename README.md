
# open-reg-auto

## 项目简介

本项目实现了对 ChatGPT 官网注册接口的纯协议逆向，在正常配置下注册成功率接近 100%（无异常情况）。部分流程思路受 [basketikun/chatgpt2api](https://github.com/basketikun/chatgpt2api) 启发。

![注册成功率示例](https://github.com/user-attachments/assets/d53e1df2-8bd0-4543-a75f-fece4afdfb78)

> 社区用户将本项目集成至 `chatgpt2api` 后，注册成功率由约 5% 提升至近乎 100%（230 个测试样本），仅 2 例因 callback 检测过快而失败。

---

## ⚠️ 免责声明

本项目仅限**个人学习、技术研究与非商业交流**使用。使用即代表你同意以下条款：

- ❌ 不得用于任何**商业用途、盈利、批量操作、自动化滥用或规模化调用**
- ❌ 不得用于**破坏市场秩序、恶意竞争、套利倒卖、二次售卖相关服务**
- ❌ 不得违反 **OpenAI 服务条款**或**当地法律法规**
- ❌ 不得生成、传播或协助生成**违法、暴力、色情、未成年人相关**内容，或用于**诈骗、欺诈、骚扰**等非法行为
- ⚠️ 使用者承担全部风险（账号封禁、法律责任等），项目作者不承担任何后果

---

## 当前功能状态

✅ 已完整打通注册链，成功换出 Token  
✅ 已验证稳定的主流程节点：

1. `/api/accounts/authorize` + PKCE → 建立会话
2. `/api/accounts/user/register`
3. `/api/accounts/email-otp/send`
4. `/api/accounts/email-otp/validate`
5. `/api/accounts/create_account`
6. `platform.openai.com/auth/callback` → `/oauth/token`

已完成能力列表：

- `authorize` / PKCE 流程
- MaliAPI 邮箱创建与验证码接收
- 注册提交 / 发码 / 校验 / 创建账号
- callback 提取与 Token 兑换
- CLI `--config` 主入口
- 结果自动落盘至 `data/last_result.json`

---

## 安装

```bash
cd /www/wwwroot/open-reg-auto
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

---

## CLI 使用指南

### 查看帮助

```bash
cd /www/wwwroot/open-reg-auto
.venv/bin/python -m open_reg_auto.cli --help
```

### 完整注册（使用配置文件）

```bash
.venv/bin/python -m open_reg_auto.cli register --config /path/to/config.json
```

### 临时覆盖代理

```bash
.venv/bin/python -m open_reg_auto.cli register \
  --config /path/to/config.json \
  --proxy 'socks5://user:pass@host:port'
```

### 生成 sub2api OAuth 第一阶段授权链接

```bash
.venv/bin/python -m open_reg_auto.cli sub2api-oauth \
  --redirect-uri 'http://localhost:1455/auth/callback' \
  --login-hint 'example@example.com'
```

输出字段：`authorize_url`、`state`、`nonce`、`device_id`、`code_verifier` 等。

### 使用 callback 或 code 完成 Token 换取并导出 sub2api JSON

```bash
# 方式1：传入完整 callback URL
.venv/bin/python -m open_reg_auto.cli sub2api-oauth \
  --config /path/to/sub2api_oauth.json \
  --callback-url 'http://localhost:1455/auth/callback?code=XXX&state=YYY'

# 方式2：仅传入 code
.venv/bin/python -m open_reg_auto.cli sub2api-oauth \
  --config /path/to/sub2api_oauth.json \
  --code 'XXX'
```

---

## 配置文件模板

参考文件：`data/test_config.example.json`

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

### MaliAPI 说明

已支持 `type = maliapi`，推荐显式配置：

- `base_url`：`https://maliapi.215.im/v1`
- `api_key`：你的 API Key

---

## 输出结果

CLI 执行完毕会输出一个 JSON 摘要，例如：

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

完整结果保存在 `data/last_result.json`，通常包含：

- `email` / `password`
- `access_token` / `refresh_token` / `id_token`
- `mailbox`
- `callback_url`
- `error`

### sub2api OAuth 额外输出

- `data/export_accounts.json` —— 可直接导入 sub2api 的账号 JSON
- `data/last_sub2api_account_archive.json` —— 完整账号档案（authorize / callback / tokens / profile）

### sub2api OAuth 配置示例

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

---

## 验证结论

当前版本在目标环境下已多次完整回归成功，主链稳定性达到“基本可用”状态。
