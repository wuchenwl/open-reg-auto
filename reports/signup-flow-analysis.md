# signup flow analysis

## 高置信流程还原

根据已抓到的上游片段，注册闭环大致不是“直接 authorize -> token”，而是：

1. `create_mailbox()`
2. `_platform_authorize(email, index)`
3. `_register_user(email, password, index)`
4. `_send_otp(index)`
5. `wait_for_code(mailbox)`
6. `_validate_otp(code, index)`
7. `_create_account(name, birthdate, index)`
8. `_login_and_exchange_tokens(email, password, mailbox, index)`
9. `exchange_platform_tokens(login_session, login_device_id, code_verifier, continue_url)`

## 当前项目和上游相比缺什么

当前 `/www/wwwroot/open-reg-auto` 已有：
- PKCE
- authorize 起手
- sentinel token 生成
- OTP validate 骨架
- consent / callback 提取
- token exchange 骨架
- mailbox(1secmail)

但当前还缺真正关键的几步：
- `_register_user(email, password, ...)`
- `_send_otp(...)`
- `_create_account(...)`
- `_login_and_exchange_tokens(...)`

## 当前 403 的最可能原因

当前只做了 `authorize` 起手，没有继续沿同一会话把 signup/register 提交下去，因此最可能是：

1. authorize 只是拿前置上下文，不是最终注册入口
2. 缺少 signup 提交流程，导致后续访问链路不具备合法会话状态
3. `code_verifier / continue_url / consent` 需要和后续登录态严格对应
4. 真实链路依赖同一 session / cookie / device_id 持续推进，当前脚本还没走到那一步

## 新的实测结论（2026-05-18）

### 1. 代理是关键变量

在无代理环境下，`authorize` 实测返回 403。
切换到用户提供的美国 socks5 代理后：
- 代理出口：纽约 / US
- `authorize` 返回 200
- `u/signup/identifier` 页面可正常打开

这说明此前的 403 主要是出口环境问题，而不是邮箱 provider 问题。

### 2. YYDS / MaliAPI 邮箱已验证可用

已用用户提供的 API key 实测成功创建临时邮箱，说明 mailbox 链路可用。

### 3. signup 页面是重前端驱动

直接抓取 `https://auth.openai.com/u/signup/identifier?...` 页面可见：
- 页面是 React / React Router 流
- bootstrap 中带 `deviceId`、`ip`、`country`、`userAgent`
- 带大量 statsig / feature flags
- cookies 至少包括：`oai-did`、`__cf_bm`、`_cfuvid`、`__cflb`

这意味着注册流不是传统“猜 API endpoint 直接 POST”那么简单，前端状态与服务端风控耦合较重。

### 4. 已从前端 bundle 中抓到的关键线索

继续分析 `https://auth-cdn.oaistatic.com/assets/app-core-*.js` 后，已拿到这些高价值线索：

- 明确存在常量：
  - `https://auth.openai.com/api/accounts`
- 明确存在行为埋点：
  - `registerUser`
  - `validateOtp`
  - `resendOtp`
- 明确存在注册相关 page type：
  - `create_account_start`
  - `create_account_password`
  - `email_otp_send`
  - `email_otp_verification_registration`
  - `about_you`
- 已抓到 `create_account_password` 对应的数据模型片段：
  - `origin_page_type: create_account_password`
  - `data: { username: J, password: gr }`
  - 或 `intent: passwordless_signup_send_otp`

进一步实测：
- 已用代理环境真实尝试：`POST https://auth.openai.com/api/accounts`
- 请求体使用：
  - `origin_page_type: create_account_password`
  - `data.username = { value: email, kind: email }`
  - `data.password = <password>`
- 服务端返回：`404 Invalid URL (POST /api/accounts)`

随后继续分析 bundle，又抓到了更细的 route schema：
- `id` = `create_account_start`
  - `origin_page_type: create_account_start`
  - `data.kind = username | connection`
- `rd` = `create_account_password`
  - `origin_page_type: create_account_password`
  - `data = { username, password }` 或 `{ intent: passwordless_signup_send_otp }`
- `sd` = `email_otp_send`
  - `origin_page_type: email_otp_send`
- `_d` = `email_otp_verification | email_otp_verification_registration`
  - `data.intent = validate | resend`

进一步实测后得到更硬的结论：
- 已尝试 `create_account_start` payload -> `POST /api/accounts`
- 已尝试 `create_account_password` payload -> `POST /api/accounts`
- 两者都返回同样的：`404 Invalid URL (POST /api/accounts)`

这说明：
1. 前端 bundle 中出现 `/api/accounts`，但当前 signup 阶段不等于直接 POST 到它
2. 注册流至少分成 `create_account_start -> create_account_password -> email_otp_send -> email_otp_verification_registration`
3. 先后阶段线索大概率是对的，但当前更核心的问题是：**真实提交 URL / route action 还没抓到**
4. 下一步需要继续抓 route action / 表单真实提交目标，尤其是 `create_account_start` 对应的提交位置，而不是继续撞 `/api/accounts`

## 下一步最值得做的事

1. 给 `start_authorize()` 增加更细日志：记录响应状态、headers、cookie、body 片段
2. 继续抓 route action / 表单真实提交目标（重点盯 `create_account_start` 与 `create_account_password` 的真实提交 URL）
3. 修正 `_create_account_start()` / `_register_user()` 的提交目标
4. 再实现 `_send_otp()` 请求
5. 拿到 `_validate_otp()` 成功后的返回结构，继续补 `_create_account()`
6. 最后再补 `_login_and_exchange_tokens()`
