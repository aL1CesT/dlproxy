# 安全策略

[文档索引](docs/README.md) · [项目首页](README.md)

## 报告问题

请用 GitHub 的 [私密漏洞报告](https://docs.github.com/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability) 渠道，不要开公开 issue。

报告里请带上：

- 复现步骤与受影响版本（`CHANGELOG.md` 里的版本号）
- 判断依据 —— 实际观察到的行为，不是推测
- 如果涉及 token 或 IP，请自行打码

一般会在 7 天内回复。这是个人维护的项目，不承诺 SLA，但会认真处理。

## 部署前必须做的事

本项目是一个**可以代理任意外链的出口**。把它暴露在公网之前：

| 事项 | 为什么 |
| --- | --- |
| 删除 `/opt/dlproxy/INITIAL_ADMIN.txt` | 里面有明文的初始管理员密码，只要文件在，页面就一直挂警告条 |
| 登录后立刻改密码 | 初始密码是随机生成的，但它躺在磁盘上 |
| 确认 443 走的是真证书 | 自签证书会让所有客户端报错，也会让人习惯性忽略警告 |
| 只给自己人发 token | token 等价于「用你的带宽代理任意 URL 的权限」，泄漏了只能重置 |
| 确认 SSRF 防护没被绕过 | 服务默认拦截内网与云元数据地址；如果你的机器在前面又套了一层反代，注意那层也要拦 |

## 设计里已经处理掉的

- **凭据不进 URL** —— 一次性提示走 120 秒 cookie，不落 nginx 访问日志、不进浏览器历史
- **访问日志关闭** —— 加速链接的形状是 `/u/<token>/<原始 URL>`，默认日志等于把 token 抄到磁盘上
- **SSRF 三段式** —— DNS pinning、连接层 peer 复验、NAT64 / 6to4 / IPv4-mapped 拆包；每跳重定向都重新校验
- **密码用 argon2id** —— 64 MiB / t=3 / p=4 / 16 字节盐，数据库里只有散列
- **会话只存散列** —— DB 里是 `sha256(session_id)`，cookie 本身由 itsdangerous 签名
- **管理路径 404 而非 403** —— 路径不对时不泄露它是否存在
- **状态变更一律 POST** —— CSRF 防护依赖会话 cookie 的 `SameSite=Lax`

## 已知的、不打算修的

见 [docs/limitations.md](docs/limitations.md)。最要紧的两条：

1. **token 泄漏等于开放代理** —— 代理任意外链、没有域名黑名单，这是明确需求，代价就是拿到链接的人能用你的带宽取任意 URL
2. **没有事前限速** —— 单连接可以吃满出口带宽。熔断是事后兜底

## 支持范围

只维护 `main` 分支的最新版。安全修复会记在 `CHANGELOG.md` 并打 tag。
