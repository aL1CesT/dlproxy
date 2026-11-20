# 故障排查

[文档索引](README.md) · [项目首页](../README.md)

先看这条：**`install.sh` 问完问题却什么都没做** —— 它最后会打印将要执行的命令行并等一个 `y`。答 `n` 或 Ctrl-D 都干净退出（`已取消，未做任何改动`）。想先看命令不执行，加 `--dry-run`。

## 加速链接

| 现象 | 原因与处理 |
| --- | --- |
| 链接 404 | token 错 / 已重置 / 账号被禁用。到管理面板看 token 状态 |
| 链接 400 | 目标不是绝对 http(s) URL、带 `user:pass@`、端口不是 80/443、或 URL 超过 8 KB |
| 链接 403，响应体只有 `forbidden` | 命中 SSRF 拦截。原因只在 `/var/log/dlproxy/security.log`（`ssrf_block`），这是有意的：不告诉调用方为什么 |
| 链接 502 | 上游不可达、重定向超过 5 跳、或上游返回了无法解析的 `Location` |
| 链接 503 + `Retry-After` | 并发打到上限。管理面板可调，或等几秒 |
| 链接 429 | 触发日 / 月熔断。面板里「临时解封」 |
| 下载到一半断了 | 上游空闲超过 `stream_idle_timeout_s`（默认 120 秒），看安全日志的 `idle_timeout` |
| 历史里某行显示 `—` | 该次请求在首字节前就结束了（客户端断开或上游连不上）。现在会记 499 / 403 / 502，若仍是 `—` 说明是旧版本留下的行 |
| 页面不停地刷新，最后报 `Max challenge attempts exceeded` | 那个站点有 JS 挑战（AWS WAF、Cloudflare 等）。挑战要求从上游域加载 `challenge.js`，而 CSP 只允许本站；要求把 token 写进 cookie，而 `Set-Cookie` 被丢。每一次加载都被当成新会话，撞到 WAF 的尝试上限就是这句话。这不是并发或活跃流的问题 —— 详见 [已知限制](limitations.md#9-带-js-挑战的站点aws-wafcloudflare-等永远过不去) |
| 页面能打开，但样式和图片全丢 | 它只转发这一个 URL，不是网页代理。相对路径会跑到 `https://<主机>/…`（不在 `/u/` 前缀下），外部子资源被 CSP `default-src 'self'` 拦，上游 cookie 被剥。详见 [已知限制](limitations.md#8-网页能打开但它不是镜像站) |

## 部署

| 现象 | 原因与处理 |
| --- | --- |
| `deploy.sh` 卡在 cert 阶段 | 80 端口公网不通。去云控制台放行 80 / 443 入站，再 `--stage cert` |
| `deploy.sh` 报「端口 80 已被占用」 | 80 上的占用者如果是 nginx / apache2 / httpd / caddy，脚本会接管并 reload 它，不算冲突；报这条说明占用者是别的东西，或查不出是谁。`ss -lntp \| grep :80` 看清楚再处理 —— 脚本不会停别人的服务 |
| 向导在 443 上看到 nginx，问「仍然尝试共用 443？」 | 旧版本会把 nginx 当成「不是 TLS 代理」。现在 443 上的 nginx / apache2 / httpd / caddy 走独占模式：脚本接管那个实例并 reload，在同一个 nginx 里新增 dlproxy 站点，别的 server 块不动。只有**不是 Web 服务器**的进程占着 443 才会问这句 |
| 用 IP 访问加速链接，出来的是别的站点 | 同一个 nginx 上还有别的 `listen 443 ssl` 站点并且它声明了 `default_server`。nginx 只允许一个默认站点，脚本不会去抢（抢了 `nginx -t` 会直接失败，报 `a duplicate default server`）。部署加 `--domain`，用域名访问；脚本在接管失败时会在 stderr 说明是哪个文件挡住的 |
| 重装时提示 `本次未生成`（没有 INITIAL_ADMIN.txt） | 正常。密码只在库里没有管理员时写入，重装不会重新生成。忘了就 `sudo dlproxy` 选 4 重置 |
| `nginx -t` 报 `unknown directive "http2"` | nginx 1.24（Ubuntu 24.04）不认独立的 `http2 on;`。重跑 `sudo ./deploy.sh --stage nginx` 让脚本按本机版本重填 |
| 向导说原服务「仅绑定在 127.0.0.1」 | 不是报错，是提醒：回环监听的端口外网连不到 `域名:PORT`。要直连就把监听地址改成 `0.0.0.0`；只走 443 的话无需处理 |
| `--share-443` 报「443 当前被占用」 | 预期行为：那个服务还占着 443。先把它改到 `--tls-service-port` 指定的端口并确认能用，再重跑 |
| `--share-443` 报缺少 stream 模块 | `apt install -y libnginx-mod-stream && ln -sf /usr/share/nginx/modules-available/mod-stream.conf /etc/nginx/modules-enabled/50-mod-stream.conf`，再重跑（`deploy.sh` 的 deps 阶段会自动做） |
| share-443 之后原服务连不上 | 它可能不认 PROXY 头。保留剥头器（默认）即可；若它自己支持 PROXY protocol，也可以改成直连并删掉剥头器 server 块 |
| share-443 之后加速链接 502 | 检查 `ss -lntp \| grep 8443` —— dlproxy 的 http 层没起来，看 `nginx -t` 与 `journalctl -u nginx` |
| 域名访问加速链接返回原服务的错误页 | 域名会被判成「带 SNI」而分流给原服务。要么用 IP 访问，要么部署时加 `--domain` / `--dlproxy-host` |

## 管理面板

| 现象 | 原因与处理 |
| --- | --- |
| 管理页 404 | 路径记错了。取回当前值：<br>`sudo -u dlproxy /opt/dlproxy/venv/bin/python -c "from app import db; print(db.get_setting(db.init_db(), 'admin_path'))"` |
| 登录一直失败 | 连续 5 次会锁定该 IP 15 分钟，锁定期间正确密码也拒。等一会儿，或看 `/var/log/dlproxy/security.log` 的 `login_locked` |
| 页面上的链接是 `<域名或IP>` 占位符 | 库里还没有站点地址。`sudo dlproxy set-site https://<你的IP>`，或在菜单里选 11 |
| 修改密码后其他浏览器被登出 | 预期行为。改密码会注销该账号的其他会话，只保留当前这个 |

## 证书

| 现象 | 原因与处理 |
| --- | --- |
| 浏览器证书警告 | 证书过期。`sudo certbot certificates` 看剩余时间，`journalctl -u snap.certbot.renew` 看续期失败原因 |
| 换公网 IP 后全站不可用 | IP 证书绑死旧 IP，换 IP 后立即失效。先在云控制台绑好新 IP、确认 80 可达，再 `sudo ./deploy.sh --stage cert` |
| 证书明明没过期但告警说 CRIT | 另一个信号触发了：续期自动化新鲜度。看 `/var/lib/certbot/last-success` 的修改时间，超过 96 小时说明续期坏了。详见 [certificates.md](certificates.md) |
| 每天收到重复告警邮件 | 正常设计是每个档位只发一封。反复收到说明状态在 WARN / 健康之间来回跳，看 `/var/log/dlproxy/cert.log` |

## 收集信息

报告问题时请附上（**把 token 与公网 IP 抹掉**）：

```bash
sudo ./deploy.sh --dry-run 2>&1 | tail -40     # 若有
nginx -t 2>&1
ss -lntp | grep -E ':(80|443|8080|8443|8441)'
journalctl -u dlproxy -n 100 --no-pager
tail -50 /var/log/dlproxy/security.log
tail -50 /var/log/dlproxy/cert.log
```
