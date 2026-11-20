# 已知限制

[文档索引](README.md) · [项目首页](../README.md)

用之前请先读这一页。下面分两类：**架构上就这样，代码修不了** 和 **刻意不做**。

## 架构层面的脆弱点

### 1. 证书是短命的

不配域名时用的是 IP 证书，有效期约 160 小时（不到 7 天）。续期失败一次就只剩几天缓冲，持续失败浏览器会直接拦截。换公网 IP 证书立刻失效。

这是整套架构最脆的一环，不是代码能修的 —— Let's Encrypt 对 IP 标识符只发短命证书。缓解办法是走域名证书（`--domain`，约 90 天），见 [certificates.md](certificates.md)。

### 2. token 泄漏等于开放代理

代理任意外链、没有域名黑名单、token 长期固定。任何拿到某个加速链接的人都能用它代理自己想要的任何 URL。

- 处置手段只有重置 token（管理面板一键，旧链接立即 404）
- 加速链接本身走的是 TLS，但一旦被贴到公开场合（issue、论坛、截图），就等于公开了
- nginx 访问日志已关闭、凭据不走 URL，能做的都做了；剩下的风险在链接的传播上

### 3. 没有事前限速

单连接可以吃满实例的出口带宽，同机 SSH 会卡。熔断是事后兜底（超了才拦），并发上限是唯一的闸门。

需要精细限速就用 nginx 的 `limit_rate` 或前置 CDN —— 本项目不做，因为自用场景下把带宽用满正是目的。

### 4. DNS rebinding 的极小窗口

已经做了连接层 peer 复验（解析 → 校验 → 连字面 IP → `getpeername()` 再比一次），窗口基本关闭，但理论上仍存在极窄的时间差。复验失败会 403 并记日志。

### 5. 初始密码文件

`/opt/dlproxy/INITIAL_ADMIN.txt` 在服务器上时，任何能读 `/opt/dlproxy` 的人都能拿到初始密码。首次登录后立刻删掉，只要它在，页面就一直挂黄色警告条。

### 6. 单进程

uvicorn 以单进程运行。一条连接的计算开销很小（流式转发几乎全是 IO），但如果单机真的跑满 CPU，没有多进程兜底。这样设计是因为并发计数与在途流状态在进程内存里，多进程需要额外的协调层。

### 7. 客户端地址来自 `X-Real-IP`，而它默认被信任

`DLPROXY_BEHIND_PROXY` 默认是 `1`，因为安装脚本总是把 uvicorn 放在 nginx 后面 —— 这时 `X-Real-IP` 由 nginx 用 `$remote_addr` 覆写，客户端改不了。

但如果你把 `DLPROXY_HOST` 改成 `0.0.0.0` 直接对外（不经 nginx），这个头就完全由客户端决定。后果是登录失败计数与 15 分钟锁定都按那个值记账：攻击者每次换一个 `X-Real-IP` 就能无限重试，或者反过来把别人的地址打进锁定。

直连部署时把 `DLPROXY_BEHIND_PROXY` 设成 `0`，应用就改用 TCP 连接的对端地址。

### 8. 网页能打开，但它不是镜像站

把 `https://example.com/` 塞进加速链接，浏览器确实会把它当网页渲染 —— 上游的 `Content-Type` 是原样透传的。但页面只有外壳，子资源基本加载不出来：

| 发生了什么 | 原因 |
| --- | --- |
| 相对路径 `/style.css` 请求到 `https://your-host/style.css`，返回 404 | `/u/<token>/` 前缀不在页面里，相对路径跑出了前缀 |
| 外部 CDN 的脚本、样式、字体被拒 | nginx 的 `Content-Security-Policy` 是 `default-src 'self'`，`'self'` 是你的站点，不是上游 |
| 上游下发的 `Set-Cookie` 被丢弃 | 转发白名单里没有它 —— 别人的会话 cookie 不该落到你的域下 |
| 页面不能被 iframe 嵌入 | `X-Frame-Options: DENY` |

实测一条 Google 首页链接：页面本身 200、渲染出来了，14 个请求里只有它自己成功，其余 13 个（`/xjs/…` 404、`gstatic.com` 被 CSP 拦、`gen_204` 405）全部失败。所以它适合**取一个文件**，不适合**逛一个网站**。

想做网页镜像需要重写 HTML 里的链接、给每条子资源单独签发代理 URL、并且放开 CSP —— 那是另一个项目，本项目不做（见下表「网页镜像」一行）。

### 9. 带 JS 挑战的站点（AWS WAF、Cloudflare 等）永远过不去

有些站点在正常内容前面放一页「验证你不是机器人」的挑战页：响应码 202（或 403），正文是一小段 HTML，加载一个跨域的 `challenge.js`，拿到 token 后 `window.location.reload(true)` 重新请求。带着那枚 token 的 cookie 再来一次，才放行真正的内容。

加速链接把这条路全部堵死了，所以它只会**无限刷新**，直到 WAF 的次数上限报出 `Max challenge attempts exceeded. Please refresh the page to try again!`：

| 挑战需要什么 | 加速链接做了什么 |
| --- | --- |
| 从 `*.awswaf.com` 加载 `challenge.js` | nginx 的 CSP 是 `script-src 'self' 'unsafe-inline'`，跨域脚本被浏览器拦掉，`AwsWafIntegration` 根本不存在 |
| 挑战成功后把 token 写进 cookie | 转发白名单没有 `Set-Cookie`，写下去也到不了下一次请求 |
| `reload(true)` 后带 cookie 重发 | 每次都当成一个全新会话，于是又拿到一张挑战页 |

实测（`https://platform.deepseek.com/usage`，走 AWS WAF）：

```
直连上游            HTTP/2 200  content-length 2781  （正常页面，带 HWWAFSES* cookie）
经加速链接          HTTP/2 202  content-length 2544  （AWS WAF 挑战页）
挑战页正文          <script src="https://a0fea896111e...token.awswaf.com/.../challenge.js">
                    AwsWafIntegration.getToken().then(() => window.location.reload(true));
```

用浏览器打开这条加速链接：导航只有 1 次、请求只有 1 个、控制台一条 CSP 报错 —— 挑战脚本没有加载，页面停在挑战页上。

**这不是并发上限或活跃流的问题**：那次 202 是在 **0 个其它连接**的情况下返回的。同一条 token 加速 `https://www.google.com/` 得到 200、236969 字节，一切正常。

**怎么办**：这类站点不要用加速链接。它适合的是「一个 URL 指向一个文件」的场景 —— release 附件、模型权重、`git clone`。要让挑战在代理后面通过，需要把 cookie 转发过去、把 CSP 放开到上游域、还要让挑战脚本认为自己运行在 `platform.deepseek.com` 这个 origin 下 —— 那已经不是一个下载加速器，而是一个通用反向代理，本项目不做（见下表「网页镜像」一行）。

## 刻意不做的功能

这些不是待办，是设计时决定不要的：

| 不做 | 原因 |
| --- | --- |
| 文件上传、`git push`、WebSocket、非 HTTP(S) 协议 | 这是个下载加速器，不是通用代理 |
| 网页镜像（改写 HTML 链接、代理子资源、放开 CSP） | 见上文第 8 条。取文件可以，逛网站不行 |
| 绕过 WAF 的 JS 挑战（转发 cookie、放开 CSP、伪造 origin） | 见上文第 9 条。`Max challenge attempts exceeded` 就是这么来的 |
| 域名黑白名单 | 明确需求：代理任意外链 |
| 缓存文件到磁盘 | 大文件不落盘是核心特性，缓存会立刻吃掉磁盘 |
| 每用户带宽限速 | 见上文第 3 条 |
| 关闭 SSRF 防护的开关 | 没有这个开关。内网与云元数据地址一律 403 |
| 多用户额度自动开通 | 2–5 人的规模，手工建号更快也更可控 |
| 前端构建工具链 | 服务端渲染 + 一份 vendored CSS 就够了，少一层依赖 |

## 并发上限的连带要求

如果调高并发上限，几个系统参数要跟着调，否则 fd 会先耗尽：

| 并发 | systemd `LimitNOFILE` | nginx `worker_connections` |
| --- | --- | --- |
| 64（默认够用） | 默认值即可 | 默认值即可 |
| 256 | 65535 | 4096 |
| 1024 | 65535 | 16384 |

每条在途流占两个 fd（下游一个、上游一个）。`deploy/dlproxy.service` 里已经写了 `LimitNOFILE=65535`，nginx 侧需要手工确认。

## 与并发相关的已知行为

- 并发计数在进程内存里，重启清零。重启用 `systemctl restart dlproxy` 不会影响已完成的计量（那些已经落库）
- 客户端断开后槽位立即释放，`/admin` 页面的活跃流数目是实时的
- 熔断判定发生在请求进入时，不打断在途流 —— 所以在途的大文件会跑完，即使它把额度推过了线
