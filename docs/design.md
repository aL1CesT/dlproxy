# 关键设计

[文档索引](README.md) · [项目首页](../README.md)

几个看起来可以随便写、实际会坏事的地方，以及这么写的原因。

## 为什么 nginx 的 `proxy_pass` 绝不能带斜杠

这是整套东西最容易踩死的地方。`deploy/nginx.conf` 里写的是：

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;    # 结尾没有 /，也没有任何 URI 部分
}
```

一旦写成 `proxy_pass http://127.0.0.1:8080/;`（或带任何 URI 片段），nginx 会在转发前重写 URI：`merge_slashes` 生效，`https://e.com/a//b.zip` 变成 `https:/e.com/a/b.zip`。于是每一个加速链接都失效，而且失效得很隐蔽 —— 只有内嵌 URL 里的双斜杠和被压缩的多斜杠会坏。

`tools/e2e_nginx.py` 用真 nginx 断言这一点，12 个正向用例加 1 个反证（故意用错误写法，必须能观察到 URL 被改写）。实测输出：

```
PASS 全部 13 项通过 — nginx 原样转发请求 URI，链接形态安全
  反证: 带斜杠的写法确实改写了 URL: /u/TOK/https:/e.com/a/b.zip
```

## URL 还原走原始字节

Starlette 的 `request.url.path` 已经解码并规范化（`%2F` → `/`）。所以 `app/urls.py` 只读 `scope["raw_path"]` 与 `scope["query_string"]`，用字节切分 `/u/<token>/` 前缀，再拼回 `?query`。全程不 decode、不 re-encode。

同时自己做这些校验（nginx 只管一部分，8080 端口也可能被直接访问）：

| 输入 | nginx 行为 | 应用行为 |
| --- | --- | --- |
| 裸 `%`、`%00` | 400 | 也 400 |
| `%ff`、非法 UTF-8 | 原样透传 | 转交上游（由上游决定） |
| `user:pass@` | 原样透传 | 400 拒绝 |
| `:8443` 等非 80/443 端口 | 原样透传 | 400 拒绝 |
| URL 超过 8 KB | 原样透传（16 KB 都过） | 414 |
| `#fragment` | 原样透传 | 在 `#` 处截断（浏览器本来就不发 `#`） |

## SSRF：DNS pinning + peer 复验

`app/ssrf.py` 在 httpcore 的 TCP 层做拦截，URL 里的 hostname 全程不改，所以 Host 头、TLS SNI、证书校验、连接池键都还是真实域名。

```
解析 → 逐个校验所有解析结果 → 连到已校验的字面 IP → 读 getpeername() 再比一次
```

最后一步是防 DNS rebinding 的关键：解析器与真正建连之间有时间窗，恶意 DNS 可以在窗口里换答案。peer 复验把窗口关掉。

另外三个容易漏的点也处理了：

- **NAT64 / 6to4 / IPv4-mapped IPv6**：`ipaddress` 认为 `64:ff9b::a9fe:a9fe`（NAT64 包着 169.254.169.254）是 `is_global=True`，必须先拆出内嵌的 IPv4 再判
- **IPv6 scope id**：`fe80::1%eth0` 要先 `split("%", 1)[0]`
- **代理**：`trust_env=False` 且不接受任何 proxy 配置。走 HTTP 代理时 httpcore 会把代理地址当 SNI，backend 只校验了代理，防护形同虚设

实测证据见 `tools/e2e_full.py`：`169.254.169.254`、`10.0.0.1`、`[::1]` 经整条链全部 403，响应体只有 `forbidden`，原因只进安全日志。

## 计量与熔断

- 只计**实际发出**的响应体字节。header 不算，回源流量不算，30x 跳转体不算
- `counters` 按 **UTC+8** 日历日分桶，硬编码，不读系统时区（云主机默认 UTC，谁 `timedatectl set-timezone` 一下都不该改变别人的日配额）
- 熔断在新请求**进入时**判定，在途流不打断。在 99% 处掐掉一个 40 GB 下载，除了浪费 40 GB 带宽什么也没做到
- 手动解封写 `settings.bypass_until`，同时跳过日与月判定，**不改动 counters**。所以月度统计永远真实，解封期间照常计量
- 并发满返回 **503 + `Retry-After`**，熔断返回 **429**。两者语义不同，不该共用一个状态码
- 熔断触发时发一封邮件，用 `settings.breaker_alerted_at` 去重：同一次熔断只发一封，请求恢复正常后清空戳。熔断期间每个被拒的请求都发信会把自己的邮箱打爆

## 中断也要入账

客户端 Ctrl+C 时历史仍然要有一条正确记录。`_relay` 的 `finally` 负责关闭上游流、flush 计量、封存历史行，`GeneratorExit` 会走 `finally`，`status_code` 记 499（nginx 的惯例）。

这里有个不直观的边界：**异步生成器如果从未被迭代过，`aclose()` 不会执行 `finally`。** 客户端在首字节前就断开、或上游根本连不上时，响应体交出去后一次都没被读取，`finally` 就静默跳过了，历史行留下 `status_code IS NULL`，页面显示成 `—`。

现在的做法是给响应体套一层 `RelayStream`：它记下自己被迭代过没有，响应对象被丢弃时回调封口。`tools/e2e_full.py` 第 5 项实测：客户端读 200 KB 后断开，服务端记录 `bytes_sent=655360`、`status=499`、counters 同步增长。

## 凭据一律不走 URL

所有一次性提示（重置出来的新 token、新密码、各种错误）都先写进 `flashes` 表，再用一个 120 秒的 cookie 交接，落地页取一次即删。不图省事用 `?msg=` 的原因：

- nginx 默认把整条请求行写进 `/var/log/nginx/access.log`，查询串也在里面
- 浏览器历史与 `Referer` 同样会留下它
- 刷新页面会重放，用户以为还有一次机会

同理，两个 nginx 模板都写死了 `access_log off;` —— 加速链接的形状是 `/u/<token>/<原始 URL>`，默认日志等于把每个人的 token 抄一份到磁盘上，而日志比 token 活得更久。

## 事件循环里不放阻塞调用

argon2id 是**故意**慢的（本机实测 37.9 ms 一次），smtplib 更慢。两者都改走 `asyncio.to_thread`：单进程同时转发着上百条流，登录阻塞 40 ms 就是所有在途流一起停 40 ms。

## 状态变更一律 POST

所有会改状态的路由都是 POST，CSRF 防护依赖会话 cookie 的 `SameSite=Lax`。这是有意的最小方案 —— 会话 cookie 本来就不带 `Secure` 之外的额外属性，加上 `SameSite=Lax` 之后跨站表单提交不会带上它。不要新增会改状态的 GET。

## 前端不用构建工具

服务端渲染的 Jinja2 模板 + 一份 vendored 的 Pico.css（83 KB，不走 CDN —— 这台机器唯一的出网流量应该是用户自己填入的下载链接）。

`app.css` 里有一处刻意的覆盖：Pico 的 `--pico-font-size` 会按视口把根字号放大到 125%（1280 px 时），连带所有 rem 一起变大。项目把它钉回 `100%`，正文固定 15 px、表格 13 px、统计数字 21.6 px，四档视口（1280 / 820 / 550 / 390）字号一致。导航栏里的 `<a role="button">` 与 `<button>` 走 Pico 两套不同的盒子（链接还额外吃到一条负 margin），曾被渲染成 41.6 px 与 38.6 px 两个高度 —— 现在两者都显式 `height: 2rem`，`tools/ui_check.py` 有一项直接比较渲染后的盒子高度（差 ≤ 1 px）。

## 依赖只钉直接版本

`requirements.txt` 只写 7 个直接依赖，不冻结传递依赖。七个包全是 `py3-none-any` 纯 Python，编译型传递依赖（pydantic-core、cffi、argon2-cffi-bindings、markupsafe）在 manylinux2014/2_17/2_24/2_26/2_27/2_28 都有 aarch64 wheel，实测 25 个 wheel 全解析、0 编译，服务器上不需要 `build-essential`。

冻结传递依赖反而会出事：`pip freeze` 在 x86 上锁出来的 tag 在 arm64 上找不到对应 wheel。验证 arm64 可装性时也必须给 `--platform` 并集，只给单个 tag 会**静默降级**到老版本（实测会退到 fastapi 0.125 / pydantic 1.10）。
