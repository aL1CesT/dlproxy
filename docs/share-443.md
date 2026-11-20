# 443 已被其他服务占用怎么办（share-443）

[文档索引](README.md) · [项目首页](../README.md)

如果这台机器上已经有一个服务在监听 443 —— 任何以 TLS 对外提供服务的进程都算，常见的有反向代理、控制面板、自建代理协议 —— dlproxy 的 nginx 就抢不到这个端口。

三条出路：

| 做法 | 代价 |
| --- | --- |
| 把已有服务挪到别的端口 | 那个服务的客户端要改配置 |
| dlproxy 换别的端口 | 加速链接带上端口号，不好看也不好记 |
| **两者共用 443，按 SNI 分流** | 多一层 TCP 跳数；443 上不再有 `default_server` 兜底 |

第三条是本项目自带的方案，也是本文讲的东西。

## 原理

**IP 进不了 SNI。** RFC 6066 规定 SNI 里只能放域名，不能放 IP 字面量。所以用户访问 `https://<IP>/u/<token>/...` 时，浏览器 / curl / aria2 **根本不发 SNI**；而任何用域名连进来的客户端**一定带 SNI**。两类流量天然不重叠，只看这一个比特就够了。

```
client --TLS--> :443  nginx stream (ssl_preread on)
                 ├── 无 SNI（IP 直连） ──> 127.0.0.1:8443  dlproxy 的 http 层 TLS
                 └── 有 SNI（域名）────> 127.0.0.1:8441  剥头器 ──> 原服务的端口
```

`ssl_preread` 只读 ClientHello，不解密、不改写，原服务的 TLS 语义完全不受影响。

## 为什么中间要有一个"剥头器"

dlproxy 需要真实客户端 IP，所以 stream 层必须 `proxy_protocol on`。问题是 `proxy_protocol` 在 nginx 里是 **per-server 的枚举开关**，只接受 `on | off | v2` 三个值，不接受变量（[PR #1713](https://github.com/nginx/nginx/pull/1713) 至今未合并）。同一个 `listen 443` 下，两个后端**都会**收到 PROXY 头。

原服务如果不认这行头，握手会直接失败。解决办法是加一个只监听回环的"剥头器"（`proxy_protocol off`），把头的部分吃掉再连过去 —— 原服务看到的字节流与直连完全一致。已实测：ClientHello 83 字节进、83 字节出，一个比特都没动。

**原服务的配置不用改。** 如果它本身支持 PROXY protocol，也可以省掉剥头器直接指向它 —— 但多数 TLS 服务不支持，保留剥头器是最省事的做法。

## 操作步骤

### 第一步：把原服务从 443 挪到别的端口

比如 `10443`。这一步脚本不会替你做：脚本不拥有那个服务的配置，改错会让它直接断线。改完先确认它还能用。

### 第二步：确认 nginx 有 stream 模块

不用手动查，`deploy.sh` 会探测并在需要时装上；想自己核对：

```bash
# 能跑通就是有（--with-stream=dynamic 也算，Ubuntu 默认就是动态模块）
printf 'events{}\nstream{server{listen 127.0.0.1:45999; ssl_preread on; proxy_pass 127.0.0.1:45998;}}\n' \
  > /tmp/p.conf && nginx -t -c /tmp/p.conf -p /tmp/ && echo "有 stream"
```

```bash
# 缺的时候这样补：Ubuntu 上 apt install nginx 不会带上它
apt install -y libnginx-mod-stream
ln -sf /usr/share/nginx/modules-available/mod-stream.conf /etc/nginx/modules-enabled/50-mod-stream.conf
```

`nginx -V | grep --with-stream` 那条老命令**不能**用来判断：模块没被 `load_module` 加载时它照样在串里，探不出真实能力。

### 第三步：带参数部署

让向导替你做：

```bash
sudo ./install.sh          # 检测到 443 被占 → 问 y/n → 依次问端口和域名
```

也可以自己拼：

```bash
sudo ./deploy.sh --share-443 --tls-service-port 10443
# 可选：--tls-port 8443（dlproxy 的 http 层）、--strip-port 8441（剥头器）
# 可选：--dlproxy-host dl.example.com（让 dlproxy 也能用域名访问，见下文）
```

`--tls-service-port` 指的是原服务此刻真正在监听的端口。

脚本会做四件事：装 `deploy/nginx-share443.conf` 到 `sites-available/dlproxy`（443 的 server 块改成监听回环 8443）、装 `deploy/nginx-share443-stream.conf` 到 `/etc/nginx/stream-enabled/dlproxy.conf`、把 `stream { include /etc/nginx/stream-enabled/*.conf; }` 追加进 `nginx.conf`（原文件先备份）、最后检查 443 是否起来。

两个容易踩的点：

- **`stream {}` 包裹不能省。** 片段是 `map` / `upstream` / `server` 这类 main 上下文指令，裸 include 会让 nginx 报 `"map" directive is not allowed here`。
- **stream 片段不能放 `sites-enabled/`。** 那个目录是在 `http {}` 上下文里 include 的，放个 `stream {}` 块进去会直接语法错。

### 关于域名：默认只有 IP 能访问 dlproxy

SNI 分流是"有 SNI 就给原服务"，所以**任何域名都会落到原服务上**。后果：

- `https://<IP>/u/<token>/...` → 能用（IP 进不了 SNI，走无 SNI 分支）
- `https://任何域名/u/<token>/...` → 走原服务，报它自己的错

要用域名访问 dlproxy，部署时加 `--domain dl.example.com`（见 [certificates.md](certificates.md)）：它会签域名证书、把 `server_name` 写成该域名、并把该域名自动加进 `map` 抢回 dlproxy，不需要再单独写 `--dlproxy-host`。

`--dlproxy-host` 仍然有用 —— 当你有多个域名都想指向 dlproxy 时，额外的那些写它：

```bash
sudo ./deploy.sh --share-443 --tls-service-port 10443 --dlproxy-host extra.example.com
```

**原服务自己在用的域名不要写进这个参数** —— 写进去那个域名就指不到原服务了。

## 预期监听

```bash
ss -lntp | grep -E ':(443|8443|8441|10443)\b'
# 443    nginx stream（对公网，按 SNI 分流）
# 8443   nginx http（只监听 127.0.0.1，来自 stream 层）
# 8441   nginx stream 剥头器（只监听 127.0.0.1）
# 10443  原服务
```

证书仍然走 :80 上的 http-01，**原服务只占了 443，80 还是 dlproxy 的**，所以证书流程完全不受影响。

## 实测结论

`tools/e2e_share443.py` 加载真实模板跑完整链路，15 项断言全过（已做反向验证：删掉 `--dlproxy-host` 那条规则后，对应断言会准确报 FAIL 而不是静默通过）：

```
PASS  http 片段：proxy_pass 不带 URI: 错误写法=0, 正确写法=1
PASS  http 片段：不再直接占用 443: 已是回环端口
PASS  http 片段：real_ip 取 PROXY 头: 存在
PASS  stream 片段：按 SNI 分流: 存在
PASS  stream 片段：剥头器关闭 PROXY protocol: 存在
PASS  加速链接经 stream + PROXY 全链可下载: HTTP/1.1 200 OK sha256=ebb99394d54c
PASS  含 // 与 %2F 的 URL 没有被 nginx 改写: HTTP/1.1 200 OK
PASS  HTTP/2 经 ssl_preread 协商成功: ALPN=h2
PASS  8 路并发 Range 经全链重组一致: 3145728B / 期望 3145728B
PASS  应用侧拿到真实客户端 IP（PROXY 头透传成功）: transfers.client_ip=127.0.0.1
PASS  原服务分支收到无 PROXY 头的原始 ClientHello: 发 83B / 收 83B
PASS  --dlproxy-host 指定的域名仍能到 dlproxy: HTTP/1.1 200 OK
PASS  明文 HTTP 打到 443 被拒: HTTP/1.1 400 Bad Request
PASS  :80 ACME 路径仍可应答（续期依赖它）: HTTP 200
```

最后一条值得注意：**明文 HTTP 打到 443 会被拒（400）**。`ssl_preread` 无法给非 TLS 字节分类，这是这套方案的固有代价 —— 正常客户端都是 TLS，不影响使用。

## 三个副作用

1. **443 上不再有 `default_server` 兜底。** 任何带 SNI 的域名流量都会转给原服务，包括扫描器与误连的浏览器。原服务会拒掉不认识的 SNI，行为正确，但它会多看到一些流量。
2. **原服务重启，nginx 不感知。** stream 层只做 TCP 转发，它不在时会立刻断连。这跟直连一样，不是新问题。
3. **多了一层 TCP 跳数。** 每条连接多一次回环转发，开销可以忽略，`proxy_timeout 3600s` 已经设好，不会切长大文件。
