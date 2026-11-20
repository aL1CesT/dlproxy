# 证书

[文档索引](README.md) · [项目首页](../README.md)

证书是整套部署里最容易出事的一块。IP 证书的规则与域名证书不一样，本文内容都经 letsencrypt.org 文档与 certbot 5.10 源码核对过。

## 两条路线怎么选

| | 没域名（默认） | 有域名（`--domain`） |
| --- | --- | --- |
| 证书有效期 | 约 160 小时（不到 7 天） | 约 90 天，剩 30 天自动续期 |
| profile | 必须 `--preferred-profile shortlived` | 默认 profile |
| 续期负担 | 每 80 小时重跑一次 http-01，**80 端口必须长期开放** | 同样要 80，但一年只跑几次 |
| 访问方式 | `https://<IP>/u/<token>/<链接>` | `https://dl.example.com/u/<token>/<链接>` |
| nginx `server_name` | `_`（通配，不看 Host） | 该域名 |
| 证书名 / lineage | `/etc/letsencrypt/live/<IP>/` | `/etc/letsencrypt/live/dl.example.com/` |
| share-443 下的 SNI | 只有 IP 直连（无 SNI）能到 dlproxy | 该域名自动进 `map`，抢回 dlproxy |

**域名要做的唯一准备**：把 `dl.example.com` 的 A/AAAA 记录指向这台机器的公网 IP，并在云控制台放行 TCP 80 与 443。`deploy.sh --stage cert` 会先探测 `http://dl.example.com/` 是否可达，不通就停下并告诉你去改 DNS 还是改安全组。

```bash
# 有域名
sudo ./deploy.sh --domain dl.example.com

# 有域名 + 443 被别的服务占着（域名会自动加进 SNI 分流，不需要再写 --dlproxy-host）
sudo ./deploy.sh --share-443 --tls-service-port 10443 --domain dl.example.com
```

向导里对应的问题是「是否用域名申请证书（否则用 IP 证书）？」，答 y 后填域名即可。域名会自动转小写（DNS 不区分大小写，证书只认小写），并且**同时**写进 `--dlproxy-host` 的效果里 —— 否则 share-443 模式下这个域名的流量会继续走原服务，证书签了也用不上。

已经在跑 IP 证书的机器想换成域名证书，重跑一次 `--stage cert` 即可：

```bash
sudo ./deploy.sh --stage cert --domain dl.example.com
sudo systemctl reload nginx
```

旧的 IP 证书不会自动删（`/etc/letsencrypt/live/<IP>/`），确认域名访问正常后可以 `certbot delete --cert-name <IP>`。`deploy/cert-check.sh` 按「nginx 实际加载的那张 → `public_base` 指向的那张 → 全部 lineage 里最早到期的一张」三级顺序找证书，所以两张并存时也不会盯错。

## IP 证书的续期节奏

- 有效期约 **160 小时**（不到 7 天），必须用 `--preferred-profile shortlived`
- certbot ≥ 4.0 对短命证书按**寿命一半**判定续期，即签发后约 **80 小时**自动续。不需要手工设 `renew_before_expiry` —— 设了反而会和内部逻辑打架
- **不要自己写 `certbot renew` 的 cron。** snap 自带 `snap.certbot.renew.timer`（每日约 2 次、随机偏移秒），正好满足 Let's Encrypt「每天至少查两次 ARI」的建议。手写定时器只会和它抢
- **绝对不要把 `--force-renewal` 放进定时任务。** `每 7 天 5 张 / 同一组标识符` 这条限制没有豁免通道，循环一次就把这个 IP 锁一周

### 每 80 小时要重新验证一次

`shortlived` profile 的**授权复用期只有 7 小时**，远短于 80 小时的续期间隔。所以每次续期都会**重新跑一遍 http-01 验证**：

> **80 端口必须长期对公网开放，不是只在首次签发时开放。**

IP 证书不能用 dns-01，certbot 对 IP 只有 http-01 一条路。

## 四个容易踩的 certbot 细节

| 项 | 正确的做法 | 常见的错法 |
| --- | --- | --- |
| 标识符参数 | `--ip-address <IP>` | 用 `-d <IP>`（能跑，但语义含糊） |
| profile | `--preferred-profile shortlived` | `--profile`（旧名）/ `--required-profile`（无 fallback，profile 变动即续期失败） |
| 续期钩子 | 放 `/etc/letsencrypt/renewal-hooks/deploy/` | 命令行 `--deploy-hook`（只在首签时给过才会写进续期配置） |
| 装证书 | nginx 手工指向 `/etc/letsencrypt/live/<IP>/` | 以为 certbot 会自动装（IP 证书不支持 nginx/apache 插件） |

## 巡检与告警

`dlproxy-cert-check`（每 6 小时，由 cron 拉起）同时看两件事，因为它们坏的时间点不同：

1. **剩余寿命**：阈值来自管理面板的「证书剩余告警阈值（天）」—— 默认 3 天，即 ≤72 小时 WARN、≤36 小时 CRIT（CRIT 恒为 WARN 的一半）。脚本每 6 小时用 `sqlite3` 读一次 `settings.cert_warn_days`，所以面板上那个字段是真的在驱动阈值，不是摆设。用小时不用天，因为这个尺度上天太粗。
2. **自动化新鲜度**：续期钩子每次成功签发 / 续期都会 touch `/var/lib/certbot/last-success`。这个文件超过 96 小时没更新，就说明**续期已经坏了** —— 即使当前证书还剩几天。这个信号比到期告警早约 60 小时。

两个信号都通过 `python -m app alert-cert` 发邮件（复用面板里的 SMTP 设置）。脚本每 6 小时跑一次，所以按状态去重：`settings.cert_alert_state` 记住上一次告警的档位，同档位不重发，恢复正常时清空。没有这一步，一张卡在 CRIT 的证书两天会发出 8 封一模一样的邮件。

### 它盯的是哪张证书

一台机器上可能同时躺着几张证书：先按 IP 签过，后来加了域名又签了一张，而 nginx 只加载其中一张。**盯错比不盯更糟**——要么对着一张没人用的证书报警，要么在真正在用的那张到期时保持沉默。所以脚本按权威性递减取第一个能用的来源：

| 顺序 | 来源 | 判据 | 输出里的标记 |
| --- | --- | --- | --- |
| 1 | `sites-available/dlproxy` 里的 `ssl_certificate` | 只有它代表 nginx 此刻真的在服务的文件 | `nginx 站点配置` |
| 2 | `settings.public_base` 里的主机名 | 站点文件读不到（自定义布局）时的意图记录，主机名转小写 | `public_base (…)` |
| 3 | 扫 `/etc/letsencrypt/live/*/fullchain.pem`，取最早到期 | 没有别的线索时的兜底 | `扫描 …（最早到期）` |

每次运行都会打一行 `cert-check: 检查对象来源：…`，并跟着进邮件正文。真选错时要能从这行看出是哪条规则做的决定，而不是重新猜。第 1 档指向一个已被删除的 lineage 时会**自动降级**到第 2 档，不会就此失败。

只看到期时间的话，你会在证书真的快过期时才知道续期一直失败 —— 第二条信号就是为了提前这点时间。

```bash
# 查证书剩余时间
sudo certbot certificates

# 查续期定时器
systemctl list-timers --all | grep certbot

# 查续期历史
sudo journalctl -u snap.certbot.renew --since '-3 days'

# 手动跑一次健康检查
sudo /usr/local/bin/dlproxy-cert-check; echo "exit=$?"
```

## 失败一次还有多久

按 80 小时续期、160 小时过期算：**约 80 小时（3.3 天）缓冲**。snap 定时器每天跑 2 次，所以一次续期失败有 6–7 次重试机会才会真的过期。

## 换公网 IP 的后果

IP 证书绑死在那个 IP 上。换 IP 之后旧证书立即失效，必须先在云控制台把新 IP 绑好、确认 80 端口可达，再 `sudo ./deploy.sh --stage cert`。在证书签下来之前，服务对外不可用。

有域名的话没有这个问题：换 IP 只需改 A/AAAA 记录，证书跟着域名走。
