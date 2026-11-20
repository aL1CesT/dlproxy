# 部署

[文档索引](README.md) · [项目首页](../README.md)

## 前置条件

- Ubuntu 24.04，含 minimal aarch64 镜像；root 或 sudo
- 公网 IPv4。证书两条路线：有域名用域名证书（`--domain`，约 90 天，自动续期），没域名用 IP 证书（约 6 天，每次续期都要重跑 http-01）。对照见 [certificates.md](certificates.md)
- 云防火墙（安全组 / Security List）放行 **TCP 80 与 443**。这一步只能在云控制台做：`deploy.sh` 不改云资源，探测到 80 不通会停下并提示你去处理
- 443 已被别的服务占用时无需搬端口，见 [share-443.md](share-443.md)
- 磁盘：代码与虚拟环境约 200 MB；日志目录有 5 GB 上限，备份保留 7 天

## 在服务器上取代码

**全部操作都在服务器上完成，不需要另一台机器中转。** 安装器只读取源码目录里的文件，跑完就把它们拷进 `/opt/dlproxy`，之后源码目录可以删。

### 方式一：下载 tarball（推荐）

`curl` 是 Ubuntu 的基础包，minimal 镜像也有；不用装 git。

```bash
curl -fL https://github.com/aL1CesT/dlproxy/archive/refs/heads/main.tar.gz | tar xz
cd dlproxy-main
sudo ./install.sh
```

tarball 里保留了执行位 —— 12 个脚本（根 `install.sh`、根 `deploy.sh`、`deploy/*.sh`、`tools/*.sh`）都是 `0755`，`tar xz` 之后可以直接执行。

### 方式二：git clone

要 `git pull` 升级时用这条。`git` 不在 `deploy.sh` 的依赖清单里，需要先手动装：

```bash
sudo apt-get install -y git
git clone --depth 1 https://github.com/aL1CesT/dlproxy.git
cd dlproxy
sudo ./install.sh
```

### 不要用 `curl … | bash`

```bash
# 这样跑不起来，不是用法问题，是 bash 的行为
curl -fsSL …/install.sh | bash
```

管道执行时 `BASH_SOURCE[0]` 是空串，`dirname ""` 得到 `.`，脚本算不出自己的目录，`deploy/install.sh` 就找不到了。先下载成文件再执行。

### 从开发机传（可选，不是必需）

如果你确实想把一台机器上的修改带上服务器：

```bash
python tools/make_upload.py --out . --keep ./dlproxy-upload
scp -r dlproxy-upload user@<IP>:/tmp/
ssh user@<IP> 'cd /tmp/dlproxy-upload/dlproxy && sudo ./install.sh'
```

- `./dlproxy-upload/dlproxy/` —— 可直接 `scp -r` 的文件夹
- `./dlproxy-upload.zip` —— 同样的内容，但 unix 权限位写在 zip 里

> **Windows 注意**：`scp -r` 从 NTFS 传出去的文件一律没有执行位，服务器上 `sudo ./install.sh` 会 `permission denied`。zip 里那 12 个脚本已经钉成 `0755`，`unzip` 会还原 —— 前提是 zip 里每个条目都声明自己来自 Unix（`create_system = 3`）；`unzip` 只在那种条目上读权限位，Windows 上打出来的 zip 默认写 `create_system = 0`（MS-DOS），权限位会被整个忽略。`tools/make_upload.py` 已经钉死这一点，并有测试盯着。只能传文件夹时，落地后先跑一遍：
>
> ```bash
> chmod +x /tmp/dlproxy-upload/dlproxy/*.sh /tmp/dlproxy-upload/dlproxy/deploy/*.sh /tmp/dlproxy-upload/dlproxy/tools/*.sh
> ```
>
> 服务器上没有 `unzip` 时（minimal 镜像通常没有）：`apt install -y unzip`，或用 `python3 -m zipfile -e dlproxy-upload.zip .` —— 后者**不还原权限位**，解完仍要 `chmod`。

### 包里有什么

约 870 KB（83 个文件）。

| 路径 | 必需 | 说明 |
| --- | --- | --- |
| `install.sh` / `deploy.sh` | 必需 | 根目录的转发入口，参数原样交给 `deploy/` 里的同名脚本 |
| `app/*.py`（15 个） | 必需 | 服务本体。`menu.py` 是交互菜单，`cli.py` 是逐条命令 |
| `app/templates/*.html`（7 个） | 必需 | 缺失时页面 500，服务仍能起 |
| `app/static/*`（2 个） | 必需 | `pico.min.css` 是 vendored 的，不联网取 |
| `requirements.txt` | 必需 | 7 个直接依赖 |
| `deploy/deploy.sh` | 必需 | 安装器本体 |
| `deploy/env.example` | 必需 | 首次部署用它生成 `.env` 并填入随机密钥 |
| `deploy/dlproxy.service` | 必需 | systemd unit |
| `deploy/nginx.conf` | 必需 | 站点模板。share-443 模式改用下面两个 |
| `deploy/nginx-share443.conf` + `nginx-share443-stream.conf` | 可选 | 443 被其他服务占用时需要 |
| `deploy/logrotate.conf` / `cron` / `backup.sh` / `cert-check.sh` / `renewal-hook.sh` | 必需 | 日志轮转、每日备份、证书自检与续期钩子 |
| `deploy/dlproxy-cli.sh` | 必需 | 安装成 `/usr/local/bin/dlproxy` |
| `deploy/uninstall.sh` | 可选 | 卸载时才用 |
| `deploy/install.sh` | 可选 | 交互式向导（根 `install.sh` 转发到它） |
| `tools/`（13 个） | 可选 | 验证工具，`verify_acceptance.py` 要在服务器上跑 |
| `tests/`（11 个测试文件 + `conftest.py`） | 可选 | 约 200 KB，服务器上不需要 |
| `README.md` / `docs/` / `CHANGELOG.md` / `LICENSE` / `CONTRIBUTING.md` / `SECURITY.md` / `pytest.ini` / `requirements-dev.txt` | 可选 | 文档与许可证 |

只留运行集（去掉 `tests/`、`tools/`、文档）约 380 KB；`deploy.sh` 不引用 `tools/`，去掉它们不影响部署。

**不该带的东西**：`.env`（含密钥，服务器上会重新生成）、`data/`（本机数据库）、`shots/`、`docs/screenshots/`、`__pycache__/`。`.gitignore` 已全部排除，`tools/make_upload.py` 从 `git ls-files` 取清单，天然不含这些。

## 部署

```bash
ssh user@<IP>
cd /tmp/dlproxy-upload/dlproxy
sudo ./install.sh
```

**推荐先跑 `install.sh`** —— 它是向导，把 `deploy.sh` 那堆 flag 变成几个 y/n 问题。
下面这段是 `sudo ./install.sh --dry-run` 的实际输出（这台机器 443 上跑着别的 TLS 服务），回答依次是「共用 443 / 原服务在 10443 / 不要域名 / 申请证书 / 用 IP 证书 / 全量」：

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  dlproxy 安装向导
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  系统      Ubuntu 24.04.5 LTS / aarch64 / 2 核
  安装目录  /opt/dlproxy

  ── 当前状态 ──────────────────────────────────────────
  80        空闲
  443       占用（xray）
  8080      占用（python）
  nginx     尚未安装（stage deps 阶段安装）

  ── 443 归谁 ──────────────────────────────────────────
[!] 443 当前被 xray 占用。若要独占 443，需先停止该服务。
  可选方案：
    y = 共用 443（nginx 按 SNI 分流；客户端仍连接 443，配置无需改动）
    n = 不共用，退出；请自行停止 xray 后重试
?  是否与已有的 TLS 服务共用 443？ [Y/n] 

  ── 共用 443 的参数 ───────────────────────────────────
  共用模式下由 nginx 接管 443 并执行 SNI 分流。同一端口不能由两个进程监听，
  因此 443 交由 nginx，原服务改在自身端口上等待 nginx 转发。
  **客户端无需改动**：仍连接 域名:443，由 nginx 按 SNI 转发至原服务的新端口。

  当前还有以下端口处于监听状态（与本次选择无关，列出以免误以为原服务在其中）：
    8080 10443

?  原服务在哪个端口对外提供服务？ [10443] 
==> 10443 已处于监听状态，原服务就位
==> dlproxy 回环 TLS 端口：8443，PROXY 剥头器：8441

  默认仅 https://<IP>/... 可访问 dlproxy —— 因为 IP 不参与 SNI。
  若有域名同样指向本机，可将其分配给 dlproxy，
  否则该域名将继续转发至原服务。
?  是否给 dlproxy 分配一个域名？ [y/N] 

  ── 证书 ──────────────────────────────────────────────
  Let's Encrypt 有两种证书：IP 证书（约 6 天，每次续期都要重跑 http-01）
  与域名证书（约 90 天，剩余 30 天自动续期）。有域名时优先用域名证书。
  前提：公网 80 端口可达（需在云防火墙放行 TCP 80 与 443）。
  跳过申请则保留临时自签证书，浏览器会提示证书不受信任，但服务可正常使用。
?  是否现在申请正式证书？ [Y/n] 
?  是否用域名申请证书（否则用 IP 证书）？ [y/N] 
  IP 证书约 6 天有效期，每次续期都要重跑 http-01（80 端口必须长期开放）。

  ── 执行范围 ──────────────────────────────────────────
  all = 依赖 → 应用 → nginx → 证书 → 收尾（全新机器选此项）
?  是否只执行某一阶段（调试或续跑用）？ [y/N] 

  ── 即将执行的命令 ────────────────────────────────────
  sudo bash /tmp/dlproxy-upload/dlproxy/deploy/deploy.sh --share-443 --tls-service-port 10443 --tls-port 8443 --strip-port 8441 --stage all

  ── 安装完成后的预期监听 ──────────────────────────────
    443       nginx stream（按 SNI 分流）
    8443      dlproxy（回环，仅接受 stream 层转来的连接）
    8441      PROXY 剥头器（回环）
    10443     原服务（你自己的 TLS 服务）

==> --dry-run：仅预览，未执行任何安装动作
```

它自己**不做任何安装动作**，问完把参数拼好交给 `deploy.sh`。三种用法：

| 用法 | 作用 |
| --- | --- |
| `sudo ./install.sh` | 逐条询问（推荐） |
| `sudo ./install.sh --yes` | 全部取推荐值，不问（CI / 重装 / 先看默认值） |
| `sudo ./install.sh --dry-run` | 只打印将要执行的命令，不动手 |

会问到的决定，按出现顺序：

1. **443 被占用时怎么办** —— 先看 443 上是谁，分四种：
   - 本机 nginx 且 `dlproxy` 已在跑 → 识别为重装，**不问**；
   - 本机 nginx / apache2 / httpd / caddy 且 dlproxy 没装 → 同样是「接管」，**不问**：脚本 reload 那个实例并在里面新增 dlproxy 站点，别的 server 块不动。这种进程改不了端口，共用模式（stream 层独占 443）对它没有意义；
   - 常见的 TLS 服务（隧道 / 反代 / 面板）→ 给 share-443 的 y/n；
   - 其它进程 → 说明它无法被接管，只在 `y` 时才尝试共用，默认 `n`。
2. **原服务在哪个端口对外服务** —— 默认取它现在真正在用的端口（从已知 TLS 服务的监听端口里找），找不到才从 `10443` 往上挑一个空闲的。填 1024 以下的特权端口、或被别的进程占着的端口会被挡回来重问。
3. **原服务还没搬过去就停下** —— 你填的端口上没有服务在听（说明它还在 443 上），向导**问完这一个问题就停**，不会让你接着白答域名和证书，而是给出「先改端口 → 重启 → 确认在听 → 重跑」的步骤。`--dry-run` 例外，它会把完整命令打出来。
4. **443 已空出来、但原服务已在别的端口** —— 不会默不作声按独占模式装，而是问一句要不要让 443 也能进原服务：答 `y` 则 nginx 接管 443，带域名的 TLS 转给原服务、IP 直连的走 dlproxy；答 `n` 则 443 只归 dlproxy。**两种都不影响现有的 `域名:服务端口` 链接**，`y` 只是多给一个 443 入口。
5. **回环端口** —— 自动从 8443 / 8441 往上找空闲的。
6. **证书** —— 是否现在申请、是否用域名申请。
7. **只跑某一段吗** —— 调试 / 续跑时用，否则全量。

答完会打印完整命令行和预期监听，确认 `y` 才真的执行。**读到 EOF 一律当取消**，所以 `sudo ./install.sh < /dev/null` 不会静默接受全部默认值。

### 直接用 deploy.sh

同样是幂等的，分六个阶段，可以单独跑某一段（括号里是全程位置，单跑某个阶段时也照此编号）：

```bash
sudo ./deploy.sh --stage deps    # 1–2  环境预检、apt 包与 venv
sudo ./deploy.sh --stage app     # 3    环境文件、数据库、systemd unit
sudo ./deploy.sh --stage nginx   # 4    nginx 站点
sudo ./deploy.sh --stage cert    # 5    Let's Encrypt 证书
sudo ./deploy.sh --stage final   # 6    logrotate、cron、端口核对
```

每个阶段开头有一条通栏标题，阶段内再分小节：

```
阶段 1/6  环境预检 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

==> 系统：Ubuntu 24.04.5 LTS / aarch64 / 2 核
==> 根分区可用空间：48251 MiB
==> 80 / 443 / 8080 端口检查通过

（此处省略阶段 2–4）

阶段 5/6  准备 HTTPS 证书 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  有效期 6 天，每 80 小时自动续期（Let's Encrypt IP 证书）
==> 证书标识: 203.0.113.9（IP）
==> 公网 IP: 203.0.113.9
  ── 前置检查 ──────────────────────────────────────────
==> 探测 80 端口公网可达性（ACME HTTP-01 需要）
==> 80 端口可达（HTTP 301）
```

`--stage cert` 仍然是 `阶段 5/6` —— 编号是它在整轮安装里的位置，不是这次的第一个。

全部参数（`sudo ./deploy.sh --help` 打印的也是这份）：

| 参数 | 作用 |
| --- | --- |
| `--stage all\|deps\|app\|nginx\|cert\|final` | 只跑某个阶段（默认 `all`） |
| `--domain HOST` | 用域名签发证书（默认用 IP 证书），见 [certificates.md](certificates.md) |
| `--share-443` | 与已占用 443 的其他 TLS 服务共存，见 [share-443.md](share-443.md) |
| `--tls-service-port N` | `--share-443` 时原服务的监听端口（必填） |
| `--dlproxy-host HOST` | share-443 时把某个域名的 SNI 抢回 dlproxy |
| `--tls-port N` | share-443 时 dlproxy 的回环 TLS 端口（默认 8443） |
| `--strip-port N` | share-443 时 PROXY 剥头器的端口（默认 8441） |
| `--skip-cert` | 跳过证书签发，先用临时自签证书跑起来 |

**443 已经被别的服务占用时**，先把那个服务搬到 `10443` 并重启，确认 `ss -lntp | grep 10443` 看得见，再：

```bash
sudo ./deploy.sh --share-443 --tls-service-port 10443
```

顺序不能颠倒：反过来跑（服务还在 443、却告诉脚本 10443）预检会拒绝并打出正确顺序。嫌麻烦就用 `install.sh`，它会替你判断这一步。

**443 上是本机的 nginx** 时不用上面这套 —— 不需要搬端口，也不需要 `--share-443`（stream 层会把 443 从那个 nginx 手里拿走）。直接 `sudo ./deploy.sh`：脚本 reload 现有的 nginx，在它里面新增 dlproxy 站点，其它 `server` 块保持原样。

有一件事需要知道：nginx 每个 `listen 443 ssl` 只能有一个 `default_server`。dlproxy 的站点会在**没人占用默认位**时声明它，这样无 SNI 的 IP 直连（`https://<IP>/u/...`）才落到 dlproxy。如果 `sites-available/` 里已经有别的站点声明了 `default_server`，脚本不会去抢（抢了 `nginx -t` 直接报 `a duplicate default server`），而是在 stderr 说明是哪个文件挡住的，并把加速链接的可用地址让给域名。这种情况加 `--domain` 部署即可。

### 首次运行之后

会打印初始管理员密码，同时写进 `/opt/dlproxy/INITIAL_ADMIN.txt`（0600）：

```
用户名: admin
密码:   <24 位随机>
管理入口: /<32 位随机路径>
```

**这个文件只在库里还没有管理员时才写。** 重装、续跑、换机器但沿用旧 `data/app.db` 时都不会再生成 —— 密码不会凭空变出来第二次。忘了就 `sudo dlproxy` 选 4 重置。

安装结束会打出站点地址、管理页完整 URL、`INITIAL_ADMIN.txt` 的绝对路径与对应命令：

```
  ── 后续步骤 ────────────────────────────────────────────

  1) 访问站点      https://203.0.113.9
  2) 管理页        https://203.0.113.9/8f3a1c6d94e2b70a5c8d13f6a9b4e072
  3) 初始账号文件  /opt/dlproxy/INITIAL_ADMIN.txt
     查看          sudo cat /opt/dlproxy/INITIAL_ADMIN.txt
     用完删除      sudo rm  /opt/dlproxy/INITIAL_ADMIN.txt

  4) 建号 / 看加速链接： 输入 dlproxy 回车，进交互菜单
```

重装（库里已有管理员）时那一段长这样 —— 管理页 URL 仍给得出来（从数据库的 `admin_path` 取），但不会再叫你去 `cat` 一个没写的文件：

```
  1) 访问站点      https://203.0.113.9
  2) 管理页        https://203.0.113.9/a1b2c3d4
  3) 初始密码      本次未生成（库中已存在管理员，密码仅在首次安装时写入）
     如需重置      sudo dlproxy   → 选择 4（重置密码）
```

地址取自这次签下的证书标识（IP 或 `--domain` 的域名），并记进数据库的 `public_base`，所以 `dlproxy` 菜单里每一处链接都是可直接复制的真实地址。想改随时：

```bash
sudo dlproxy set-site https://1.2.3.4      # 也可以在菜单里选 11
```

## 建号

三种方式等价：管理面板、交互菜单、逐条命令。

**交互菜单**（推荐，不用记参数）：

```bash
sudo dlproxy          # 等价于 dlproxy menu
```

```
╭──────────────────────────────────────────────╮
│              dlproxy 管理控制台              │
│             https://203.0.113.9              │
├──────────────────────────────────────────────┤
│   账号                                       │
│      1  账号列表                             │
│      2  新建账号                             │
│      3  新建管理员                           │
│      4  重置密码                             │
│      5  查看 token 与加速链接                │
│      6  重置 token                           │
│      7  启用 / 禁用账号                      │
│                                              │
│   用量                                       │
│      8  用量与限额                           │
│                                              │
│   运维                                       │
│      9  备份数据库                           │
│     10  服务状态与管理入口                   │
│     11  设置站点地址                         │
├──────────────────────────────────────────────┤
│      q  退出                                 │
╰──────────────────────────────────────────────╯
```

十一项按用途分成三组，编号仍是连续的 1–11（文档和向导里说的「选 11」照旧有效）。框宽跟随终端，画出来的框在 42–62 列之间（`menu_width()` 返回的是两条竖线之间那段横线的长度，比框少两列）。标题下那行是当前记录的站点地址；还没记录时不显示，第一次进菜单会提示你选 `11` 填一次。`5` 查看 token 与加速链接，给出可直接打开的完整链接，例如 `https://203.0.113.9/u/<token>/https://example.com/big.iso`。

**管理面板**：登录后导航栏有「管理」按钮，页面里的「新建账号」填用户名、密码、是否管理员。重名会提示「该用户名已存在」，不会覆盖已有账号 —— 覆盖会让别人手上的加速链接静默失效。

**逐条命令**（适合脚本）：

```bash
sudo -u dlproxy /opt/dlproxy/venv/bin/python -m app createuser alice
sudo -u dlproxy /opt/dlproxy/venv/bin/python -m app createadmin boss
sudo -u dlproxy /opt/dlproxy/venv/bin/python -m app listusers
sudo -u dlproxy /opt/dlproxy/venv/bin/python -m app showtoken alice
sudo -u dlproxy /opt/dlproxy/venv/bin/python -m app setpassword alice
```

`/usr/local/bin/dlproxy` 这个 wrapper 只做三件事：无参数时补上 `menu`（否则 `python -m app` 会直接起服务器）、降权到 `dlproxy` 用户、转交给 venv 里的解释器。**降权是必须的** —— 用 root 跑会在 `data/` 里留下 root 属主的 `-wal` / `-shm`，之后服务自己就写不进数据库。root 调用时它会自动 `sudo -u dlproxy`。

`--db` 可以放在任意位置，`dlproxy listusers --db /tmp/x.db` 与 `dlproxy --db /tmp/x.db listusers` 都认。

## 卸载

```bash
sudo ./deploy/uninstall.sh            # 停服务、删配置，保留 data/ backup/ .env
sudo ./deploy/uninstall.sh --purge    # 连数据和密钥一起删，会单独提示 .env
```

## 运维速查

| 项目 | 位置 / 命令 |
| --- | --- |
| 服务状态 | `systemctl status dlproxy` |
| 实时日志 | `journalctl -u dlproxy -f` |
| 安全日志（SSRF 拦截、登录失败、熔断、坏 token） | `/var/log/dlproxy/security.log`，保留 90 天 |
| 数据库 | `/opt/dlproxy/data/app.db`（WAL 模式） |
| 每日备份 | 03:00，`/opt/dlproxy/backup/app_YYYY-MM-DD.db`，保留 7 天 |
| 证书检查 | 每 6 小时，`/var/log/dlproxy/cert.log` |
| 交互式菜单 | `sudo dlproxy` |

备份使用 SQLite 的 `.backup` / Python `backup()` API，**不是 `cp`**：WAL 模式下 `cp app.db` 会漏掉最近的提交，还可能复制到写了一半的页。

## 管理面板

路径是 `settings.admin_path`（32 位随机串），非管理员访问返回 404 而非 403 —— 路径本身就是一道门禁，说「存在但无权限」等于泄露它。面板里能做：

- 账号：新建、禁用 / 启用、重置密码、重置 token、启用 / 停用 token、删除
- 限额：日 / 月上限（GB）、全局活跃流上限、单 token 活跃流上限、流空闲超时、每用户历史条数、历史每页条数、证书告警阈值
- 每账号今日 / 本月用量表、全站实时并发数
- 熔断手动解封（按小时）
- 任意账号的历史查看（只读，带分页）
- SMTP 配置与发送测试邮件
- 重新生成管理路径（旧路径立即 404）
