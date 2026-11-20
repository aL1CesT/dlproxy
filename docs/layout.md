# 目录结构

[文档索引](README.md) · [项目首页](../README.md)

```
dlproxy/
├── install.sh              根目录入口：参数原样交给 deploy/install.sh
├── deploy.sh               根目录入口：参数原样交给 deploy/deploy.sh
├── requirements.txt        7 个运行时直接依赖（服务器上用）
├── requirements-dev.txt    测试依赖（pytest / pytest-asyncio / playwright，只在开发机）
├── app/                    应用本体（FastAPI，单进程）
│   ├── main.py             路由、生命周期、SSRF 中间件挂载
│   ├── proxy.py            转发主流程：并发闸门、重定向、流式转交、计量
│   ├── ssrf.py             出站连接层：DNS pinning、peer 复验、网段判定
│   ├── urls.py             从原始字节还原目标 URL，以及目标合法性校验
│   ├── quota.py            日 / 月熔断判定与自愈
│   ├── history.py          下载历史（60 秒窗口聚合、按人裁剪）
│   ├── auth.py             账号、token、会话、锁定
│   ├── flash.py            一次性提示（凭据不进 URL）
│   ├── mailer.py           SMTP 告警与自检
│   ├── menu.py             交互式菜单（`dlproxy` 无参进入）
│   ├── cli.py              子命令（建号、改密、备份、set-site、alert-cert）
│   ├── db.py               schema、默认设置、增量迁移、时间口径
│   ├── filters.py          Jinja2 过滤器
│   ├── templates/          7 个页面：base / login / password / home / admin / admin_history / breaker
│   └── static/             app.css + vendored pico.min.css（不走 CDN）
├── deploy/                 部署与运维（全部随包上传，服务器上就地执行）
│   ├── install.sh          交互式安装向导（问完拼出 deploy.sh 命令行）；由根 install.sh 转发
│   ├── deploy.sh           六阶段幂等部署；也可以用 DLPROXY_LIB_ONLY=1 source 取函数
│   ├── uninstall.sh        卸载（默认保留 data/、backup/、.env）
│   ├── dlproxy-cli.sh      装到 /usr/local/bin/dlproxy，降权到服务账号再进菜单
│   ├── dlproxy.service     systemd 单元（含 LimitNOFILE=65535 等加固项）
│   ├── nginx.conf          独占 443 的站点配置
│   ├── nginx-share443.conf 443 被别的 TLS 服务占用时的 http 层片段
│   ├── nginx-share443-stream.conf  同一场景的 stream 层片段（按 SNI 分流）
│   ├── cert-check.sh       证书健康检查（每 6 小时，cron 拉起）
│   ├── renewal-hook.sh     装进 certbot 的 deploy hook，成功后打时间戳
│   ├── backup.sh           SQLite 在线备份（用 backup API，不是 cp）
│   ├── logrotate.conf      日志轮转与总量上限
│   ├── cron                定时任务（备份 + 证书巡检）
│   └── env.example         `.env` 模板（只存一个密钥）
├── tests/                  11 个 pytest 文件 + conftest.py，577 个用例
│   ├── conftest.py         app_client / db 等 fixture
│   ├── test_urls.py        原始字节还原与目标校验
│   ├── test_ssrf.py        网段判定、NAT64/6to4/mapped 拆包
│   ├── test_proxy.py       转发主流程、并发、熔断告警、中断入账
│   ├── test_auth.py        密码、token、会话、锁定
│   ├── test_quota.py       计量与日 / 月边界（UTC+8）
│   ├── test_web.py         页面、表单、分页、一次性提示、密码修改
│   ├── test_menu.py        交互菜单的每一个动作
│   ├── test_db_and_cli.py  schema、迁移、子命令
│   ├── test_deploy_sh.py   deploy.sh 与证书脚本（真 nginx / 真 openssl）
│   ├── test_install_sh.py  向导的每个分支（假 ss / 假 systemctl）
│   └── test_entrypoints.py 根目录两个转发入口、requirements-dev、打包器的执行位与无 git 兜底
├── tools/                  本地验证与打包（不上服务器也能跑）
│   ├── verify_all.sh       一条命令跑完下面四组 + pytest
│   ├── e2e_nginx.sh        上面那条的 bash 版（不依赖 pytest，可在服务器上自检）
│   ├── e2e_nginx.py        真 nginx：13 项，含「带斜杠会改写 URL」的反证
│   ├── e2e_nginx_conf.py   真 nginx 加载 deploy/nginx.conf：6 项
│   ├── e2e_full.py         nginx → uvicorn → 上游整链：7 项
│   ├── e2e_share443.py     443 共存全链：15 项
│   ├── ui_check.py         四档视口 × 五页面：210 项
│   ├── http2spell.py       按本机 nginx 版本填 `http2` 写法（供两个 e2e 复用）
│   ├── nginxbin.py         找 nginx 可执行文件（用 is_file 而不是 exists）
│   ├── shot.py             截图
│   ├── verify_acceptance.py 验收清单半自动执行器
│   ├── range_download.sh   16 线程 Range 下载脚本
│   └── make_upload.py      打上传包（zip 里钉住 0755 执行位）
├── docs/                   分册文档（本目录）
├── CHANGELOG.md            已修问题与版本变更
├── CONTRIBUTING.md         开发约定与提交前检查
├── SECURITY.md             安全边界与报告渠道
├── LICENSE                 MIT
├── requirements.txt        7 个直接依赖，不冻结传递依赖
└── pytest.ini              pytest 配置
```

## 几处刻意的安排

**`deploy/` 全部随包上传。** `deploy.sh` 在服务器上就地执行，不做成 pip 包。这样升级就是「重新覆盖 `deploy/` 再跑一次」，不需要理解打包系统。

**`tools/` 不上服务器。** 它们依赖真 nginx 与本机 playwright，服务器上没有也不需要。`deploy.sh` 不引用 `tools/` 里的任何文件 —— 最小上传集去掉 `tools/`、`tests/`、`docs/` 仍然能部署。

**`app/` 里没有 `models.py` 或 `services/`。** 这个规模的项目分到那个粒度只会增加跳转成本。`db.py` 管 schema，`proxy.py` 是唯一有复杂状态的地方。

**`tests/` 与 `tools/` 的分工。** `tests/` 是纯 pytest，不依赖外部进程（除了两个脚本测试用真 nginx / 真 openssl）。`tools/` 里的 `e2e_*.py` 起真进程做整链验证 —— 它们慢（合计约 40 秒），所以不进 pytest。
