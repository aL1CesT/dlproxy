# 参与开发

## 环境

- Python 3.12（生产目标版本；3.11+ 也能跑测试）
- 需要 `nginx` 可执行文件才能跑 e2e（`tools/nginxbin.py` 会依次找 `--nginx` 参数、`$PATH`、以及若干常见路径）
- 不需要数据库服务、不需要 docker

```bash
python -m venv .venv
. .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt
python -m playwright install chromium      # tools/ui_check.py 需要这个浏览器
```

`requirements-dev.txt` 只装开发机需要的测试依赖（pytest / pytest-asyncio / playwright），服务器上只装 `requirements.txt` 就够了。

## 提交前必须跑的两条命令

```bash
tools/verify_all.sh /usr/sbin/nginx      # 5 组：pytest + 四组真 nginx e2e
python tools/ui_check.py                 # 四档视口 × 五个页面，210 项
```

`verify_all.sh` 的 5 组是：pytest、原始 URI 契约、`deploy/nginx.conf` 模板本身、整链（nginx → 应用 → 上游）、443 共存。Windows 上传完整路径；`--nginx /usr/sbin/nginx` 也认，两种写法等价。

**不传 nginx 路径就只跑 pytest**，其余四组会打印「跳过」并以 0 退出 —— 看到「跳过」不代表通过。显式传了一个不可执行的路径时脚本会 `exit 2`，不会假装通过。

两组都通过才算改完。`tools/verify_acceptance.py` 要在真服务器上跑，开发机上跑不了（它验的是公网可达性与证书）。

## 改动前的约定

- **不要引入新的运行时依赖**，除非它列进 `requirements.txt` 并说明理由。依赖只钉直接版本，不冻结传递依赖 —— 冻结在 x86 上的 wheel tag 到 arm64 会找不到。
- **`.sh` 与 `.py` 一律 LF**，仓库里有 `.gitattributes` 兜底；改了之后用 `read_bytes().count(b"\r\n") == 0` 核对一遍。
- **改文案必须同步测试**。测试里有大量 `assert "…" in out`，改一句界面文字就会红一片；这是刻意的，别为了通过而放宽断言。
- **改了 nginx 模板，同步 `tests/test_deploy_sh.py` 与两个 e2e 工具的占位符替换链**。模板里的 `__XXX__` 占位符少替换一个，渲染出来的配置就是废的。

## 测试的写法

- 用 `tests/conftest.py` 的 `app_client` fixture，它起真实的 ASGI 应用（`TestClient` + `https://testserver`，因为 cookie 带 `Secure`）。
- 设置 `DLPROXY_INIT_FILE` 指到临时目录，否则 `_bootstrap()` 会把一个真实的管理员密码写进工作树。
- 涉及 nginx 的断言，把渲染后的配置喂给真 `nginx -t`，不要只做字符串匹配 —— 字符串匹配测不出「这行在错误的上下文里」。
- 每修一个缺陷，先写一个会红的测试，再改代码。反向验证也很重要：把修复撤掉，确认测试确实变红。

## 报告问题

请附上：

1. `deploy.sh` / `install.sh` 的完整输出
2. `nginx -t` 的结果
3. `ss -lntp | grep -E ':(80|443|8080|8443|8441)'`
4. `journalctl -u dlproxy -n 100 --no-pager`
5. 你实际执行的命令行（**把 token 和公网 IP 抹掉**）
