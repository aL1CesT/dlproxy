"""tools/ui_check.py — programmatic render checks for the web pages.

Screenshots alone prove nothing; a person has to look at them. This script
checks the things a person would notice, mechanically:

  * horizontal overflow (the classic "table blew up the layout" bug)
  * elements wider than the viewport
  * text that is invisible (zero size, display:none) where it should not be
  * form controls with no accessible label
  * CSS actually applied (Pico loaded, custom sheet loaded)
  * no console errors, no failed requests
  * contrast of the muted text against its background
  * the token shown on the home page round-trips into the generated link

It runs at desktop and phone widths. Anything it catches is a real visual bug.

    python tools/ui_check.py [--out DIR]
"""
from __future__ import annotations

import argparse
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
ADMIN_PATH = "f3a91c07b58d42e6a0c1d9f4b27e8a56"
ADMIN_TOKEN = "aB3dEfGh1JkLmNoP2qRsTuVwXyZ45678"
ALICE_TOKEN = "Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq0Pp"
PASSWORD = "demo-password-123"
# The address deploy.sh records at install time. The seed writes it so the
# screenshots show what a real deployment shows, not the loopback address the
# ASGI app sees behind Nginx.
PUBLIC_BASE = "https://dlproxy.example.com"


def _force_utf8() -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def wait_for_port(port: int, timeout: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.05)
    return False


SEED = r'''
import sys
sys.path.insert(0, {root!r})
from app import auth, db

conn = db.init_db({dbfile!r})
conn.execute("DELETE FROM users")
conn.execute("DELETE FROM transfers")
conn.execute("DELETE FROM counters")
conn.execute("INSERT INTO users(username,pwd_hash,token,token_active,disabled,is_admin,created_at)"
             " VALUES(?,?,?,1,0,1,?)",
             ("admin", auth.hash_password({pw!r}), {admin_token!r},
              "2026-11-01T00:00:00.000Z"))
conn.execute("INSERT INTO users(username,pwd_hash,token,token_active,disabled,is_admin,created_at)"
             " VALUES(?,?,?,1,0,0,?)",
             ("alice", auth.hash_password({pw!r}), {alice_token!r},
              "2026-11-02T00:00:00.000Z"))
uid = conn.execute("SELECT id FROM users WHERE username='alice'").fetchone()["id"]
rows = [
    ("https://github.com/torvalds/linux/releases/download/v6.12/linux-6.12.tar.gz",
     200, 2147483648, 2147483648, "2026-11-18T02:11:04.120Z", 0, 184320),
    ("https://mirrors.tuna.tsinghua.edu.cn/ubuntu-releases/24.04/ubuntu-24.04.1-live-server-arm64.iso",
     206, 3221225472, 3221225472, "2026-11-18T03:42:11.004Z", 1, 631400),
    ("https://example.com/assets/dataset-2026.tar.zst",
     200, 524288000, 524288000, "2026-11-17T22:05:51.900Z", 0, 41200),
    ("https://cdn.example.org/firmware/device-1.4.2.img",
     499, None, 18874368, "2026-11-17T20:31:02.500Z", 1, 3050),
]
for url, status, size, sent, started, rng, dur in rows:
    conn.execute(
        "INSERT INTO transfers(user_id,url,status_code,size_total,bytes_sent,"
        "started_at,last_at,range_hit,client_ip,user_agent,xff_raw,duration_ms)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (uid, url, status, size, sent, started, started, rng,
         "203.0.113.42", "aria2/1.37.0", "", dur))
    conn.execute("INSERT INTO counters(day,bytes) VALUES(?,?)"
                 " ON CONFLICT(day) DO UPDATE SET bytes=bytes+excluded.bytes",
                 (started[:10], sent))
db.set_setting(conn, "admin_path", {admin_path!r})
db.set_setting(conn, "public_base", {public_base!r})
db.set_setting(conn, "public_host", {public_host!r})
conn.commit()
'''


def main() -> int:
    _force_utf8()
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=str(ROOT / "shots"))
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="dlproxy-ui-"))
    db_path = work / "app.db"
    port = free_port()

    subprocess.run([sys.executable, "-c", SEED.format(
        root=str(ROOT), dbfile=str(db_path), pw=PASSWORD,
        admin_token=ADMIN_TOKEN, alice_token=ALICE_TOKEN,
        admin_path=ADMIN_PATH,
        public_base=PUBLIC_BASE, public_host="dlproxy.example.com")],
        check=True, cwd=str(ROOT))

    serve = work / "serve.py"
    serve.write_text(f'''
import sys
sys.path.insert(0, {str(ROOT)!r})
import uvicorn
from app.main import create_app
app = create_app(db_path_override={str(db_path)!r},
                 allow_private_upstream=True,
                 security_log_path=__import__("pathlib").Path({str(work / "sec.log")!r}))
uvicorn.run(app, host="127.0.0.1", port={port}, log_level="error", access_log=False)
''', encoding="utf-8")
    env = dict(os.environ, DLPROXY_SECRET_KEY="ui-check-secret",
               DLPROXY_BEHIND_PROXY="0")
    proc = subprocess.Popen([sys.executable, str(serve)], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not wait_for_port(port):
        proc.kill()
        print("应用启动失败")
        return 1

    base = f"http://127.0.0.1:{port}"
    results: list[tuple[str, bool, str]] = []

    def check(name: str, ok: bool, evidence: str) -> None:
        results.append((name, ok, evidence))
        print(f"  {PASS if ok else FAIL}  {name}: {evidence}")

    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as pw:
            browser = pw.chromium.launch()

            def login(page) -> None:
                page.goto(f"{base}/login", wait_until="networkidle")
                page.fill('input[name="username"]', "admin")
                page.fill('input[name="password"]', PASSWORD)
                page.click('button[type="submit"]')
                page.wait_for_load_state("networkidle")

            pages = [
                ("login", f"{base}/login", False, 1280, 900),
                ("home", f"{base}/", True, 1280, 900),
                ("admin", f"{base}/{ADMIN_PATH}", True, 1280, 900),
                ("history", f"{base}/{ADMIN_PATH}/history/2", True, 1280, 900),
                ("password", f"{base}/password", True, 1280, 900),
            ]

            for name, url, needs_auth, width, height in pages:
                # Four widths, because the users table breaks in the middle:
                # it fits at 1440 and stacks at 390, but the 641–950 band was
                # exactly where the action column lost its buttons. The 550
                # slot is the uncanny valley on a phone in landscape / a small
                # tablet: narrower than the 640 breakpoint (so the secondary
                # columns are gone) yet wide enough that nobody thinks to test
                # it — a screenshot from exactly there is what exposed six
                # full-width buttons stacking into a six-row-tall card.
                for label, vw, vh in (("desktop", width, height),
                                      ("tablet", 820, 1180),
                                      ("phablet", 550, 1000),
                                      ("mobile", 390, 844)):
                    context = browser.new_context(
                        viewport={"width": vw, "height": vh},
                        device_scale_factor=2)
                    page = context.new_page()
                    console_errors: list[str] = []
                    failed: list[str] = []
                    page.on("console", lambda m: console_errors.append(m.text)
                            if m.type == "error" else None)
                    page.on("requestfailed",
                            lambda r: failed.append(f"{r.url} {r.failure}"))
                    if needs_auth:
                        login(page)
                    page.goto(url, wait_until="networkidle")
                    page.wait_for_timeout(250)

                    # 1. horizontal overflow at the document level
                    overflow = page.evaluate(
                        "() => ({sw: document.documentElement.scrollWidth,"
                        "        cw: document.documentElement.clientWidth})")
                    no_overflow = overflow["sw"] <= overflow["cw"] + 1

                    # 2. any element wider than the viewport. Elements inside a
                    #    horizontal scroll container are legitimate — that is what
                    #    .table-wrap is for — so they are excluded, and a table
                    #    with no wrapper at all is flagged separately.
                    wide = page.evaluate("""() => {
                        const vw = document.documentElement.clientWidth;
                        const bad = [];
                        const inScroller = el => {
                            for (let p = el.parentElement; p; p = p.parentElement) {
                                const ox = getComputedStyle(p).overflowX;
                                if (ox === 'auto' || ox === 'scroll') return true;
                            }
                            return false;
                        };
                        for (const el of document.querySelectorAll('body *')) {
                            const r = el.getBoundingClientRect();
                            if (r.width > vw + 2 && !inScroller(el)
                                && getComputedStyle(el).position !== 'fixed') {
                                bad.push(`${el.tagName}.${el.className}`.slice(0, 48)
                                         + ` w=${Math.round(r.width)}`);
                            }
                        }
                        return bad.slice(0, 4);
                    }""")
                    # A wide table is only acceptable if it scrolls on its own.
                    unwrapped_tables = page.evaluate("""() => {
                        const vw = document.documentElement.clientWidth;
                        const bad = [];
                        for (const t of document.querySelectorAll('table')) {
                            if (t.getBoundingClientRect().width <= vw + 2) continue;
                            const p = t.parentElement;
                            const ox = p ? getComputedStyle(p).overflowX : 'visible';
                            if (ox !== 'auto' && ox !== 'scroll') bad.push(t.className || 'table');
                        }
                        return bad;
                    }""")

                    # 2b. every interactive control sits inside its scroll
                    #     container. A table can overflow its .table-wrap and
                    #     still "pass" the check above (the wrapper scrolls),
                    #     while a button in the last column renders outside the
                    #     wrapper's clip box — reachable only if the user thinks
                    #     to scroll. That is how the admin 删除 button stayed
                    #     half-cut at 1440 px with 66 checks green.
                    clipped = page.evaluate("""() => {
                        const bad = [];
                        for (const el of document.querySelectorAll('button, a[role="button"], input[type="submit"]')) {
                            if (!el.checkVisibility({checkVisibilityCSS: true})) continue;
                            for (let p = el.parentElement; p; p = p.parentElement) {
                                const cs = getComputedStyle(p);
                                if (cs.overflowX !== 'auto' && cs.overflowX !== 'scroll') continue;
                                const pr = p.getBoundingClientRect();
                                const er = el.getBoundingClientRect();
                                if (er.right > pr.right + 1 || er.left < pr.left - 1) {
                                    bad.push(el.textContent.trim().slice(0, 12)
                                             + ` r=${Math.round(er.right)}/${Math.round(pr.right)}`);
                                }
                                break;
                            }
                        }
                        return bad.slice(0, 6);
                    }""")

                    # 2c. six action buttons must not stack into six rows. They
                    #     are stretched full width below 900 px so that a mistap
                    #     cannot land on 删除 — but stretching each onto its own
                    #     line made every account card six buttons tall, which is
                    #     what the 550 px screenshot showed. Count the *buttons*,
                    #     not the children of .actions: the five POST buttons live
                    #     inside a <form> that contributes no box of its own
                    #     (`display: contents`), so anything that walks children
                    #     sees two and can never fail. One row is not required
                    #     either — 历史 plus five buttons cannot fit 390 px — but
                    #     two per row on average is: six buttons must not need
                    #     more than three rows. Comparing against `kids.length`
                    #     (i.e. "all on one line each") is too weak, because a
                    #     form that stays a block box yields 1 + 5 = 5 rows for 6
                    #     buttons and would sneak through — which is exactly what
                    #     the first version of this check did.
                    stacking = page.evaluate("""() => {
                        const bad = [];
                        for (const box of document.querySelectorAll('.actions')) {
                            if (!box.checkVisibility({checkVisibilityCSS: true})) continue;
                            const kids = [...box.querySelectorAll(
                                ':scope > a, :scope > button, :scope > form button')]
                                .filter(k => k.checkVisibility({checkVisibilityCSS: true}));
                            if (kids.length < 4) continue;
                            const tops = new Set(kids.map(
                                k => Math.round(k.getBoundingClientRect().top)));
                            const limit = Math.ceil(kids.length / 2);
                            if (tops.size > limit) {
                                bad.push(`${kids.length} 个按钮排成 ${tops.size} 行（上限 ${limit} 行）`);
                            }
                        }
                        return bad.slice(0, 4);
                    }""")

                    # 3. stylesheets really loaded (a 404 on Pico would leave the
                    #    page readable but unbranded, and tests would still pass)
                    sheets = page.evaluate(
                        "() => Array.from(document.styleSheets).map(s => s.href || 'inline')")
                    css_ok = any("pico" in (h or "") for h in sheets) and \
                        any("app.css" in (h or "") for h in sheets)
                    pico_rules = page.evaluate("""() => {
                        for (const s of document.styleSheets) {
                            if ((s.href || '').includes('pico')) {
                                try { return s.cssRules.length } catch (e) { return -1 }
                            }
                        }
                        return 0;
                    }""")

                    # 4. inputs are labelled
                    unlabelled = page.evaluate("""() => {
                        const out = [];
                        for (const i of document.querySelectorAll('input, select, textarea')) {
                            if (i.type === 'hidden') continue;
                            const id = i.id;
                            const wrap = i.closest('label');
                            const named = id && document.querySelector(`label[for="${id}"]`);
                            const aria = i.getAttribute('aria-label');
                            if (!wrap && !named && !aria) out.push(i.name || i.type);
                        }
                        return out;
                    }""")

                    # 5. visible text is actually visible. `checkVisibility`
                    #    walks ancestors, so a child of a display:none cell is not
                    #    reported as broken text — the cell hid it deliberately.
                    invisible = page.evaluate("""() => {
                        const out = [];
                        for (const el of document.querySelectorAll('p, h1, h2, h3, small, td, th, button, a')) {
                            if (!el.textContent.trim()) continue;
                            if (!el.checkVisibility({checkOpacity: true, checkVisibilityCSS: true})) continue;
                            const r = el.getBoundingClientRect();
                            if (r.width < 1 || r.height < 1) {
                                out.push(`${el.tagName}:${el.textContent.trim().slice(0, 20)}`);
                            }
                        }
                        return out.slice(0, 4);
                    }""")

                    page.screenshot(path=str(out / f"ui-{name}-{label}.png"),
                                    full_page=(name == "admin"))

                    tag = f"{name}/{label}"
                    check(f"{tag} 无横向溢出", no_overflow,
                          f"scrollWidth={overflow['sw']} clientWidth={overflow['cw']}")
                    check(f"{tag} 无超宽元素", not wide, str(wide) if wide else "无")
                    check(f"{tag} 超宽表格可滚动", not unwrapped_tables,
                          str(unwrapped_tables) if unwrapped_tables else "无未包裹表格")
                    check(f"{tag} 控件未被裁切", not clipped,
                          str(clipped) if clipped else "全部在容器内")
                    check(f"{tag} 操作按钮不竖排", not stacking,
                          str(stacking) if stacking else "未排成单列")
                    check(f"{tag} 样式表已加载", css_ok and pico_rules > 100,
                          f"sheets={len(sheets)}, pico 规则数={pico_rules}")
                    check(f"{tag} 表单均有标签", not unlabelled,
                          str(unlabelled) if unlabelled else "全部有标签")
                    check(f"{tag} 无不可见文本", not invisible,
                          str(invisible) if invisible else "正常")
                    check(f"{tag} 无控制台错误", not console_errors,
                          console_errors[0][:70] if console_errors else "无")
                    check(f"{tag} 无失败请求", not failed,
                          failed[0][:70] if failed else "无")
                    context.close()

            # --- behavioural check that only a browser can do ---------------
            context = browser.new_context(viewport={"width": 1280, "height": 900})
            page = context.new_page()
            login(page)
            page.fill("#src", "https://github.com/o/r/releases/download/v1/a.zip")
            page.dispatch_event("#src", "input")
            built = page.input_value("#out")
            expected = (f"{PUBLIC_BASE}/u/{ADMIN_TOKEN}/"
                        f"https://github.com/o/r/releases/download/v1/a.zip")
            check("首页生成加速链接", built == expected, built)

            prefix = page.input_value("#base")
            want_prefix = f"{PUBLIC_BASE}/u/{ADMIN_TOKEN}/"
            check("加速前缀可复制", prefix == want_prefix, prefix)

            # The nav mixes <a role="button"> and a real <button> inside a form.
            # Pico shapes them with different rules (the link also inherits a
            # negative margin), so they rendered 41.6 px and 38.6 px tall — the
            # step is only visible in a browser, which is why it survived the
            # assertion suite. Compare the rendered boxes, not the CSS.
            heights = page.evaluate("""() => {
                const out = [];
                for (const el of document.querySelectorAll(
                        '.site-header a[role="button"], .site-header button')) {
                    if (!el.checkVisibility({checkVisibilityCSS: true})) continue;
                    out.push(Math.round(el.getBoundingClientRect().height * 10) / 10);
                }
                return out;
            }""")
            spread = (max(heights) - min(heights)) if heights else 0
            check("导航控件同高", spread <= 1,
                  f"heights={heights} 差 {spread}px")

            # Every copy affordance is a plain button carrying the id of the
            # element to read. Clicking it must leave a visible confirmation,
            # otherwise the user cannot tell a silent success from a no-op —
            # and on plain http (no secure context) the modern clipboard API is
            # unavailable, so this also exercises the execCommand fallback.
            targets = page.eval_on_selector_all(
                "[data-copy-target]",
                "els => els.map(e => e.dataset.copyTarget)")
            check("复制按钮齐全", sorted(targets) == ["base", "out", "token"],
                  str(sorted(targets)))
            page.click('[data-copy-target="out"]')
            page.wait_for_timeout(150)
            hint = (page.text_content("#hint") or "").strip()
            check("复制有反馈", bool(hint), hint or "(空)")

            # The admin page has to be reachable *back* from the admin page:
            # it lived under /<admin_path> with no way home but the browser's
            # back button, which is exactly where the admin path is hidden.
            page.goto(f"{base}/{ADMIN_PATH}", wait_until="networkidle")
            home_link = page.evaluate("""() => {
                const a = [...document.querySelectorAll('a')]
                    .find(e => e.getAttribute('href') === '/');
                if (!a) return null;
                return {text: a.textContent.trim(),
                        role: a.getAttribute('role'),
                        visible: a.checkVisibility({checkVisibilityCSS: true})};
            }""")
            check("管理页有返回首页的链接",
                  bool(home_link and home_link["visible"]),
                  str(home_link))

            # "My active streams" must be labelled as *mine*: a bare number on
            # the home page would read as the site-wide figure.
            page.goto(f"{base}/", wait_until="networkidle")
            mine = page.evaluate("""() => {
                for (const el of document.querySelectorAll('article.stat')) {
                    if (el.textContent.includes('我的活跃流')) {
                        return el.querySelector('.big')?.textContent.trim();
                    }
                }
                return null;
            }""")
            check("首页显示我的活跃流", mine is not None, f"value={mine!r}")

            # This used to test `/\\S+\\s+\\d+/` against the whole body, which
            # is true on any page carrying "0 B" or "/ 256" — it could not fail.
            # Read the one <small> that sits under the live-stream figure and
            # insist it is either the explicit "nothing running" sentence or a
            # run of "name count" pairs.
            page.goto(f"{base}/{ADMIN_PATH}", wait_until="networkidle")
            detail = page.evaluate("""() => {
                const cells = [...document.querySelectorAll('.grid > div')];
                const cell = cells.find(d => d.textContent.includes('活跃流（全局上限'));
                if (!cell) return null;
                const smalls = [...cell.querySelectorAll('small')];
                if (!smalls.length) return null;
                return smalls[smalls.length - 1].textContent
                    .replace(/\\s+/g, ' ').trim();
            }""")
            # `match`, not `fullmatch`: an orphan footer may legitimately
            # follow the "name count" run.
            shape = re.compile(r"(?:\S+ \d+(?: · )?)+")
            ok = bool(detail) and (
                detail.startswith("当前没有正在传输的连接")
                or shape.match(detail) is not None
            )
            check("管理页显示活跃流分布", ok, f"detail={detail!r}")

            # The connection count is the reason the column exists: assert the
            # header cell is really in the table, not just somewhere in the HTML.
            page.goto(f"{base}/{ADMIN_PATH}/history/2", wait_until="networkidle")
            headers = page.evaluate("""() => [...document.querySelectorAll(
                'table thead th')].map(th => th.textContent.trim())""")
            check("历史表有连接列", "连接" in headers, str(headers))

            # The history URL column used to ellipsise every long link. Assert
            # the cell actually renders its whole value: compute the clipped
            # width instead of trusting the CSS declaration.
            page.goto(f"{base}/", wait_until="networkidle")
            truncated = page.evaluate("""() => {
                const bad = [];
                for (const td of document.querySelectorAll('td.url')) {
                    const cs = getComputedStyle(td);
                    if (cs.textOverflow === 'ellipsis' && cs.whiteSpace === 'nowrap') {
                        bad.push(td.textContent.trim().slice(0, 30));
                    }
                }
                return bad;
            }""")
            check("历史 URL 未被截断", not truncated,
                  str(truncated) if truncated else "完整显示")
            context.close()
            browser.close()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        if not args.keep:
            import shutil
            shutil.rmtree(work, ignore_errors=True)

    failed_items = [r for r in results if not r[1]]
    print()
    print(f"==> {len(results) - len(failed_items)} PASS / {len(failed_items)} FAIL")
    print(f"==> 截图: {out}")
    return 1 if failed_items else 0


if __name__ == "__main__":
    sys.exit(main())
