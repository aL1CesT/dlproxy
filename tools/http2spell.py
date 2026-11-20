"""Ask deploy.sh how to spell http2, instead of retyping the rule here.

nginx 1.25.1 added a standalone `http2 on;` directive. Ubuntu 24.04 ships
1.24.0, which only knows the `listen ... ssl http2` parameter form and fails
the whole config with `unknown directive "http2"`. The site templates therefore
carry a bare `__HTTP2_DIRECTIVE__` line, and deploy.sh fills it in after
probing the local nginx.

Every rehearsal tool that renders the template has to go through the same
step. The first two that did not (`e2e_nginx_conf.py` and `e2e_share443.py`)
started failing with `unknown directive "__HTTP2_DIRECTIVE__"` the moment the
templates changed -- which is exactly the drift this module exists to prevent.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEPLOY_SH = ROOT / "deploy" / "deploy.sh"

PLACEHOLDER = "__HTTP2_DIRECTIVE__"


def apply(site: Path, nginx_binary: Path | None) -> None:
    """Fill in the http2 placeholder in `site`, using deploy.sh's own logic.

    `nginx_binary`, when given, is put first on PATH so the probe inside
    deploy.sh sees the same nginx the caller is about to start -- otherwise a
    host with no nginx on PATH always takes the "old spelling" branch.
    """
    env = dict(os.environ)
    if nginx_binary is not None:
        env["PATH"] = (
            f"{Path(nginx_binary).parent.as_posix()}{os.pathsep}{env.get('PATH', '')}"
        )
    env.pop("DLPROXY_HTTP2", None)
    proc = subprocess.run(
        ["bash", "-c",
         f'set +e\nsource "{DEPLOY_SH.as_posix()}"\nset +e\n'
         f'apply_http2_spelling "{site.as_posix()}"'],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=120, env=env,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            "deploy.sh 没有成功应用 http2 写法：\n"
            + (proc.stdout or "") + (proc.stderr or "")
        )
    if PLACEHOLDER in site.read_text(encoding="utf-8"):
        raise RuntimeError(f"http2 占位符 {PLACEHOLDER} 没有被替换掉")
