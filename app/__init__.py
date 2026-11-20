"""dlproxy — a self-hosted download accelerator gateway.

Modules
-------
db        schema, migrations, UTC+8 quota day bucket
ssrf      DNS pinning + peer re-verification at the httpcore TCP layer
urls      byte-exact recovery of the target URL from the raw request line
proxy     streaming relay, redirect walking, byte accounting
quota     metering and the daily/monthly breaker
history   60-second aggregate of concurrent range requests
auth      argon2id passwords, signed cookies, login lockout, access tokens
mailer    background SMTP alerts
main      FastAPI app and the page/admin routes
"""

__version__ = "1.0.0"
