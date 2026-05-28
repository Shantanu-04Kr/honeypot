from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
import random

router = APIRouter()

# ── Fake admin / login pages ──────────────────────────────────────────────────

FAKE_LOGIN_HTML = """
<!DOCTYPE html><html><head><title>Admin Login</title>
<style>body{{font-family:Arial;background:#1a1a2e;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}}
.box{{background:#16213e;padding:40px;border-radius:8px;width:320px}}
h2{{color:#e94560;text-align:center}}input{{width:100%;padding:10px;margin:10px 0;box-sizing:border-box;background:#0f3460;border:none;color:#fff;border-radius:4px}}
button{{width:100%;padding:10px;background:#e94560;border:none;color:#fff;border-radius:4px;cursor:pointer}}
.err{{color:#e94560;text-align:center;font-size:13px;margin-top:8px}}</style></head>
<body><div class="box"><h2>🔒 Admin Panel</h2>
<form method="POST"><input name="username" placeholder="Username" required>
<input name="password" type="password" placeholder="Password" required>
<button type="submit">Login</button></form>
{error}</div></body></html>
"""


@router.get("/admin", response_class=HTMLResponse)
@router.get("/admin/login", response_class=HTMLResponse)
@router.get("/wp-admin", response_class=HTMLResponse)
@router.get("/wp-login.php", response_class=HTMLResponse)
@router.get("/administrator", response_class=HTMLResponse)
@router.get("/login", response_class=HTMLResponse)
@router.get("/dashboard", response_class=HTMLResponse)
async def fake_login_get(request: Request):
    return HTMLResponse(FAKE_LOGIN_HTML.format(error=""))


@router.post("/admin", response_class=HTMLResponse)
@router.post("/admin/login", response_class=HTMLResponse)
@router.post("/wp-admin", response_class=HTMLResponse)
@router.post("/wp-login.php", response_class=HTMLResponse)
@router.post("/login", response_class=HTMLResponse)
async def fake_login_post(request: Request, username: str = Form(default=""), password: str = Form(default="")):
    # Always fail — log the credentials attempt via middleware
    error = '<p class="err">Invalid credentials. Try again.</p>'
    return HTMLResponse(FAKE_LOGIN_HTML.format(error=error), status_code=401)


# ── Fake API endpoints ────────────────────────────────────────────────────────

@router.get("/api/users")
@router.get("/api/v1/users")
async def fake_users():
    return JSONResponse([
        {"id": 1, "username": "admin", "email": "admin@company.internal", "role": "superadmin"},
        {"id": 2, "username": "dbuser", "email": "db@company.internal", "role": "dba"},
        {"id": 3, "username": "devops", "email": "devops@company.internal", "role": "ops"},
    ])


@router.get("/api/config")
@router.get("/api/v1/config")
async def fake_config():
    return JSONResponse({
        "db_host": "postgres://admin:S3cr3tP@ss@db.internal:5432/prod",
        "redis_url": "redis://:redispass@cache.internal:6379",
        "jwt_secret": "HS256_SUPER_SECRET_DO_NOT_SHARE",
        "env": "production",
    })


@router.get("/api/keys")
@router.get("/api/tokens")
async def fake_keys():
    return JSONResponse({
        "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
        "aws_secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "stripe_key": "sk_live_51FakeKeyForHoneypot",
    })


# ── Fake file endpoints ───────────────────────────────────────────────────────

@router.get("/.env")
async def fake_env():
    return HTMLResponse("""DB_PASSWORD=Passw0rd123!
SECRET_KEY=django-insecure-honeypot
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
SENDGRID_API_KEY=SG.fake-honeypot-key
""", media_type="text/plain")


@router.get("/etc/passwd")
@router.get("/../etc/passwd")
@router.get("/proc/self/environ")
async def fake_passwd():
    return HTMLResponse("""root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
ubuntu:x:1000:1000:ubuntu:/home/ubuntu:/bin/bash
""", media_type="text/plain")


@router.get("/backup.sql")
@router.get("/dump.sql")
@router.get("/db_backup.sql")
async def fake_sql_dump():
    return HTMLResponse("""-- MySQL dump 10.13  Distrib 8.0.26
-- Host: localhost    Database: production
CREATE TABLE users (id INT, username VARCHAR(50), password VARCHAR(255), email VARCHAR(100));
INSERT INTO users VALUES (1,'admin','$2b$12$FakeBcryptHashForHoneypot','admin@company.com');
""", media_type="text/plain")


# ── Fake shell / RCE endpoints ────────────────────────────────────────────────

@router.get("/shell")
@router.post("/shell")
@router.get("/cmd")
@router.post("/cmd")
async def fake_shell(request: Request, cmd: str = ""):
    fake_outputs = {
        "id": "uid=0(root) gid=0(root) groups=0(root)",
        "whoami": "root",
        "ls": "bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  srv  sys  tmp  usr  var",
        "pwd": "/var/www/html",
        "uname -a": "Linux prod-server 5.15.0-1034-aws #38-Ubuntu SMP x86_64 GNU/Linux",
        "cat /etc/shadow": "Permission denied",
    }
    output = fake_outputs.get(cmd.strip(), f"bash: {cmd}: command not found")
    return JSONResponse({"output": output, "exit_code": 0})


# ── Catch-all for other probing ───────────────────────────────────────────────

@router.get("/{full_path:path}")
@router.post("/{full_path:path}")
async def catch_all(request: Request, full_path: str):
    # Return a generic 404 that looks like a real server
    return HTMLResponse(
        "<html><head><title>404 Not Found</title></head>"
        "<body><h1>Not Found</h1><p>The requested URL was not found.</p>"
        "<hr/><address>Apache/2.4.41 (Ubuntu) Server at localhost Port 80</address></body></html>",
        status_code=404
    )
