from fastapi import FastAPI, Form, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from passlib.hash import argon2
from jose import jwt, JWTError
import json, os, time

# ============================================================
# APP SETUP
# ============================================================
app = FastAPI(
    title="FM Radio Login API",
    description="Login system with roles, JWT, IP-ban, account-ban, and secure dev panel"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# FILES & CONSTANTS
# ============================================================
DB_FILE = "users.json"
BAN_IP_FILE = "banned_ips.json"
BAN_LOG_FILE = "ban_log.json"

DEV_CODE = "17731"   # Required to enter /dev

SECRET_KEY = "CHANGE_THIS_SECRET_KEY_IN_PRODUCTION"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_SECONDS = 3600  # 1 hour

MAX_LOGIN_ATTEMPTS = 5
LOCK_SECONDS = 60

RATE_LIMIT = {}  # (ip, key) -> {count, window_start}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# ============================================================
# JSON LOAD/SAVE HELPERS
# ============================================================
def load_json(path):
    if not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        try:
            return json.load(f)
        except:
            return {}

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def load_users(): return load_json(DB_FILE)
def save_users(data): save_json(DB_FILE, data)
def load_bans(): return load_json(BAN_IP_FILE)
def save_bans(data): save_json(BAN_IP_FILE, data)

def append_ban_log(action, actor="system", username=None, ip=None, reason=None, expires=None):
    data = load_json(BAN_LOG_FILE)
    logs = data.get("logs", [])
    logs.append({
        "time": int(time.time()),
        "action": action,
        "actor": actor,
        "username": username,
        "ip": ip,
        "reason": reason,
        "expires": expires
    })
    data["logs"] = logs
    save_json(BAN_LOG_FILE, data)

# ============================================================
# UTILS
# ============================================================
def get_ip(request: Request):
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real = request.headers.get("X-Real-IP")
    if real:
        return real.strip()
    return request.client.host

def detect_vpn_or_proxy(request: Request, ip: str):
    proxy_headers = ["CF-Connecting-IP", "X-Forwarded-For", "X-Real-IP"]
    hits = sum(1 for h in proxy_headers if h in request.headers)
    private = ("10.", "172.16.", "192.168.", "127.", "::1")
    return hits >= 2 or ip.startswith(private)

def check_rate_limit(ip: str, key: str, limit: int, window: int):
    now = time.time()
    info = RATE_LIMIT.get((ip, key), {"count": 0, "start": now})
    if now - info["start"] > window:
        info = {"count": 0, "start": now}
    info["count"] += 1
    RATE_LIMIT[(ip, key)] = info
    if info["count"] > limit:
        raise HTTPException(429, "Too many requests")

def create_access_token(username, role):
    exp = int(time.time()) + ACCESS_TOKEN_EXPIRE_SECONDS
    return jwt.encode({"sub": username, "role": role, "exp": exp}, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except:
        raise HTTPException(401, "Invalid token")
    users = load_users()
    if data["sub"] not in users:
        raise HTTPException(401, "User not found")
    user = users[data["sub"]]
    user["username"] = data["sub"]
    return user

# ============================================================
# HOME
# ============================================================
@app.get("/")
def home():
    return {"message": "FM Radio Login API is running!"}

# ============================================================
# SIGNUP
# ============================================================
@app.post("/signup")
def signup(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = get_ip(request)
    users = load_users()
    banned_ips = load_bans()

    check_rate_limit(ip, "signup", 5, 60)

    if ip in banned_ips:
        raise HTTPException(403, f"IP banned: {banned_ips[ip].get('reason','No reason')}")

    if username in users:
        raise HTTPException(400, "Username already exists")

    if len(username) < 3 or len(password) < 4:
        raise HTTPException(400, "Username or password too short")

    hashed = argon2.hash(password)

    users[username] = {
        "password": hashed,
        "role": "user",
        "banned": False,
        "ban_reason": None,
        "ban_expires": None,
        "failed_attempts": 0,
        "locked_until": 0,
        "ip": ip,
        "created": int(time.time()),
        "last_login": None,
    }

    save_users(users)

    return {"message": f"Account created for {username}"}

# ============================================================
# LOGIN
# ============================================================
@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = get_ip(request)
    users = load_users()
    banned_ips = load_bans()

    check_rate_limit(ip, "login", 10, 60)

    if ip in banned_ips:
        raise HTTPException(403, f"IP banned: {banned_ips[ip].get('reason','No reason')}")

    if username not in users:
        raise HTTPException(404, "User not found")

    user = users[username]
    now = time.time()

    # Lockout
    if user.get("locked_until", 0) > now:
        sec = int(user["locked_until"] - now)
        raise HTTPException(403, f"Locked. Try again in {sec} sec")

    # Verify password
    try:
        valid = argon2.verify(password, user["password"])
    except:
        valid = False

    if not valid:
        user["failed_attempts"] += 1
        if user["failed_attempts"] >= MAX_LOGIN_ATTEMPTS:
            user["locked_until"] = now + LOCK_SECONDS
        save_users(users)
        raise HTTPException(401, "Incorrect password")

    # Reset fail counters
    user["failed_attempts"] = 0
    user["locked_until"] = 0

    # Ban check
    if user["banned"]:
        if user["ban_expires"] and user["ban_expires"] < now:
            user["banned"] = False
            user["ban_reason"] = None
            user["ban_expires"] = None
        else:
            save_users(users)
            return {
                "message": "User is banned",
                "reason": user["ban_reason"],
                "expires": user["ban_expires"],
                "banned": True
            }

    user["last_login"] = int(now)
    save_users(users)

    token = create_access_token(username, user["role"])
    vpn_flag = detect_vpn_or_proxy(request, ip)

    return {
        "message": f"Welcome back, {username}!",
        "user": username,
        "role": user["role"],
        "access_token": token,
        "token_type": "bearer",
        "vpn_suspected": vpn_flag
    }

# ============================================================
# /me
# ============================================================
@app.get("/me")
async def me(user = Depends(get_current_user)):
    return {
        "username": user["username"],
        "role": user["role"],
        "banned": user["banned"],
        "ban_reason": user["ban_reason"],
        "ban_expires": user["ban_expires"],
        "last_login": user.get("last_login")
    }

# ============================================================
# BAN / UNBAN / DELETE / PROMOTE
# ============================================================
@app.post("/ban")
def ban_user(username: str = Form(...), reason: str = Form("No reason"), duration: int = Form(0)):
    users = load_users()
    banned_ips = load_bans()

    if username not in users:
        raise HTTPException(404, "User not found")

    user = users[username]
    expires = int(time.time()) + duration if duration > 0 else None

    user["banned"] = True
    user["ban_reason"] = reason
    user["ban_expires"] = expires

    if user["ip"]:
        banned_ips[user["ip"]] = {"reason": reason, "expires": expires}

    save_users(users)
    save_bans(banned_ips)

    return {"message": f"{username} banned"}

@app.post("/unban")
def unban_user(username: str = Form(...)):
    users = load_users()
    banned_ips = load_bans()

    if username not in users:
        raise HTTPException(404, "User not found")

    ip = users[username]["ip"]

    users[username]["banned"] = False
    users[username]["ban_reason"] = None
    users[username]["ban_expires"] = None

    if ip in banned_ips:
        del banned_ips[ip]

    save_users(users)
    save_bans(banned_ips)
    return {"message": f"{username} unbanned"}

@app.post("/delete")
def delete_user(username: str = Form(...)):
    users = load_users()

    if username not in users:
        raise HTTPException(404, "User not found")

    del users[username]
    save_users(users)
    return {"message": f"{username} deleted"}

@app.post("/promote")
def promote(username: str = Form(...), role: str = Form("admin")):
    users = load_users()
    if username not in users:
        raise HTTPException(404, "User not found")
    if role not in ["user", "admin", "owner"]:
        raise HTTPException(400, "Invalid role")
    users[username]["role"] = role
    save_users(users)
    return {"message": f"{username} promoted to {role}"}

# ============================================================
# DEV PANEL + BAN LOG
# ============================================================
@app.get("/banlog", response_class=HTMLResponse)
def banlog(code: str = None):
    if code != DEV_CODE:
        return "<h3>Access denied</h3>"

    data = load_json(BAN_LOG_FILE).get("logs", [])
    rows = ""
    for x in reversed(data[-200:]):
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(x["time"]))
        rows += f"<tr><td>{ts}</td><td>{x['action']}</td><td>{x['actor']}</td><td>{x['username']}</td><td>{x['ip']}</td><td>{x['reason']}</td><td>{x['expires']}</td></tr>"

    return f"""
    <html>
    <body style='background:#0f172a;color:white;'>
    <h2>Ban Log</h2>
    <table border=1>
    <tr><th>Time</th><th>Action</th><th>Actor</th><th>User</th><th>IP</th><th>Reason</th><th>Expires</th></tr>
    {rows}
    </table>
    </body>
    </html>
    """

@app.get("/dev", response_class=HTMLResponse)
def dev(code: str = None):
    if code != DEV_CODE:
        return "<h3>Access denied</h3>"

    users = load_users()
    rows = ""
    for u, d in users.items():
        rows += f"<tr><td>{u}</td><td>{d.get('role')}</td><td>{d.get('ip')}</td></tr>"

    return f"""
    <html>
    <body style='background:#0f172a;color:white;'>
    <h2>Developer Panel</h2>
    <table border=1>
    <tr><th>User</th><th>Role</th><th>IP</th></tr>
    {rows}
    </table>
    </body>
    </html>
    """

# ============================================================
# END OF FILE
# ============================================================
