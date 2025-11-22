from fastapi import FastAPI, Form, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from passlib.hash import bcrypt
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

# Rate limiting store (in-memory)
RATE_LIMIT = {}  # (ip, key) -> {count, window_start}

# JWT auth scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


# ============================================================
# HELPER FUNCTIONS: JSON LOAD/SAVE
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

def load_users():
    return load_json(DB_FILE)

def save_users(d):
    save_json(DB_FILE, d)

def load_bans():
    raw = load_json(BAN_IP_FILE)
    fixed = {}
    for ip, entry in raw.items():
        if isinstance(entry, dict):
            fixed[ip] = {
                "reason": entry.get("reason", "No reason"),
                "expires": entry.get("expires"),
                "ip_only": entry.get("ip_only", False),
            }
        else:
            # legacy: value was just True/False
            fixed[ip] = {
                "reason": "Legacy ban",
                "expires": None,
                "ip_only": False,
            }
    return fixed

def save_bans(d):
    save_json(BAN_IP_FILE, d)

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
# IP / VPN / RATE LIMIT / JWT HELPERS
# ============================================================
def get_ip(request: Request):
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real = request.headers.get("X-Real-IP")
    if real:
        return real.strip()
    return request.client.host

def detect_vpn_or_proxy(request: Request, ip: str) -> bool:
    # Very simple heuristic; not real VPN detection
    proxy_headers = ["CF-Connecting-IP", "X-Forwarded-For", "X-Real-IP", "X-Forwarded-Host", "X-Forwarded-Proto"]
    hits = sum(1 for h in proxy_headers if h in request.headers)
    private_prefixes = ("10.", "172.16.", "192.168.", "127.", "::1")
    if hits >= 2:
        return True
    if ip.startswith(private_prefixes):
        return True
    return False

def check_rate_limit(ip: str, key: str, limit: int, window_seconds: int):
    now = time.time()
    rk = (ip, key)
    info = RATE_LIMIT.get(rk, {"count": 0, "start": now})
    # reset window
    if now - info["start"] > window_seconds:
        info = {"count": 0, "start": now}
    info["count"] += 1
    RATE_LIMIT[rk] = info
    if info["count"] > limit:
        raise HTTPException(429, detail="Too many requests. Slow down.")

def create_access_token(username: str, role: str):
    expire = int(time.time()) + ACCESS_TOKEN_EXPIRE_SECONDS
    to_encode = {"sub": username, "role": role, "exp": expire}
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

async def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = decode_access_token(token)
    username = payload["sub"]
    users = load_users()
    if username not in users:
        raise HTTPException(401, detail="User not found")
    user = users[username]
    user["username"] = username
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

    check_rate_limit(ip, "signup", limit=5, window_seconds=60)

    # Check IP ban
    if ip in banned_ips:
        entry = banned_ips[ip]
        if entry.get("expires") and entry["expires"] < time.time():
            del banned_ips[ip]
            save_bans(banned_ips)
        else:
            raise HTTPException(
                403,
                detail=f"Signup blocked — your IP is banned. Reason: {entry.get('reason', 'No reason')}"
            )

    if username in users:
        raise HTTPException(400, detail="Username already exists")

    if len(username) < 3 or len(password) < 4:
        raise HTTPException(400, detail="Username or password too short")

    # Default role: user
    hashed = bcrypt.hash(password)
    users[username] = {
        "password": hashed,
        "ip": ip,
        "banned": False,
        "ban_reason": None,
        "ban_expires": None,
        "role": "user",
        "failed_attempts": 0,
        "locked_until": 0,
        "last_login": None,
    }

    save_users(users)

    vpn_flag = detect_vpn_or_proxy(request, ip)
    return {
        "message": f"Account created for {username}",
        "vpn_suspected": vpn_flag
    }


# ============================================================
# LOGIN
# ============================================================
@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = get_ip(request)
    users = load_users()
    banned_ips = load_bans()

    check_rate_limit(ip, "login", limit=10, window_seconds=60)

    # IP BAN CHECK
    if ip in banned_ips:
        entry = banned_ips[ip]
        if entry.get("expires") and entry["expires"] < time.time():
            del banned_ips[ip]
            save_bans(banned_ips)
        else:
            raise HTTPException(
                403,
                detail=f"Access denied — your IP is banned. Reason: {entry.get('reason', 'No reason')}"
            )

    if username not in users:
        raise HTTPException(404, detail="User not found")

    user = users[username]
    now = time.time()

    # Lockout check
    locked_until = user.get("locked_until", 0)
    if locked_until > now:
        remaining = int(locked_until - now)
        raise HTTPException(403, detail=f"Too many failed attempts. Try again in {remaining} seconds.")

    stored_pw = user["password"]

    # Hash-aware verify (supports legacy plain-text)
    valid = False
    try:
        if bcrypt.verify(password, stored_pw):
            valid = True
    except Exception:
        # Not a bcrypt hash, fallback to plain comparison
        if stored_pw == password:
            valid = True

    if not valid:
        user["failed_attempts"] = user.get("failed_attempts", 0) + 1
        if user["failed_attempts"] >= MAX_LOGIN_ATTEMPTS:
            user["locked_until"] = now + LOCK_SECONDS
        save_users(users)
        raise HTTPException(401, detail="Incorrect password")

    # Reset failure counters
    user["failed_attempts"] = 0
    user["locked_until"] = 0

    # USER BAN CHECK
    if user.get("banned", False):
        if user.get("ban_expires") and user["ban_expires"] < time.time():
            user["banned"] = False
            user["ban_reason"] = None
            user["ban_expires"] = None
        else:
            save_users(users)
            return {
                "message": "User is banned",
                "banned": True,
                "reason": user.get("ban_reason"),
                "expires": user.get("ban_expires")
            }

    # Successful login
    user["last_login"] = int(now)
    role = user.get("role", "user")
    save_users(users)

    token = create_access_token(username=username, role=role)
    vpn_flag = detect_vpn_or_proxy(request, ip)

    return {
        "message": f"Welcome back, {username}!",
        "user": username,
        "role": role,
        "banned": False,
        "access_token": token,
        "token_type": "bearer",
        "vpn_suspected": vpn_flag
    }


# ============================================================
# JWT-PROTECTED CURRENT USER
# ============================================================
@app.get("/me")
async def read_me(current_user: dict = Depends(get_current_user)):
    # Don't expose password hash
    return {
        "username": current_user["username"],
        "role": current_user.get("role", "user"),
        "banned": current_user.get("banned", False),
        "ban_reason": current_user.get("ban_reason"),
        "ban_expires": current_user.get("ban_expires"),
        "last_login": current_user.get("last_login"),
    }


# ============================================================
# BAN USER (reason + duration)
# ============================================================
@app.post("/ban")
def ban_user(
    username: str = Form(...),
    reason: str = Form("No reason provided"),
    duration: int = Form(0),  # seconds, 0 = permanent
    actor: str = Form("dev_panel"),
):
    users = load_users()
    banned_ips = load_bans()

    if username not in users:
        raise HTTPException(404, detail="User not found")

    user = users[username]
    ip = user.get("ip")

    expires = int(time.time()) + duration if duration > 0 else None

    user["banned"] = True
    user["ban_reason"] = reason
    user["ban_expires"] = expires

    if ip:
        banned_ips[ip] = {
            "reason": reason,
            "expires": expires,
            "ip_only": False,
        }

    save_users(users)
    save_bans(banned_ips)

    append_ban_log("ban_user", actor=actor, username=username, ip=ip, reason=reason, expires=expires)

    return {
        "message": f"{username} banned successfully",
        "reason": reason,
        "expires": expires
    }


# ============================================================
# UNBAN USER
# ============================================================
@app.post("/unban")
def unban_user(username: str = Form(...), actor: str = Form("dev_panel")):
    users = load_users()
    banned_ips = load_bans()

    if username not in users:
        raise HTTPException(404, detail="User not found")

    user = users[username]
    ip = user.get("ip")

    user["banned"] = False
    user["ban_reason"] = None
    user["ban_expires"] = None

    if ip in banned_ips:
        del banned_ips[ip]

    save_users(users)
    save_bans(banned_ips)

    append_ban_log("unban_user", actor=actor, username=username, ip=ip)

    return {"message": f"{username} and IP {ip} have been unbanned."}


# ============================================================
# IP-ONLY BAN / UNBAN
# ============================================================
@app.post("/ban_ip")
def ban_ip(
    ip: str = Form(...),
    reason: str = Form("IP-only ban"),
    duration: int = Form(0),
    actor: str = Form("dev_panel"),
):
    banned_ips = load_bans()
    expires = int(time.time()) + duration if duration > 0 else None

    banned_ips[ip] = {
        "reason": reason,
        "expires": expires,
        "ip_only": True,
    }

    save_bans(banned_ips)
    append_ban_log("ban_ip", actor=actor, ip=ip, reason=reason, expires=expires)

    return {"message": f"IP {ip} banned", "reason": reason, "expires": expires}

@app.post("/unban_ip")
def unban_ip(
    ip: str = Form(...),
    actor: str = Form("dev_panel"),
):
    banned_ips = load_bans()

    if ip in banned_ips:
        del banned_ips[ip]
        save_bans(banned_ips)
        append_ban_log("unban_ip", actor=actor, ip=ip)
        return {"message": f"IP {ip} unbanned"}
    else:
        raise HTTPException(404, detail="IP not found in ban list")


# ============================================================
# DELETE USER
# ============================================================
@app.post("/delete")
def delete_user(username: str = Form(...), actor: str = Form("dev_panel")):
    users = load_users()

    if username not in users:
        raise HTTPException(404, detail="User not found")

    del users[username]
    save_users(users)

    append_ban_log("delete_user", actor=actor, username=username)

    return {"message": f"Deleted account '{username}'"}


# ============================================================
# PROMOTE USER ROLE (user -> admin)
# ============================================================
@app.post("/promote")
def promote_user(username: str = Form(...), role: str = Form("admin"), actor: str = Form("dev_panel")):
    users = load_users()

    if username not in users:
        raise HTTPException(404, detail="User not found")

    if role not in ("user", "admin", "owner"):
        raise HTTPException(400, detail="Invalid role")

    users[username]["role"] = role
    save_users(users)

    append_ban_log("promote_user", actor=actor, username=username, reason=f"Role -> {role}")

    return {"message": f"User '{username}' promoted to role '{role}'"}


# ============================================================
# LOGOUT
# ============================================================
@app.post("/logout")
def logout():
    # JWT is stateless; client should discard token.
    return {"message": "Logged out (discard your token client-side)"}


# ============================================================
# BAN LOG VIEWER
# ============================================================
@app.get("/banlog", response_class=HTMLResponse)
def view_banlog(code: str = None):
    if code != DEV_CODE:
        return """
        <html><body style='background:#0f172a;color:white;font-family:Poppins;'>
        <div style='margin:auto;width:320px;padding-top:100px;text-align:center;'>
            <h2>Ban Log Access</h2>
            <form>
                <input name='code' placeholder='Enter access code'>
                <button>View</button>
            </form>
        </div>
        </body></html>
        """
    data = load_json(BAN_LOG_FILE)
    logs = data.get("logs", [])
    rows = ""
    for entry in reversed(logs[-200:]):  # show last 200
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(entry["time"]))
        rows += f"""
        <tr>
            <td class='px-3 py-2 text-xs text-slate-300'>{ts}</td>
            <td class='px-3 py-2 text-xs'>{entry.get('action')}</td>
            <td class='px-3 py-2 text-xs'>{entry.get('actor')}</td>
            <td class='px-3 py-2 text-xs'>{entry.get('username') or '—'}</td>
            <td class='px-3 py-2 text-xs'>{entry.get('ip') or '—'}</td>
            <td class='px-3 py-2 text-xs'>{entry.get('reason') or '—'}</td>
            <td class='px-3 py-2 text-xs'>{entry.get('expires') or '—'}</td>
        </tr>
        """
    return f"""
    <html>
    <head>
        <script src="https://cdn.tailwindcss.com"></script>
        <title>Ban Log</title>
    </head>
    <body class="bg-slate-950 text-slate-100 min-h-screen p-6">
        <h1 class="text-2xl font-semibold mb-4 text-cyan-400">Ban Log</h1>
        <div class="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/70">
            <table class="min-w-full text-left text-xs">
                <thead class="bg-slate-900/90 text-slate-400">
                    <tr>
                        <th class="px-3 py-2">Time</th>
                        <th class="px-3 py-2">Action</th>
                        <th class="px-3 py-2">Actor</th>
                        <th class="px-3 py-2">User</th>
                        <th class="px-3 py-2">IP</th>
                        <th class="px-3 py-2">Reason</th>
                        <th class="px-3 py-2">Expires</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>
        <a href="/dev?code={DEV_CODE}" class="inline-block mt-4 text-cyan-400 text-sm hover:underline">Back to Dev Panel</a>
    </body>
    </html>
    """


# ============================================================
# DEV PANEL (TAILWIND UI)
# ============================================================
@app.get("/dev", response_class=HTMLResponse)
def dev_panel(request: Request, code: str = None):
    if code != DEV_CODE:
        return """
        <html>
        <head>
            <title>Developer Access</title>
            <style>
                body {
                    background:#0f172a; color:#f1f5f9;
                    display:flex; align-items:center; justify-content:center;
                    height:100vh; font-family: Poppins, system-ui, sans-serif;
                }
                .box {
                    background:#1e293b; padding:30px;
                    border-radius:10px; text-align:center;
                    width:340px;
                    box-shadow:0 0 20px rgba(0,0,0,0.4);
                }
                input {
                    padding:10px; border-radius:6px;
                    border:none; width:200px; margin-bottom:10px;
                    background:#334155; color:white;
                    font-size:16px;
                }
                button {
                    padding:10px 16px; border-radius:6px;
                    border:none; cursor:pointer;
                    background:#38bdf8; color:black;
                    font-weight:700; font-size:15px;
                }
            </style>
        </head>
        <body>
            <div class="box">
                <h2>🔐 Developer Access</h2>
                <p>Enter access code:</p>
                <form method="get">
                    <input type="text" name="code" placeholder="Enter code">
                    <br>
                    <button type="submit">Unlock</button>
                </form>
            </div>
        </body>
        </html>
        """

    users = load_users()
    banned_ips = load_bans()
    now = time.time()

    # User rows
    user_rows = ""
    for username, info in users.items():
        ip = info.get("ip", "Unknown")
        banned = info.get("banned", False)
        reason = info.get("ban_reason", "—")
        expires = info.get("ban_expires", None)
        role = info.get("role", "user")
        last_login = info.get("last_login")
        online = (
            last_login is not None and (now - last_login <= 600)
        )
        status_label = "🚫 Banned" if banned else ("🟢 Online" if online else "⚪ Offline")
        expires_str = expires if expires else "No limit"

        user_rows += f"""
        <tr class="border-b border-slate-800/80 hover:bg-slate-800/40">
            <td class="px-3 py-2 text-xs font-mono text-slate-100">{username}</td>
            <td class="px-3 py-2 text-xs text-slate-300">{ip}</td>
            <td class="px-3 py-2 text-xs">{status_label}</td>
            <td class="px-3 py-2 text-xs">{role}</td>
            <td class="px-3 py-2 text-xs text-slate-300">{reason}</td>
            <td class="px-3 py-2 text-xs text-slate-400">{expires_str}</td>
            <td class="px-3 py-2 text-xs">
                <form action="/ban" method="post" class="inline-flex gap-1 mb-1">
                    <input type="hidden" name="username" value="{username}">
                    <input type="hidden" name="actor" value="dev_panel">
                    <input class="bg-slate-900/70 border border-slate-700 rounded px-1 py-0.5 text-[10px] text-slate-200" type="text" name="reason" placeholder="Reason">
                    <input class="bg-slate-900/70 border border-slate-700 rounded px-1 py-0.5 w-16 text-[10px] text-slate-200" type="number" name="duration" placeholder="Secs">
                    <button class="bg-red-500/90 hover:bg-red-500 text-white rounded px-2 py-0.5 text-[10px]">Ban</button>
                </form>
                <form action="/unban" method="post" class="inline-block mb-1">
                    <input type="hidden" name="username" value="{username}">
                    <input type="hidden" name="actor" value="dev_panel">
                    <button class="bg-emerald-500/90 hover:bg-emerald-500 text-white rounded px-2 py-0.5 text-[10px]">Unban</button>
                </form>
                <form action="/delete" method="post" class="inline-block mb-1">
                    <input type="hidden" name="username" value="{username}">
                    <input type="hidden" name="actor" value="dev_panel">
                    <button class="bg-rose-600/80 hover:bg-rose-600 text-white rounded px-2 py-0.5 text-[10px]">Delete</button>
                </form>
                <form action="/promote" method="post" class="inline-flex gap-1">
                    <input type="hidden" name="username" value="{username}">
                    <input type="hidden" name="actor" value="dev_panel">
                    <select name="role" class="bg-slate-900/70 border border-slate-700 rounded px-1 py-0.5 text-[10px] text-slate-200">
                        <option value="user" {"selected" if role=="user" else ""}>user</option>
                        <option value="admin" {"selected" if role=="admin" else ""}>admin</option>
                        <option value="owner" {"selected" if role=="owner" else ""}>owner</option>
                    </select>
                    <button class="bg-sky-500/90 hover:bg-sky-500 text-white rounded px-2 py-0.5 text-[10px]">Set</button>
                </form>
            </td>
        </tr>
        """

    # IP ban rows
    ip_rows = ""
    for ip, entry in banned_ips.items():
        reason = entry.get("reason", "—")
        expires = entry.get("expires", None)
        ip_only = entry.get("ip_only", False)
        expires_str = expires if expires else "No limit"
        tag = "IP-only" if ip_only else "User-linked"
        ip_rows += f"""
        <tr class="border-b border-slate-800/80 hover:bg-slate-800/40">
            <td class="px-3 py-2 text-xs font-mono text-slate-100">{ip}</td>
            <td class="px-3 py-2 text-xs text-slate-300">{tag}</td>
            <td class="px-3 py-2 text-xs text-slate-300">{reason}</td>
            <td class="px-3 py-2 text-xs text-slate-400">{expires_str}</td>
            <td class="px-3 py-2 text-xs">
                <form action="/unban_ip" method="post" class="inline-block">
                    <input type="hidden" name="ip" value="{ip}">
                    <input type="hidden" name="actor" value="dev_panel">
                    <button class="bg-emerald-500/90 hover:bg-emerald-500 text-white rounded px-2 py-0.5 text-[10px]">Unban IP</button>
                </form>
            </td>
        </tr>
        """

    return f"""
    <html>
    <head>
        <title>FM Developer Panel</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-slate-950 text-slate-100 min-h-screen">
        <div class="max-w-6xl mx-auto py-6 px-4 space-y-6">
            <header class="flex items-center justify-between">
                <div>
                    <h1 class="text-2xl font-semibold text-cyan-400">🛠️ FM Radio Developer Panel</h1>
                    <p class="text-xs text-slate-400 mt-1">Manage users, bans, roles, and IP bans.</p>
                </div>
                <a href="/banlog?code={DEV_CODE}" class="text-xs text-cyan-300 hover:text-cyan-200 underline">View Ban Log</a>
            </header>

            <div class="grid md:grid-cols-3 gap-4">
                <div class="col-span-2 bg-slate-900/70 border border-slate-800 rounded-xl overflow-hidden">
                    <div class="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
                        <h2 class="text-sm font-semibold text-slate-100">Users</h2>
                        <span class="text-[11px] text-slate-400">Total: {len(users)}</span>
                    </div>
                    <div class="overflow-x-auto">
                        <table class="min-w-full text-left text-xs">
                            <thead class="bg-slate-900/90 text-slate-400">
                                <tr>
                                    <th class="px-3 py-2">Username</th>
                                    <th class="px-3 py-2">IP</th>
                                    <th class="px-3 py-2">Status</th>
                                    <th class="px-3 py-2">Role</th>
                                    <th class="px-3 py-2">Ban Reason</th>
                                    <th class="px-3 py-2">Ban Expires</th>
                                    <th class="px-3 py-2">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {user_rows}
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class="bg-slate-900/70 border border-slate-800 rounded-xl overflow-hidden">
                    <div class="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
                        <h2 class="text-sm font-semibold text-slate-100">IP Bans</h2>
                        <span class="text-[11px] text-slate-400">Total: {len(banned_ips)}</span>
                    </div>
                    <div class="overflow-x-auto">
                        <table class="min-w-full text-left text-xs">
                            <thead class="bg-slate-900/90 text-slate-400">
                                <tr>
                                    <th class="px-3 py-2">IP</th>
                                    <th class="px-3 py-2">Type</th>
                                    <th class="px-3 py-2">Reason</th>
                                    <th class="px-3 py-2">Expires</th>
                                    <th class="px-3 py-2">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {ip_rows}
                            </tbody>
                        </table>
                    </div>
                    <div class="px-4 py-3 border-t border-slate-800">
                        <form action="/ban_ip" method="post" class="space-y-1">
                            <input type="hidden" name="actor" value="dev_panel">
                            <div class="flex gap-2">
                                <input name="ip" placeholder="IP address"
                                    class="flex-1 bg-slate-950/80 border border-slate-700 rounded px-2 py-1 text-[11px] text-slate-100">
                            </div>
                            <div class="flex gap-2">
                                <input name="reason" placeholder="Reason"
                                    class="flex-1 bg-slate-950/80 border border-slate-700 rounded px-2 py-1 text-[11px] text-slate-100">
                                <input name="duration" type="number" placeholder="Secs"
                                    class="w-20 bg-slate-950/80 border border-slate-700 rounded px-2 py-1 text-[11px] text-slate-100">
                            </div>
                            <button class="mt-1 bg-red-500/90 hover:bg-red-500 text-white rounded px-3 py-1 text-[11px]">
                                Ban IP
                            </button>
                        </form>
                    </div>
                </div>
            </div>

        </div>
    </body>
    </html>
    """


# ============================================================
# END OF FILE
# ============================================================
