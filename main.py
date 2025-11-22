from fastapi import FastAPI, Form, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import json, os, time

app = FastAPI(title="FM Radio Login API", description="Login system with IP-ban, account-ban, and secure dev panel")

# =========================
# CORS
# =========================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================
# FILES
# =========================
DB_FILE = "users.json"
BAN_IP_FILE = "banned_ips.json"

DEV_CODE = "17731"   # Required to enter /dev


# =========================
# HELPER FUNCTIONS
# =========================
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
    return load_json(BAN_IP_FILE)

def save_bans(d):
    save_json(BAN_IP_FILE, d)


# REAL IP SUPPORT (Render, Cloudflare, Nginx, etc.)
def get_ip(request: Request):
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()

    real = request.headers.get("X-Real-IP")
    if real:
        return real.strip()

    return request.client.host


# ===============================
# HOME
# ===============================
@app.get("/")
def home():
    return {"message": "FM Radio Login API is running!"}


# ===============================
# SIGNUP
# ===============================
@app.post("/signup")
def signup(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = get_ip(request)
    users = load_users()
    banned_ips = load_bans()

    # IP ban check
    if ip in banned_ips:
        entry = banned_ips[ip]

        # Auto-unban if expired
        if entry.get("expires") and entry["expires"] < time.time():
            del banned_ips[ip]
            save_bans(banned_ips)
        else:
            raise HTTPException(
                403,
                detail=f"Signup blocked — IP banned. Reason: {entry.get('reason', 'No reason')}"
            )

    if username in users:
        raise HTTPException(400, detail="Username already exists")

    users[username] = {
        "password": password,
        "ip": ip,
        "banned": False,
        "ban_reason": None,
        "ban_expires": None
    }

    save_users(users)
    return {"message": f"Account created for {username}"}


# ===============================
# LOGIN
# ===============================
@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = get_ip(request)
    users = load_users()
    banned_ips = load_bans()

    # IP BAN CHECK
    if ip in banned_ips:
        entry = banned_ips[ip]

        # Auto-unban expired IP bans
        if entry.get("expires") and entry["expires"] < time.time():
            del banned_ips[ip]
            save_bans(banned_ips)
        else:
            raise HTTPException(
                403,
                detail=f"Access denied — IP banned. Reason: {entry.get('reason', 'No reason')}"
            )

    if username not in users:
        raise HTTPException(404, detail="User not found")

    user = users[username]

    if user["password"] != password:
        raise HTTPException(401, detail="Incorrect password")

    # USER BAN CHECK
    if user.get("banned", False):
        # Auto-expire user ban
        if user.get("ban_expires") and user["ban_expires"] < time.time():
            user["banned"] = False
            user["ban_reason"] = None
            user["ban_expires"] = None
            save_users(users)
        else:
            return {
                "message": "User is banned",
                "banned": True,
                "reason": user.get("ban_reason"),
                "expires": user.get("ban_expires")
            }

    return {"message": f"Welcome back, {username}!", "user": username, "banned": False}


# ===============================
# BAN USER (reason + time)
# ===============================
@app.post("/ban")
def ban_user(
    username: str = Form(...),
    reason: str = Form("No reason provided"),
    duration: int = Form(0)  # seconds, 0 = permanent
):
    users = load_users()
    banned_ips = load_bans()

    if username not in users:
        raise HTTPException(404, detail="User not found")

    user = users[username]
    ip = user.get("ip")

    expires = int(time.time()) + duration if duration > 0 else None

    # USER BAN
    user["banned"] = True
    user["ban_reason"] = reason
    user["ban_expires"] = expires

    # IP BAN
    if ip:
        banned_ips[ip] = {
            "reason": reason,
            "expires": expires
        }

    save_users(users)
    save_bans(banned_ips)

    return {
        "message": f"{username} banned successfully",
        "reason": reason,
        "expires": expires
    }


# ===============================
# UNBAN USER
# ===============================
@app.post("/unban")
def unban_user(username: str = Form(...)):
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

    return {"message": f"{username} and IP {ip} have been unbanned."}


# ===============================
# DELETE USER
# ===============================
@app.post("/delete")
def delete_user(username: str = Form(...)):
    users = load_users()

    if username not in users:
        raise HTTPException(404, detail="User not found")

    del users[username]
    save_users(users)

    return {"message": f"Deleted account '{username}'"}


# ===============================
# LOGOUT
# ===============================
@app.post("/logout")
def logout():
    return {"message": "Logged out"}



# ============================================================
# SECURE DEVELOPER PANEL
# ============================================================
@app.get("/dev", response_class=HTMLResponse)
def dev_panel(request: Request, code: str = None):
    # Access code required
    if code != DEV_CODE:
        return """
        <html><body style='background:#0f172a;color:white;font-family:Poppins;'>
        <div style='margin:auto;width:300px;padding-top:100px;text-align:center;'>
            <h2>Developer Access</h2>
            <form>
                <input name='code' placeholder='Enter access code'>
                <button>Enter</button>
            </form>
        </div>
        </body></html>
        """

    users = load_users()
    banned_ips = load_bans()

    rows = ""
    for username, info in users.items():
        ip = info.get("ip", "Unknown")
        is_banned = info.get("banned")
        reason = info.get("ban_reason", "—")
        expires = info.get("ban_expires", "No limit")

        rows += f"""
        <tr>
            <td>{username}</td>
            <td>{ip}</td>
            <td>{"🚫 Banned" if is_banned else "✅ Active"}</td>
            <td>{reason}</td>
            <td>{expires}</td>
            <td>
                <form method='post' action='/ban' style='display:inline;'>
                    <input type='hidden' name='username' value='{username}'>
                    <input type='text' name='reason' placeholder='Reason'>
                    <input type='number' name='duration' placeholder='Seconds'>
                    <button>Ban</button>
                </form>
                <form method='post' action='/unban' style='display:inline;'>
                    <input type='hidden' name='username' value='{username}'>
                    <button>Unban</button>
                </form>
            </td>
        </tr>
        """

    return f"""
    <html>
    <body style="background:#0f172a;color:white;font-family:Poppins;padding:20px;">
        <h1>FM Radio Developer Panel</h1>
        <table border="1" cellpadding="8" style="width:100%;border-collapse:collapse;">
            <tr>
                <th>Username</th>
                <th>IP</th>
                <th>Status</th>
                <th>Ban Reason</th>
                <th>Expires</th>
                <th>Actions</th>
            </tr>
            {rows}
        </table>
    </body>
    </html>
    """


# ============================================================
# END OF FILE
# ============================================================
