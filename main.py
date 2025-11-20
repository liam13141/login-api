from fastapi import FastAPI, Form, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import json, os

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

# REAL IP — supports render, cloudflare, proxies
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

    if ip in banned_ips:
        raise HTTPException(403, detail="Signup blocked — your IP is banned.")

    if username in users:
        raise HTTPException(400, detail="Username already exists")

    users[username] = {
        "password": password,
        "banned": False,
        "ip": ip
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

    if ip in banned_ips:
        raise HTTPException(403, detail="Access denied — your IP is banned.")

    if username not in users:
        raise HTTPException(404, detail="User not found")

    user = users[username]

    if user["password"] != password:
        raise HTTPException(401, detail="Incorrect password")

    if user.get("banned", False):
        return {"message": "User is banned", "user": username, "banned": True}

    return {"message": f"Welcome back, {username}!", "user": username, "banned": False}


# ===============================
# BAN USER
# ===============================
@app.post("/ban")
def ban_user(username: str = Form(...)):
    users = load_users()
    banned_ips = load_bans()

    if username not in users:
        raise HTTPException(404, detail="User not found")

    ip = users[username].get("ip")

    users[username]["banned"] = True

    if ip:
        banned_ips[ip] = True

    save_users(users)
    save_bans(banned_ips)

    return {"message": f"{username} and IP {ip} have been banned."}


# ===============================
# UNBAN USER
# ===============================
@app.post("/unban")
def unban_user(username: str = Form(...)):
    users = load_users()
    banned_ips = load_bans()

    if username not in users:
        raise HTTPException(404, detail="User not found")

    ip = users[username].get("ip")

    users[username]["banned"] = False

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
# SECURE ADMIN PANEL WITH ACCESS CODE (17731 REQUIRED)
# ============================================================
@app.get("/dev", response_class=HTMLResponse)
def dev_panel(request: Request, code: str = None):
    # If no correct code → show code prompt
    if code != DEV_CODE:
        return """
        <html>
        <head>
            <title>Developer Access</title>
            <style>
                body {
                    background:#0f172a; color:#f1f5f9;
                    display:flex; align-items:center; justify-content:center;
                    height:100vh; font-family: Poppins, sans-serif;
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

    # If code correct → show real dev panel
    users = load_users()
    banned_ips = load_bans()

    # Build HTML rows
    rows = ""
    for username, info in users.items():
        ip = info.get("ip", "Unknown")
        is_banned = info.get("banned", False)
        ip_is_banned = ip in banned_ips

        rows += f"""
            <tr>
                <td>{username}</td>
                <td>{ip}</td>
                <td>{"🚫 Banned" if is_banned else "✅ Active"}</td>
                <td>{"🔥 Banned" if ip_is_banned else "🟢 Allowed"}</td>
                <td>
                    <form action="/ban" method="post" style="display:inline;">
                        <input type="hidden" name="username" value="{username}">
                        <button style="background:#ef4444;color:white;border:none;padding:6px 10px;border-radius:6px;">Ban</button>
                    </form>
                    <form action="/unban" method="post" style="display:inline;">
                        <input type="hidden" name="username" value="{username}">
                        <button style="background:#22c55e;color:white;border:none;padding:6px 10px;border-radius:6px;">Unban</button>
                    </form>
                    <form action="/delete" method="post" style="display:inline;">
                        <input type="hidden" name="username" value="{username}">
                        <button style="background:#f87171;color:white;border:none;padding:6px 10px;border-radius:6px;">Delete</button>
                    </form>
                </td>
            </tr>
        """

    return f"""
    <html>
    <head>
        <title>FM Developer Panel</title>
        <style>
            body {{
                background:#0f172a; color:#f1f5f9;
                font-family: Poppins, sans-serif;
                padding:20px;
            }}
            table {{
                width:100%; border-collapse:collapse;
                background:#1e293b; border-radius:8px;
                overflow:hidden;
            }}
            th, td {{
                padding:12px; border-bottom:1px solid #334155;
            }}
            th {{
                background:#0f172a;
            }}
            h1 {{
                text-align:center; margin-bottom:20px;
                color:#38bdf8;
            }}
        </style>
    </head>
    <body>
        <h1>🛠️ FM Radio Developer Panel</h1>
        <table>
            <tr>
                <th>Username</th>
                <th>IP</th>
                <th>User Status</th>
                <th>IP Status</th>
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
