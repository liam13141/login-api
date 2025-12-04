from fastapi import FastAPI, Form, Request, HTTPException, Depends, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from passlib.hash import argon2
import json, os, time

# ============================================================
# CONFIG
# ============================================================
app = FastAPI(title="FM Radio Login API (DEV TOKEN AUTO GENERATION)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = "9666"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_SECONDS = 3600
DEV_CODE = "17731"

DB_USERS = "users.json"
DB_SETTINGS = "settings.json"
DB_LISTEN = "listen.json"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

MAX_ATTEMPTS = 5
LOCK_TIME = 60
RATE_LIMIT = {}

# ============================================================
# FILE HELPERS
# ============================================================
def load_json(path):
    if not os.path.exists(path):
        return {}
    try:
        return json.load(open(path))
    except:
        return {}

def save_json(path, data):
    json.dump(data, open(path, "w"), indent=2)

def load_users(): return load_json(DB_USERS)
def save_users(d): save_json(DB_USERS, d)

def load_settings():
    if not os.path.exists(DB_SETTINGS):
        save_json(DB_SETTINGS, {"christmas_mode": False, "maintenance_mode": False})
    return load_json(DB_SETTINGS)

def save_settings(d):
    save_json(DB_SETTINGS, d)

def load_listen(): return load_json(DB_LISTEN)
def save_listen(d): save_json(DB_LISTEN, d)

# ============================================================
# TOKEN SYSTEM
# ============================================================
def create_token(username, role):
    exp = int(time.time()) + ACCESS_TOKEN_EXPIRE_SECONDS
    return jwt.encode({"sub": username, "role": role, "exp": exp}, SECRET_KEY)

def create_dev_token():
    exp = int(time.time()) + 3600 * 24  # 24-hour dev token
    return jwt.encode({"sub": "dev", "role": "owner", "exp": exp}, SECRET_KEY)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except:
        raise HTTPException(401, "Invalid token")

    users = load_users()
    if data["sub"] not in users and data["sub"] != "dev":
        raise HTTPException(401, "User not found")

    return {"username": data["sub"], "role": data["role"]}

# ============================================================
# RATE LIMIT
# ============================================================
def get_ip(request: Request):
    return request.headers.get("X-Forwarded-For", request.client.host)

def check_rate(ip, key, limit, window):
    now = time.time()
    info = RATE_LIMIT.get((ip, key), {"count": 0, "time": now})

    if now - info["time"] > window:
        info = {"count": 0, "time": now}

    info["count"] += 1
    RATE_LIMIT[(ip, key)] = info

    if info["count"] > limit:
        raise HTTPException(429, "Too many requests")

# ============================================================
# ROOT
# ============================================================
@app.get("/")
def home():
    return {"status": "FM Radio Login API with Auto Dev Token"}

# ============================================================
# SIGNUP
# ============================================================
@app.post("/signup")
def signup(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = get_ip(request)
    check_rate(ip, "signup", 5, 60)

    users = load_users()
    if username in users:
        raise HTTPException(400, "Username already exists")

    hashed = argon2.hash(password)

    users[username] = {
        "password": hashed,
        "role": "user",
        "banned": False,
        "ban_reason": None,
        "ban_expires": None,
        "failed": 0,
        "lock": 0,
        "ip": ip,
        "created": int(time.time()),
        "favorites": [],
        "notes": []
    }
    save_users(users)

    return {"message": f"Account created for {username}"}

# ============================================================
# LOGIN (returns token)
# ============================================================
@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = get_ip(request)
    check_rate(ip, "login", 10, 60)

    users = load_users()
    if username not in users:
        raise HTTPException(404, "User not found")

    user = users[username]
    now = time.time()

    if user["lock"] > now:
        raise HTTPException(403, f"Locked. Try again in {int(user['lock'] - now)} sec")

    if not argon2.verify(password, user["password"]):
        user["failed"] += 1
        if user["failed"] >= MAX_ATTEMPTS:
            user["lock"] = now + LOCK_TIME
        save_users(users)
        raise HTTPException(401, "Wrong password")

    if user["banned"]:
        raise HTTPException(403, f"Banned: {user['ban_reason']}")

    token = create_token(username, user["role"])

    user["failed"] = 0
    user["lock"] = 0
    save_users(users)

    return {"message": "Login OK", "token": token, "role": user["role"]}

# ============================================================
# BAN SYSTEM
# ============================================================
@app.post("/ban")
def ban(username: str = Form(...), reason: str = Form("No reason"), duration: int = Form(0),
        user=Depends(get_current_user)):

    if user["role"] not in ["admin", "owner"]:
        raise HTTPException(403, "Forbidden")

    users = load_users()
    if username not in users:
        raise HTTPException(404, "User not found")

    users[username]["banned"] = True
    users[username]["ban_reason"] = reason
    users[username]["ban_expires"] = int(time.time()) + duration if duration else None
    save_users(users)

    return {"message": f"{username} banned"}

@app.post("/unban")
def unban(username: str = Form(...), user=Depends(get_current_user)):

    if user["role"] not in ["admin", "owner"]:
        raise HTTPException(403, "Forbidden")

    users = load_users()
    if username not in users:
        raise HTTPException(404, "User not found")

    users[username]["banned"] = False
    users[username]["ban_reason"] = None
    users[username]["ban_expires"] = None
    save_users(users)

    return {"message": f"{username} unbanned"}

@app.post("/delete")
def delete(username: str = Form(...), user=Depends(get_current_user)):

    if user["role"] != "owner":
        raise HTTPException(403, "Owner only")

    users = load_users()

    if username not in users:
        raise HTTPException(404, "Not found")

    del users[username]
    save_users(users)

    return {"message": f"{username} deleted"}

@app.post("/promote")
def promote(username: str = Form(...), role: str = Form(...),
            user=Depends(get_current_user)):

    if user["role"] != "owner":
        raise HTTPException(403, "Owner only")

    users = load_users()

    if username not in users:
        raise HTTPException(404, "Not found")

    users[username]["role"] = role
    save_users(users)

    return {"message": f"{username} promoted to {role}"}

# ============================================================
# RESET PASSWORD
# ============================================================
@app.post("/admin/reset-password")
def reset_pw(username: str = Form(...), new_password: str = Form(...),
             user=Depends(get_current_user)):

    if user["role"] not in ["admin", "owner"]:
        raise HTTPException(403, "Forbidden")

    users = load_users()
    if username not in users:
        raise HTTPException(404, "Not found")

    users[username]["password"] = argon2.hash(new_password)
    save_users(users)

    return {"message": f"{username}'s password reset"}

# ============================================================
# LISTEN TIME
# ============================================================
@app.post("/listen")
def add_listen(username: str = Form(...), seconds: int = Form(...)):
    data = load_listen()

    if username not in data:
        data[username] = {"total_seconds": 0}

    data[username]["total_seconds"] += seconds
    save_listen(data)

    return data[username]

@app.get("/listen-time/{username}")
def get_listen(username: str):
    data = load_listen()
    return data.get(username, {"total_seconds": 0})

@app.get("/leaderboard")
def leaderboard():
    data = load_listen()
    return sorted(
        [{"username": u, "total_seconds": d["total_seconds"]} for u, d in data.items()],
        key=lambda x: x["total_seconds"],
        reverse=True
    )

# ============================================================
# ONLINE USERS (WEBSOCKET)
# ============================================================
connected_users = set()

@app.websocket("/ws/online")
async def ws_online(websocket: WebSocket):
    await websocket.accept()
    connected_users.add(websocket)

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        connected_users.remove(websocket)

@app.get("/online")
def get_online():
    return {"online": len(connected_users)}

# ============================================================
# DEV PANEL WITH AUTO TOKEN GENERATION
# ============================================================
@app.get("/dev", response_class=HTMLResponse)
def dev(request: Request, code: str = None):

    if code != DEV_CODE:
        return """
        <html><body style='background:#0f172a;color:white;font-family:sans-serif;'>
            <h3>Developer Access</h3>
            <form method='get'>
                <input name='code' placeholder='dev code'>
                <button>Enter</button>
            </form>
        </body></html>
        """

    # Generate 24-hour owner token
    dev_token = create_dev_token()

    settings = load_settings()
    users = load_users()

    # Build settings
    settings_rows = ""
    for key, value in settings.items():
        settings_rows += f"""
        <tr>
            <td>{key}</td>
            <td>{value}</td>
            <td>
                <form method='post' action='/toggle-setting'>
                    <input type='hidden' name='setting' value='{key}'>
                    <input type='hidden' name='value' value='true'>
                    <input type='hidden' name='token' value='{dev_token}'>
                    <button>Enable</button>
                </form>

                <form method='post' action='/toggle-setting'>
                    <input type='hidden' name='setting' value='{key}'>
                    <input type='hidden' name='value' value='false'>
                    <input type='hidden' name='token' value='{dev_token}'>
                    <button>Disable</button>
                </form>
            </td>
        </tr>
        """

    # Build user table
    user_rows = ""
    for name, u in users.items():
        user_rows += f"""
        <tr>
            <td>{name}</td>
            <td>{u['role']}</td>
            <td>{u['ip']}</td>
            <td>{u['ban_reason']}</td>
            <td>{u['ban_expires']}</td>

            <td>
                <form method='post' action='/ban'>
                    <input type='hidden' name='username' value='{name}'>
                    <input type='hidden' name='token' value='{dev_token}'>
                    <button>Ban</button>
                </form>
            </td>

            <td>
                <form method='post' action='/unban'>
                    <input type='hidden' name='username' value='{name}'>
                    <input type='hidden' name='token' value='{dev_token}'>
                    <button>Unban</button>
                </form>
            </td>

            <td>
                <form method='post' action='/delete'>
                    <input type='hidden' name='username' value='{name}'>
                    <input type='hidden' name='token' value='{dev_token}'>
                    <button>Delete</button>
                </form>
            </td>

            <td>
                <form method='post' action='/promote'>
                    <input type='hidden' name='username' value='{name}'>
                    <select name='role'>
                        <option value='user'>user</option>
                        <option value='admin'>admin</option>
                        <option value='owner'>owner</option>
                    </select>
                    <input type='hidden' name='token' value='{dev_token}'>
                    <button>Promote</button>
                </form>
            </td>

            <td>
                <form method='post' action='/admin/reset-password'>
                    <input type='hidden' name='username' value='{name}'>
                    <input name='new_password' placeholder='new password'>
                    <input type='hidden' name='token' value='{dev_token}'>
                    <button>Reset</button>
                </form>
            </td>
        </tr>
        """

    return f"""
    <html>
    <body style='background:#0f172a;color:white;font-family:sans-serif;'>
    
        <h2>FM Radio Developer Panel</h2>
        <p style="color:lightgreen">Dev token generated automatically.</p>
        <p><b>Your Dev Token:</b></p>
        <code>{dev_token}</code>

        <h3>Server Settings</h3>
        <table border='1'>
            {settings_rows}
        </table>

        <h3>User Management</h3>
        <table border='1'>
            <tr>
                <th>User</th><th>Role</th><th>IP</th><th>Reason</th><th>Expires</th>
                <th>Ban</th><th>Unban</th><th>Delete</th>
                <th>Promote</th><th>Reset Password</th>
            </tr>
            {user_rows}
        </table>

    </body>
    </html>
    """

# END
