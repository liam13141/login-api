from fastapi import FastAPI, Form, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
import json, os

app = FastAPI(title="FM Radio Login API", description="Login system with IP ban protection")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_FILE = "users.json"
BAN_IP_FILE = "banned_ips.json"


# ---------- JSON HELPERS ----------
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

def save_users(data):
    save_json(DB_FILE, data)

def load_bans():
    return load_json(BAN_IP_FILE)

def save_bans(data):
    save_json(BAN_IP_FILE, data)


# ---------- GET USER IP ----------
def get_ip(request: Request):
    return request.client.host


# ---------- HOME ----------
@app.get("/")
def home():
    return {"message": "FM Radio Login API running!"}


# ---------- SIGNUP ----------
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
    return {"message": f"Account created for {username}", "ip": ip}



# ---------- LOGIN ----------
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

    return {"message": f"Welcome back, {username}!", "user": username, "banned": False, "ip": ip}



# ---------- BAN USER + IP ----------
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

    return {"message": f"{username} banned and IP {ip} blocked."}



# ---------- UNBAN USER + IP ----------
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

    return {"message": f"{username} unbanned and IP {ip} unblocked."}



# ---------- DIRECT IP BAN ----------
@app.post("/ban_ip")
def ban_ip(ip: str = Form(...)):
    banned_ips = load_bans()
    banned_ips[ip] = True
    save_bans(banned_ips)
    return {"message": f"IP {ip} is now banned."}



# ---------- DIRECT IP UNBAN ----------
@app.post("/unban_ip")
def unban_ip(ip: str = Form(...)):
    banned_ips = load_bans()
    if ip in banned_ips:
        del banned_ips[ip]
        save_bans(banned_ips)
    return {"message": f"IP {ip} has been unbanned."}



# ---------- DELETE ACCOUNT ----------
@app.post("/delete")
def delete_account(username: str = Form(...)):
    users = load_users()

    if username not in users:
        raise HTTPException(404, detail="User not found")

    del users[username]
    save_users(users)
    return {"message": f"Account '{username}' deleted."}



# ---------- DEV PANEL ----------
@app.get("/dev", response_class=HTMLResponse)
def dev_panel():
    users = load_users()
    banned_ips = load_bans()

    html = """
    <html>
    <head>
        <title>FM Radio Developer Panel</title>
        <style>
            body { font-family: Poppins, sans-serif; background: #0f172a; color: #f1f5f9; text-align: center; }
            h1 { color: #38bdf8; }
            table { margin: 20px auto; border-collapse: collapse; width: 90%; }
            th, td { padding: 12px 20px; border-bottom: 1px solid #334155; }
            button { padding: 6px 14px; border: none; border-radius: 6px; cursor: pointer; }
            .ban { background: #ef4444; color: white; }
            .unban { background: #22c55e; color: white; }
            .delete { background: #f87171; color: white; }
            .ipban { background: #fb923c; }
            .ipunban { background: #4ade80; }
        </style>
    </head>
    <body>
        <h1>🛠️ FM Radio Developer Panel</h1>
        <h3>Total Users: """ + str(len(users)) + """</h3>
        <h3>Banned IPs: """ + str(len(banned_ips)) + """</h3>
        <table>
            <tr><th>Username</th><th>IP</th><th>User Status</th><th>IP Status</th><th>Actions</th></tr>
    """

    for username, info in users.items():
        ip = info.get("ip", "Unknown")
        user_banned = info.get("banned", False)
        ip_banned = ip in banned_ips if ip != "Unknown" else False

        html += f"""
        <tr>
            <td>{username}</td>
            <td>{ip}</td>
            <td>{'🚫 Banned' if user_banned else '✅ Active'}</td>
            <td>{'🔥 IP Banned' if ip_banned else '🟢 Allowed'}</td>
            <td>
                <button class="{'unban' if user_banned else 'ban'}"
                    onclick="toggleBan('{username}', {str(user_banned).lower()})">
                    {'Unban' if user_banned else 'Ban'}
                </button>

                <button class="{'ipunban' if ip_banned else 'ipban'}"
                    onclick="toggleIP('{ip}', {str(ip_banned).lower()})">
                    {'Unban IP' if ip_banned else 'Ban IP'}
                </button>

                <button class="delete" onclick="deleteAcc('{username}')">Delete</button>
            </td>
        </tr>
        """

    html += """
        </table>

        <script>
        async function toggleBan(username, banned) {
            const endpoint = banned ? "/unban" : "/ban";
            const form = new FormData();
            form.append("username", username);
            let r = await fetch(endpoint, { method: "POST", body: form });
            alert((await r.json()).message);
            location.reload();
        }

        async function toggleIP(ip, banned) {
            const endpoint = banned ? "/unban_ip" : "/ban_ip";
            const form = new FormData();
            form.append("ip", ip);
            let r = await fetch(endpoint, { method: "POST", body: form });
            alert((await r.json()).message);
            location.reload();
        }

        async function deleteAcc(username) {
            if (!confirm("Delete '" + username + "'?")) return;
            const form = new FormData();
            form.append("username", username);
            let r = await fetch("/delete", { method: "POST", body: form });
            alert((await r.json()).message);
            location.reload();
        }
        </script>

    </body>
    </html>
    """

    return html
