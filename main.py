from fastapi import FastAPI, Form, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import json, os

app = FastAPI(title="FM Radio Login API", description="Login system with IP ban-evasion prevention")

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


# ---------- HELPERS ----------
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
    users = load_json(DB_FILE)
    banned_ips = load_json(BAN_IP_FILE)

    # BLOCK signup from banned IP
    if ip in banned_ips:
        raise HTTPException(403, detail="Signup blocked — your IP is banned.")

    if username in users:
        raise HTTPException(400, detail="Username already exists")

    # Create account + store IP
    users[username] = {
        "password": password,
        "banned": False,
        "ip": ip
    }

    save_json(DB_FILE, users)
    return {"message": f"Account created for {username}"}

@app.get("/dev", response_class=HTMLResponse)
def dev_panel():
    users = load_users()
    banned_ips = load_bans()

    html = """
    <html>
    <head>
        <title>FM Radio Developer Panel</title>
        <style>
            body {
                font-family: Poppins, sans-serif;
                background: #0f172a;
                color: #f1f5f9;
                text-align: center;
                padding-bottom: 40px;
            }
            h1 { color: #38bdf8; }
            table {
                margin: 20px auto;
                border-collapse: collapse;
                width: 90%;
                max-width: 1000px;
            }
            th, td {
                padding: 12px 20px;
                border-bottom: 1px solid #334155;
                font-size: 14px;
            }
            button {
                padding: 6px 14px;
                border: none;
                border-radius: 6px;
                cursor: pointer;
                font-weight: 600;
            }
            .ban { background: #ef4444; color: white; }
            .unban { background: #22c55e; color: white; }
            .delete { background: #f87171; color: white; }
            .ipban { background: #fb923c; color: black; }
            .ipunban { background: #4ade80; color: black; }
            .status { font-weight: 500; }
            #logoutBtn {
                margin-top: 20px;
                background: #6366f1;
                color: white;
                padding: 10px 20px;
                border-radius: 8px;
            }
        </style>
    </head>
    <body>
        <h1>🛠️ FM Radio Developer Panel</h1>

        <h3>Total Users: """ + str(len(users)) + """</h3>
        <h3>Banned IPs: """ + str(len(banned_ips)) + """</h3>

        <table>
            <tr>
                <th>Username</th>
                <th>IP</th>
                <th>User Status</th>
                <th>IP Status</th>
                <th>Actions</th>
            </tr>
    """

    # Loop users
    for username, info in users.items():
        ip = info.get("ip", "Unknown")
        is_banned = info.get("banned", False)
        ip_banned = ip in banned_ips if ip != "Unknown" else False

        user_status = "🚫 User Banned" if is_banned else "✅ Active"
        ip_status = "🔥 IP Banned" if ip_banned else "🟢 Allowed"

        user_btn_class = "unban" if is_banned else "ban"
        user_btn_label = "Unban User" if is_banned else "Ban User"

        ip_btn_class = "ipunban" if ip_banned else "ipban"
        ip_btn_label = "Unban IP" if ip_banned else "Ban IP"

        html += f"""
            <tr id="row-{username}">
                <td>{username}</td>
                <td>{ip}</td>
                <td class="status">{user_status}</td>
                <td class="status">{ip_status}</td>
                <td>
                    <button class="{user_btn_class}" onclick="toggleBan('{username}', {str(is_banned).lower()})">{user_btn_label}</button>
                    <button class="{ip_btn_class}" onclick="toggleIP('{ip}', {str(ip_banned).lower()})">{ip_btn_label}</button>
                    <button class="delete" onclick="deleteAccount('{username}')">🗑️ Delete</button>
                </td>
            </tr>
        """

    html += """
        </table>

        <button id="logoutBtn" onclick="logout()">🚪 Log Out</button>

        <script>
        // Toggle User Ban
        async function toggleBan(username, isBanned) {
            const endpoint = isBanned ? '/unban' : '/ban';
            const body = JSON.stringify({ username });
            const headers = { 'Content-Type': 'application/json' };
            const res = await fetch(endpoint, { method: 'POST', headers, body });
            const data = await res.json();
            alert(data.message);
            location.reload();
        }

        // Toggle IP Ban
        async function toggleIP(ip, banned) {
            const endpoint = banned ? '/unban_ip' : '/ban_ip';
            const body = JSON.stringify({ ip });
            const headers = { 'Content-Type': 'application/json' };
            const res = await fetch(endpoint, { method: 'POST', headers, body });
            const data = await res.json();
            alert(data.message);
            location.reload();
        }

        // Delete User
        async function deleteAccount(username) {
            if (!confirm("Delete user '" + username + "' permanently?")) return;
            const form = new FormData();
            form.append("username", username);
            const res = await fetch('/delete', { method: 'POST', body: form });
            const data = await res.json();
            alert(data.message);
            location.reload();
        }

        // Logout
        async function logout() {
            localStorage.removeItem('fmradio_user');
            localStorage.removeItem('fmradio_pass');
            const res = await fetch('/logout', { method: 'POST' });
            const data = await res.json();
            alert(data.message);
            location.reload();
        }
        </script>

    </body>
    </html>
    """

    return html


# ---------- LOGIN ----------
@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = get_ip(request)
    users = load_json(DB_FILE)
    banned_ips = load_json(BAN_IP_FILE)

    # IF IP IS BANNED → BLOCK LOGIN
    if ip in banned_ips:
        raise HTTPException(403, detail="Access denied — your IP is banned.")

    if username not in users:
        raise HTTPException(404, detail="User not found")

    user = users[username]

    # Incorrect password
    if user["password"] != password:
        raise HTTPException(401, detail="Incorrect password")

    # User account banned
    if user.get("banned", False):
        return {"message": "User is banned", "user": username, "banned": True}

    return {"message": f"Welcome back, {username}!", "user": username, "banned": False}


# ---------- ADMIN BAN ----------
@app.post("/ban")
def ban_user(username: str = Form(...)):
    users = load_json(DB_FILE)
    banned_ips = load_json(BAN_IP_FILE)

    if username not in users:
        raise HTTPException(404, detail="User not found")

    ip = users[username].get("ip")

    # Ban account
    users[username]["banned"] = True

    # Ban IP
    if ip:
        banned_ips[ip] = True

    save_json(DB_FILE, users)
    save_json(BAN_IP_FILE, banned_ips)

    return {"message": f"{username} and IP {ip} have been banned."}


# ---------- ADMIN UNBAN ----------
@app.post("/unban")
def unban_user(username: str = Form(...)):
    users = load_json(DB_FILE)
    banned_ips = load_json(BAN_IP_FILE)

    if username not in users:
        raise HTTPException(404, detail="User not found")

    ip = users[username].get("ip")

    # Unban account
    users[username]["banned"] = False

    # Remove IP ban
    if ip in banned_ips:
        del banned_ips[ip]

    save_json(DB_FILE, users)
    save_json(BAN_IP_FILE, banned_ips)

    return {"message": f"{username} and IP {ip} have been unbanned."}
