import os
import secrets
import sqlite3
import requests
from typing import Optional
from fastapi import FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel
from jinja2 import Template

app = FastAPI(title="Bank Webhook Manager")

DB_FILE = "database.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    # Thêm cột target_url để lưu URL web chính nhận thông báo
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS webhook_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            name TEXT NOT NULL,
            secret_key TEXT UNIQUE NOT NULL,
            target_url TEXT DEFAULT '',
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            secret_key TEXT,
            gateway TEXT,
            transfer_amount REAL,
            content TEXT,
            reference_code TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ==================== GIAO DIỆN HTML ====================

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <title>Quản lý Webhook</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body class="bg-light">
    <nav class="navbar navbar-dark bg-dark px-3">
        <span class="navbar-brand mb-0 h1">Bank Webhook Manager</span>
        <div class="dropdown">
            <button class="btn btn-outline-light" type="button" data-bs-toggle="dropdown"><i class="fa-solid fa-bars"></i> Menu</button>
            <ul class="dropdown-menu dropdown-menu-end">
                <li><a class="dropdown-item" href="/dashboard"><i class="fa-solid fa-house"></i> Trang chủ</a></li>
                <li><a class="dropdown-item" href="/history"><i class="fa-solid fa-clock-rotate-left"></i> Lịch sử Webhook</a></li>
                <li><hr class="dropdown-divider"></li>
                <li><a class="dropdown-item text-danger" href="/logout"><i class="fa-solid fa-right-from-bracket"></i> Đăng xuất</a></li>
            </ul>
        </div>
    </nav>

    <div class="container my-4">
        <div class="row mb-4">
            <div class="col-md-6">
                <div class="card text-white bg-primary shadow-sm">
                    <div class="card-body">
                        <h5 class="card-title">Tổng số giao dịch nhận</h5>
                        <h3>{{ total_tx }}</h3>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card text-white bg-success shadow-sm">
                    <div class="card-body">
                        <h5 class="card-title">Tổng tiền đã nhận</h5>
                        <h3>{{ "{:,.0f}".format(total_money) }} VNĐ</h3>
                    </div>
                </div>
            </div>
        </div>

        <!-- Tạo Webhook Key mới kèm URL nhận thông báo -->
        <div class="card shadow-sm mb-4">
            <div class="card-header bg-white"><strong>Tạo Webhook Key mới</strong></div>
            <div class="card-body">
                <form method="POST" action="/create-key" class="row g-3">
                    <div class="col-md-5">
                        <input type="text" name="name" class="form-control" placeholder="Tên gợi nhớ (VD: Web bán hàng)" required>
                    </div>
                    <div class="col-md-5">
                        <input type="url" name="target_url" class="form-control" placeholder="URL web chính nhận thông báo (VD: https://yourwebsite.com/api/ipn)">
                    </div>
                    <div class="col-md-2">
                        <button type="submit" class="btn btn-primary w-100"><i class="fa-solid fa-plus"></i> Tạo</button>
                    </div>
                </form>
            </div>
        </div>

        <div class="card shadow-sm">
            <div class="card-header bg-white"><strong>Danh sách Webhook của bạn</strong></div>
            <div class="card-body p-0">
                <table class="table table-striped mb-0 align-middle">
                    <thead>
                        <tr>
                            <th>Tên & URL nhận</th>
                            <th>Link Webhook (Cấu hình vào MONA Pay)</th>
                            <th class="text-end">Hành động</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for k in keys %}
                        <tr>
                            <td>
                                <strong>{{ k.name }}</strong><br>
                                <small class="text-muted">Gửi tới: {{ k.target_url if k.target_url else 'Chưa cấu hình URL' }}</small>
                            </td>
                            <td>
                                <input type="text" class="form-control form-control-sm bg-white" id="link-{{ k.id }}" value="{{ base_url }}/webhook/bank/{{ k.secret_key }}" readonly>
                            </td>
                            <td class="text-end">
                                <button class="btn btn-sm btn-outline-secondary" onclick="copyLink('link-{{ k.id }}', this)"><i class="fa-solid fa-copy"></i></button>
                                <form action="/regenerate-key/{{ k.id }}" method="POST" class="d-inline">
                                    <button type="submit" class="btn btn-sm btn-outline-warning" onclick="return confirm('Đổi key mới?')"><i class="fa-solid fa-rotate"></i></button>
                                </form>
                                <form action="/delete-key/{{ k.id }}" method="POST" class="d-inline">
                                    <button type="submit" class="btn btn-sm btn-outline-danger" onclick="return confirm('Xóa key này?')"><i class="fa-solid fa-trash"></i></button>
                                </form>
                            </td>
                        </tr>
                        {% else %}
                        <tr><td colspan="3" class="text-center text-muted py-3">Chưa có webhook nào.</td></tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function copyLink(elementId, btn) {
            var copyText = document.getElementById(elementId);
            copyText.select();
            navigator.clipboard.writeText(copyText.value);
            let originalText = btn.innerHTML;
            btn.innerHTML = '<i class="fa-solid fa-check"></i>';
            setTimeout(() => { btn.innerHTML = originalText; }, 2000);
        }
    </script>
</body>
</html>
"""

LOGIN_HTML = """
<!DOCTYPE html>
<html lang="vi">
<head><meta charset="UTF-8"><title>Đăng nhập</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet"></head>
<body class="bg-light d-flex align-items-center justify-content-center vh-100">
    <div class="card p-4 shadow" style="width: 350px;">
        <h3 class="text-center mb-3">Đăng Nhập</h3>
        {% if error %}<div class="alert alert-danger p-2">{{ error }}</div>{% endif %}
        <form method="POST" action="/login">
            <div class="mb-3"><label class="form-label">Tài khoản</label><input type="text" name="username" class="form-control" required></div>
            <div class="mb-3"><label class="form-label">Mật khẩu</label><input type="password" name="password" class="form-control" required></div>
            <button type="submit" class="btn btn-primary w-100">Đăng Nhập</button>
        </form>
        <p class="text-center mt-3 mb-0"><a href="/register">Đăng ký tài khoản</a></p>
    </div>
</body>
</html>
"""

REGISTER_HTML = """
<!DOCTYPE html>
<html lang="vi">
<head><meta charset="UTF-8"><title>Đăng ký</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet"></head>
<body class="bg-light d-flex align-items-center justify-content-center vh-100">
    <div class="card p-4 shadow" style="width: 350px;">
        <h3 class="text-center mb-3">Đăng Ký</h3>
        {% if error %}<div class="alert alert-danger p-2">{{ error }}</div>{% endif %}
        <form method="POST" action="/register">
            <div class="mb-3"><label class="form-label">Tài khoản</label><input type="text" name="username" class="form-control" required></div>
            <div class="mb-3"><label class="form-label">Mật khẩu</label><input type="password" name="password" class="form-control" required></div>
            <button type="submit" class="btn btn-success w-100">Đăng Ký Ngay</button>
        </form>
        <p class="text-center mt-3 mb-0"><a href="/login">Đăng nhập</a></p>
    </div>
</body>
</html>
"""

HISTORY_HTML = """
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8"><title>Lịch sử Webhook</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body class="bg-light">
    <nav class="navbar navbar-dark bg-dark px-3">
        <span class="navbar-brand mb-0 h1">Bank Webhook Manager</span>
        <div class="dropdown">
            <button class="btn btn-outline-light" type="button" data-bs-toggle="dropdown"><i class="fa-solid fa-bars"></i> Menu</button>
            <ul class="dropdown-menu dropdown-menu-end">
                <li><a class="dropdown-item" href="/dashboard"><i class="fa-solid fa-house"></i> Trang chủ</a></li>
                <li><a class="dropdown-item" href="/history"><i class="fa-solid fa-clock-rotate-left"></i> Lịch sử Webhook</a></li>
                <li><hr class="dropdown-divider"></li>
                <li><a class="dropdown-item text-danger" href="/logout"><i class="fa-solid fa-right-from-bracket"></i> Đăng xuất</a></li>
            </ul>
        </div>
    </nav>
    <div class="container my-4">
        <div class="card shadow-sm mb-4">
            <div class="card-body">
                <form method="GET" action="/history" class="row g-3 align-items-center">
                    <div class="col-auto"><label class="col-form-label"><strong>Chọn Key:</strong></label></div>
                    <div class="col-md-6">
                        <select name="key" class="form-select" onchange="this.form.submit()">
                            <option value="">-- Tất cả --</option>
                            {% for k in keys %}
                            <option value="{{ k.secret_key }}" {% if selected_key == k.secret_key %}selected{% endif %}>{{ k.name }}</option>
                            {% endfor %}
                        </select>
                    </div>
                </form>
            </div>
        </div>
        <div class="card shadow-sm">
            <div class="card-header bg-white"><strong>Lịch sử giao dịch</strong></div>
            <div class="card-body p-0">
                <table class="table table-striped mb-0">
                    <thead><tr><th>Thời gian</th><th>Ngân hàng</th><th>Mã GD</th><th>Nội dung</th><th class="text-end">Số tiền</th></tr></thead>
                    <tbody>
                        {% for tx in txs %}
                        <tr>
                            <td>{{ tx.created_at }}</td>
                            <td>{{ tx.gateway }}</td>
                            <td><code>{{ tx.reference_code }}</code></td>
                            <td>{{ tx.content }}</td>
                            <td class="text-end text-success fw-bold">+{{ "{:,.0f}".format(tx.transfer_amount) }} VNĐ</td>
                        </tr>
                        {% else %}
                        <tr><td colspan="5" class="text-center text-muted py-3">Chưa có giao dịch.</td></tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""

# ==================== ROUTES ====================

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return RedirectResponse(url="/dashboard", status_code=302)

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: Optional[str] = None):
    return HTMLResponse(Template(LOGIN_HTML).render(error=error))

@app.post("/login")
async def login_action(request: Request, username: str = Form(...), password: str = Form(...)):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, password FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    if not user or user[1] != password:
        return HTMLResponse(Template(LOGIN_HTML).render(error="Sai tài khoản hoặc mật khẩu!"))
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(key="user_id", value=str(user[0]))
    return response

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request, error: Optional[str] = None):
    return HTMLResponse(Template(REGISTER_HTML).render(error=error))

@app.post("/register")
async def register_action(request: Request, username: str = Form(...), password: str = Form(...)):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return HTMLResponse(Template(REGISTER_HTML).render(error="Tài khoản đã tồn tại!"))
    conn.close()
    return RedirectResponse(url="/login", status_code=303)

@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(key="user_id")
    return response

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    user_id = request.cookies.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=303)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, secret_key, target_url FROM webhook_keys WHERE user_id = ?", (user_id,))
    keys = [{"id": r[0], "name": r[1], "secret_key": r[2], "target_url": r[3]} for r in cursor.fetchall()]
    
    secret_keys = [k["secret_key"] for k in keys]
    total_tx, total_money = 0, 0.0
    if secret_keys:
        placeholders = ','.join(['?'] * len(secret_keys))
        cursor.execute(f"SELECT COUNT(*), SUM(transfer_amount) FROM transactions WHERE secret_key IN ({placeholders})", secret_keys)
        res = cursor.fetchone()
        if res and res[0]:
            total_tx, total_money = res[0], res[1] or 0.0
    conn.close()
    base_url = str(request.base_url).rstrip('/')
    return HTMLResponse(Template(DASHBOARD_HTML).render(keys=keys, total_tx=total_tx, total_money=total_money, base_url=base_url))

@app.post("/create-key")
async def create_key(request: Request, name: str = Form(...), target_url: Optional[str] = Form("")):
    user_id = request.cookies.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=303)
    secret_key = secrets.token_hex(16)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO webhook_keys (user_id, name, secret_key, target_url) VALUES (?, ?, ?, ?)", (user_id, name, secret_key, target_url))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/dashboard", status_code=303)

@app.post("/regenerate-key/{key_id}")
async def regenerate_key(request: Request, key_id: int):
    user_id = request.cookies.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=303)
    new_secret_key = secrets.token_hex(16)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("UPDATE webhook_keys SET secret_key = ? WHERE id = ? AND user_id = ?", (new_secret_key, key_id, user_id))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/dashboard", status_code=303)

@app.post("/delete-key/{key_id}")
async def delete_key(request: Request, key_id: int):
    user_id = request.cookies.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=303)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM webhook_keys WHERE id = ? AND user_id = ?", (key_id, user_id))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/dashboard", status_code=303)

@app.get("/history", response_class=HTMLResponse)
async def history(request: Request, key: Optional[str] = None):
    user_id = request.cookies.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=303)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, secret_key FROM webhook_keys WHERE user_id = ?", (user_id,))
    keys = [{"id": r[0], "name": r[1], "secret_key": r[2]} for r in cursor.fetchall()]
    user_secret_keys = [k["secret_key"] for k in keys]
    
    txs = []
    if user_secret_keys:
        if key and key in user_secret_keys:
            cursor.execute("SELECT id, gateway, transfer_amount, content, reference_code, created_at FROM transactions WHERE secret_key = ? ORDER BY id DESC", (key,))
        else:
            placeholders = ','.join(['?'] * len(user_secret_keys))
            cursor.execute(f"SELECT id, gateway, transfer_amount, content, reference_code, created_at FROM transactions WHERE secret_key IN ({placeholders}) ORDER BY id DESC", user_secret_keys)
        for row in cursor.fetchall():
            txs.append({"id": row[0], "gateway": row[1], "transfer_amount": row[2], "content": row[3], "reference_code": row[4], "created_at": row[5]})
    conn.close()
    return HTMLResponse(Template(HISTORY_HTML).render(keys=keys, txs=txs, selected_key=key or ""))

# ==================== WEBHOOK NHẬN & TỰ ĐỘNG CHUYỂN TIẾP (FORWARD) ====================

@app.api_route("/webhook/bank/{secret_key}", methods=["GET", "POST"])
async def receive_bank_webhook(secret_key: str, request: Request):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Lấy thông tin key và target_url của web chính
    cursor.execute("SELECT id, target_url FROM webhook_keys WHERE secret_key = ?", (secret_key,))
    k = cursor.fetchone()
    
    if not k:
        conn.close()
        raise HTTPException(status_code=403, detail="Invalid Webhook Secret Key")
        
    target_url = k[1] # URL web chính do bạn cài lúc tạo key

    if request.method == "GET":
        conn.close()
        return {"status": "success", "message": "Webhook URL is active!"}
        
    try:
        data = await request.json()
    except:
        data = {}
        
    gateway = data.get("gateway", "Bank")
    amount = float(data.get("transferAmount", data.get("amount", 0)))
    content = data.get("content", data.get("description", ""))
    ref_code = data.get("referenceCode", data.get("transactionCode", "REF" + secrets.token_hex(4)))
    
    # 1. Lưu vào Database trên Render
    cursor.execute("""
        INSERT INTO transactions (secret_key, gateway, transfer_amount, content, reference_code)
        VALUES (?, ?, ?, ?, ?)
    """, (secret_key, gateway, amount, content, ref_code))
    conn.commit()
    conn.close()

    # 2. TỰ ĐỘNG GỬI TRỰC TIẾP (FORWARD) LÊN URL WEB CHÍNH CỦA BẠN
    if target_url and target_url.startswith("http"):
        try:
            # Gửi dữ liệu nguyên bản (hoặc tuỳ chỉnh) sang website chính của bạn
            requests.post(target_url, json=data, timeout=5)
        except Exception as e:
            print(f"Lỗi forward webhook tới web chính: {str(e)}")

    return {"status": "success", "message": "Transaction recorded and forwarded successfully"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
