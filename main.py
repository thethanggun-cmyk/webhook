import os
import secrets
import sqlite3
from typing import Optional
from fastapi import FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

app = FastAPI(title="Bank Webhook Manager")

os.makedirs("templates", exist_ok=True)
templates = Jinja2Templates(directory="templates")

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
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS webhook_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            name TEXT NOT NULL,
            secret_key TEXT UNIQUE NOT NULL,
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

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return RedirectResponse(url="/dashboard", status_code=302)

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: Optional[str] = None):
    return templates.TemplateResponse("login.html", {"request": request, "error": error})

@app.post("/login")
async def login_action(request: Request, username: str = Form(...), password: str = Form(...)):
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT id, password FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        
        if not user or user[1] != password:
            return templates.TemplateResponse("login.html", {"request": request, "error": "Sai tài khoản hoặc mật khẩu!"})
        
        response = RedirectResponse(url="/dashboard", status_code=303)
        response.set_cookie(key="user_id", value=str(user[0]))
        return response
    except Exception as e:
        return templates.TemplateResponse("login.html", {"request": request, "error": f"Lỗi hệ thống: {str(e)}"})

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request, error: Optional[str] = None):
    return templates.TemplateResponse("register.html", {"request": request, "error": error})

@app.post("/register")
async def register_action(request: Request, username: str = Form(...), password: str = Form(...)):
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        conn.close()
        return RedirectResponse(url="/login", status_code=303)
    except sqlite3.IntegrityError:
        return templates.TemplateResponse("register.html", {"request": request, "error": "Tài khoản này đã tồn tại!"})
    except Exception as e:
        return templates.TemplateResponse("register.html", {"request": request, "error": f"Lỗi: {str(e)}"})

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
    
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, name, secret_key FROM webhook_keys WHERE user_id = ?", (user_id,))
        keys = [{"id": row[0], "name": row[1], "secret_key": row[2]} for row in cursor.fetchall()]
        
        secret_keys = [k["secret_key"] for k in keys]
        total_tx = 0
        total_money = 0.0
        
        if secret_keys:
            placeholders = ','.join(['?'] * len(secret_keys))
            cursor.execute(f"SELECT COUNT(*), SUM(transfer_amount) FROM transactions WHERE secret_key IN ({placeholders})", secret_keys)
            res = cursor.fetchone()
            if res and res[0]:
                total_tx = res[0]
                total_money = res[1] or 0.0
                
        conn.close()
        
        base_url = str(request.base_url).rstrip('/')
        return templates.TemplateResponse("dashboard.html", {
            "request": request,
            "keys": keys,
            "total_tx": total_tx,
            "total_money": total_money,
            "base_url": base_url
        })
    except Exception as e:
        return HTMLResponse(content=f"<h3>Lỗi Dashboard: {str(e)}</h3>", status_code=500)

@app.post("/create-key")
async def create_key(request: Request, name: str = Form(...)):
    user_id = request.cookies.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=303)
    
    secret_key = secrets.token_hex(16)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO webhook_keys (user_id, name, secret_key) VALUES (?, ?, ?)", (user_id, name, secret_key))
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
        
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, name, secret_key FROM webhook_keys WHERE user_id = ?", (user_id,))
        keys = [{"id": row[0], "name": row[1], "secret_key": row[2]} for row in cursor.fetchall()]
        user_secret_keys = [k["secret_key"] for k in keys]
        
        txs = []
        if user_secret_keys:
            if key and key in user_secret_keys:
                cursor.execute("SELECT id, gateway, transfer_amount, content, reference_code, created_at FROM transactions WHERE secret_key = ? ORDER BY id DESC", (key,))
            else:
                placeholders = ','.join(['?'] * len(user_secret_keys))
                cursor.execute(f"SELECT id, gateway, transfer_amount, content, reference_code, created_at FROM transactions WHERE secret_key IN ({placeholders}) ORDER BY id DESC", user_secret_keys)
            txs = cursor.fetchall()
            
        conn.close()
        
        return templates.TemplateResponse("history.html", {
            "request": request,
            "keys": keys,
            "txs": txs,
            "selected_key": key or ""
        })
    except Exception as e:
        return HTMLResponse(content=f"<h3>Lỗi History: {str(e)}</h3>", status_code=500)

class BankTransaction(BaseModel):
    gateway: str
    transferAmount: float
    content: str
    referenceCode: str

@app.post("/webhook/bank/{secret_key}")
async def receive_bank_webhook(secret_key: str, data: BankTransaction):
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute("SELECT id FROM webhook_keys WHERE secret_key = ?", (secret_key,))
        k = cursor.fetchone()
        
        if not k:
            conn.close()
            raise HTTPException(status_code=403, detail="Invalid Webhook Secret Key")
            
        cursor.execute("""
            INSERT INTO transactions (secret_key, gateway, transfer_amount, content, reference_code)
            VALUES (?, ?, ?, ?, ?)
        """, (secret_key, data.gateway, data.transferAmount, data.content, data.referenceCode))
        
        conn.commit()
        conn.close()
        
        return {"status": "success", "message": "Transaction recorded successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
