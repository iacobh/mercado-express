from flask import Flask, render_template, request, jsonify, session, send_from_directory
import sqlite3
from pathlib import Path
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import time, os, secrets, hmac
import requests
from urllib.parse import urlencode

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DATA_DIR", str(BASE_DIR)))
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "compra_y_venta.db"
UPLOAD_FOLDER = DATA_DIR / "uploads"
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024
COMMISSION_RATE = 0.10
MP_ACCESS_TOKEN = os.environ.get("MP_ACCESS_TOKEN", "")
MP_PUBLIC_KEY = os.environ.get("MP_PUBLIC_KEY", "")
MP_CLIENT_ID = os.environ.get("MP_CLIENT_ID", "")
MP_CLIENT_SECRET = os.environ.get("MP_CLIENT_SECRET", "")
MP_REDIRECT_URI = os.environ.get("MP_REDIRECT_URI", "")


def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con


def _column_names(con, table):
    return {r["name"] for r in con.execute(f"PRAGMA table_info({table})").fetchall()}


def init_db():
    con = db()
    cur = con.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE COLLATE NOCASE,
        password_hash TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)

    user_cols = _column_names(con, "users")
    if "mp_access_token" not in user_cols:
        cur.execute("ALTER TABLE users ADD COLUMN mp_access_token TEXT")
    if "mp_refresh_token" not in user_cols:
        cur.execute("ALTER TABLE users ADD COLUMN mp_refresh_token TEXT")
    if "mp_user_id" not in user_cols:
        cur.execute("ALTER TABLE users ADD COLUMN mp_user_id TEXT")
    if "mp_connected_at" not in user_cols:
        cur.execute("ALTER TABLE users ADD COLUMN mp_connected_at TEXT")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        price REAL NOT NULL,
        category TEXT NOT NULL,
        description TEXT DEFAULT '',
        stock INTEGER NOT NULL DEFAULT 1,
        image TEXT DEFAULT '',
        seller_id INTEGER,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(seller_id) REFERENCES users(id)
    )
    """)

    # Migración suave si se usa una base de una versión anterior.
    if "seller_id" not in _column_names(con, "products"):
        cur.execute("ALTER TABLE products ADD COLUMN seller_id INTEGER")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT NOT NULL UNIQUE,
        customer_name TEXT NOT NULL,
        customer_phone TEXT NOT NULL,
        customer_email TEXT DEFAULT '',
        customer_address TEXT NOT NULL,
        notes TEXT DEFAULT '',
        total REAL NOT NULL,
        status TEXT NOT NULL DEFAULT 'Pendiente',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)

    order_cols = _column_names(con, "orders")
    if "payment_id" not in order_cols:
        cur.execute("ALTER TABLE orders ADD COLUMN payment_id TEXT")
    if "payment_status" not in order_cols:
        cur.execute("ALTER TABLE orders ADD COLUMN payment_status TEXT DEFAULT ''")
    if "marketplace_fee" not in order_cols:
        cur.execute("ALTER TABLE orders ADD COLUMN marketplace_fee REAL NOT NULL DEFAULT 0")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS order_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL,
        product_id INTEGER,
        product_name TEXT NOT NULL,
        price REAL NOT NULL,
        quantity INTEGER NOT NULL,
        seller_id INTEGER,
        commission REAL NOT NULL DEFAULT 0,
        seller_net REAL NOT NULL DEFAULT 0,
        FOREIGN KEY(order_id) REFERENCES orders(id),
        FOREIGN KEY(seller_id) REFERENCES users(id)
    )
    """)

    cols = _column_names(con, "order_items")
    if "seller_id" not in cols:
        cur.execute("ALTER TABLE order_items ADD COLUMN seller_id INTEGER")
    if "commission" not in cols:
        cur.execute("ALTER TABLE order_items ADD COLUMN commission REAL NOT NULL DEFAULT 0")
    if "seller_net" not in cols:
        cur.execute("ALTER TABLE order_items ADD COLUMN seller_net REAL NOT NULL DEFAULT 0")

    count = cur.execute("SELECT COUNT(*) c FROM products").fetchone()["c"]
    if count == 0:
        seed = [
            ("Chomba clásica", 24999, "ropa", "Chomba cómoda de corte clásico.", 1, "", None),
            ("Buzo urbano", 39999, "ropa", "Buzo unisex de estilo urbano.", 1, "", None),
            ("Pantalón cargo", 44999, "ropa", "Pantalón cargo con bolsillos laterales.", 1, "", None),
        ]
        cur.executemany("""
        INSERT INTO products(name,price,category,description,stock,image,seller_id)
        VALUES(?,?,?,?,?,?,?)
        """, seed)

    con.commit()
    con.close()


init_db()


def verify_admin_password(password):
    return bool(ADMIN_PASSWORD) and hmac.compare_digest(password, ADMIN_PASSWORD)


def admin_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return jsonify({"error": "No autorizado"}), 401
        return fn(*args, **kwargs)
    return wrapper


def user_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify({"error": "Tenés que iniciar sesión"}), 401
        return fn(*args, **kwargs)
    return wrapper


def save_image(file):
    if not file or not file.filename:
        return ""
    safe = secure_filename(file.filename)
    ext = Path(safe).suffix.lower()
    if ext not in {".jpg", ".jpeg", ".png", ".webp", ".gif"}:
        return ""
    filename = f"{int(time.time()*1000)}_{secrets.token_hex(3)}{ext}"
    file.save(UPLOAD_FOLDER / filename)
    return f"/uploads/{filename}"


@app.get("/")
def home():
    return render_template("index.html")


@app.get("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)


# ---------- Usuarios ----------
@app.get("/api/auth/status")
def auth_status():
    uid = session.get("user_id")
    if not uid:
        return jsonify({"logged_in": False})
    con = db()
    u = con.execute("SELECT id,name,email, CASE WHEN mp_access_token IS NOT NULL AND mp_access_token != '' THEN 1 ELSE 0 END AS mp_connected FROM users WHERE id=?", (uid,)).fetchone()
    con.close()
    if not u:
        session.pop("user_id", None)
        return jsonify({"logged_in": False})
    return jsonify({"logged_in": True, "user": dict(u)})


@app.post("/api/auth/register")
def register():
    data = request.get_json(force=True)
    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    if len(name) < 2:
        return jsonify({"error": "Ingresá tu nombre"}), 400
    if "@" not in email or "." not in email.split("@")[-1]:
        return jsonify({"error": "Email inválido"}), 400
    if len(password) < 6:
        return jsonify({"error": "La contraseña debe tener al menos 6 caracteres"}), 400
    con = db()
    try:
        cur = con.cursor()
        cur.execute("INSERT INTO users(name,email,password_hash) VALUES(?,?,?)",
                    (name, email, generate_password_hash(password)))
        con.commit()
        session["user_id"] = cur.lastrowid
    except sqlite3.IntegrityError:
        con.close()
        return jsonify({"error": "Ese email ya está registrado"}), 409
    con.close()
    return jsonify({"ok": True}), 201


@app.post("/api/auth/login")
def user_login():
    data = request.get_json(force=True)
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    con = db()
    u = con.execute("SELECT * FROM users WHERE email=? COLLATE NOCASE", (email,)).fetchone()
    con.close()
    if not u or not check_password_hash(u["password_hash"], password):
        return jsonify({"error": "Email o contraseña incorrectos"}), 401
    session["user_id"] = u["id"]
    return jsonify({"ok": True})


@app.post("/api/auth/logout")
def user_logout():
    session.pop("user_id", None)
    return jsonify({"ok": True})


# ---------- Admin ----------
@app.get("/api/admin/status")
def admin_status():
    return jsonify({"logged_in": bool(session.get("admin_logged_in"))})


@app.post("/api/admin/login")
def admin_login():
    data = request.get_json(force=True)
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    if username == ADMIN_USERNAME and verify_admin_password(password):
        session["admin_logged_in"] = True
        return jsonify({"ok": True})
    return jsonify({"error": "Usuario o contraseña incorrectos"}), 401


@app.post("/api/admin/logout")
def admin_logout():
    session.pop("admin_logged_in", None)
    return jsonify({"ok": True})


# ---------- Mercado Pago / Marketplace ----------
@app.get("/api/mp/config")
def mp_config():
    return jsonify({
        "public_key": MP_PUBLIC_KEY,
        "configured": bool(MP_PUBLIC_KEY and MP_ACCESS_TOKEN),
        "oauth_configured": bool(MP_CLIENT_ID and MP_CLIENT_SECRET and MP_REDIRECT_URI),
        "commission_rate": COMMISSION_RATE,
    })


@app.get("/api/mp/status")
@user_required
def mp_status():
    con = db()
    u = con.execute("SELECT mp_user_id, mp_connected_at, mp_access_token FROM users WHERE id=?", (session["user_id"],)).fetchone()
    con.close()
    return jsonify({
        "connected": bool(u and u["mp_access_token"]),
        "mp_user_id": u["mp_user_id"] if u else None,
        "connected_at": u["mp_connected_at"] if u else None,
        "oauth_configured": bool(MP_CLIENT_ID and MP_CLIENT_SECRET and MP_REDIRECT_URI),
    })


@app.get("/api/mp/oauth/start")
@user_required
def mp_oauth_start():
    if not (MP_CLIENT_ID and MP_CLIENT_SECRET and MP_REDIRECT_URI):
        return jsonify({"error": "Falta configurar MP_CLIENT_ID, MP_CLIENT_SECRET o MP_REDIRECT_URI en Render"}), 503
    state = secrets.token_urlsafe(24)
    session["mp_oauth_state"] = state
    session["mp_oauth_user_id"] = session["user_id"]
    params = {
        "client_id": MP_CLIENT_ID,
        "response_type": "code",
        "platform_id": "mp",
        "redirect_uri": MP_REDIRECT_URI,
        "state": state,
    }
    return jsonify({"url": "https://auth.mercadopago.com.ar/authorization?" + urlencode(params)})


@app.get("/api/mp/oauth/callback")
def mp_oauth_callback():
    code = request.args.get("code", "")
    state = request.args.get("state", "")
    expected_state = session.get("mp_oauth_state", "")
    uid = session.get("mp_oauth_user_id")
    if not code or not state or not expected_state or not hmac.compare_digest(state, expected_state) or not uid:
        return "Autorización inválida o vencida. Volvé a Compra y Venta e intentá de nuevo.", 400
    if not (MP_CLIENT_ID and MP_CLIENT_SECRET and MP_REDIRECT_URI):
        return "Falta configurar OAuth de Mercado Pago en el servidor.", 503
    try:
        r = requests.post(
            "https://api.mercadopago.com/oauth/token",
            headers={"accept": "application/json", "content-type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "authorization_code",
                "client_id": MP_CLIENT_ID,
                "client_secret": MP_CLIENT_SECRET,
                "code": code,
                "redirect_uri": MP_REDIRECT_URI,
            },
            timeout=20,
        )
        data = r.json()
    except Exception:
        return "No pudimos comunicarnos con Mercado Pago. Intentá nuevamente.", 502
    if not r.ok or not data.get("access_token"):
        return f"Mercado Pago rechazó la autorización. Código {r.status_code}.", 400
    con = db()
    con.execute("""
        UPDATE users SET mp_access_token=?, mp_refresh_token=?, mp_user_id=?, mp_connected_at=CURRENT_TIMESTAMP
        WHERE id=?
    """, (data.get("access_token"), data.get("refresh_token", ""), str(data.get("user_id", "")), uid))
    con.commit(); con.close()
    session.pop("mp_oauth_state", None); session.pop("mp_oauth_user_id", None)
    return """<!doctype html><html lang="es"><meta charset="utf-8"><title>Mercado Pago conectado</title>
    <body style="font-family:Arial;padding:40px;text-align:center"><h1>Mercado Pago conectado</h1>
    <p>Ya podés volver a Compra y Venta.</p><a href="/">Volver al marketplace</a></body></html>"""


@app.post("/api/mp/disconnect")
@user_required
def mp_disconnect():
    con = db()
    con.execute("UPDATE users SET mp_access_token=NULL,mp_refresh_token=NULL,mp_user_id=NULL,mp_connected_at=NULL WHERE id=?", (session["user_id"],))
    con.commit(); con.close()
    return jsonify({"ok": True})


def build_cart(items):
    con = db(); cur = con.cursor()
    total = 0.0; final_items = []; seller_ids = set()
    for item in items:
        try:
            pid = int(item["id"]); qty = max(1, int(item["qty"]))
        except Exception:
            continue
        p = cur.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
        if not p or not p["stock"]:
            continue
        subtotal = round(float(p["price"]) * qty, 2)
        total += subtotal
        seller_ids.add(p["seller_id"])
        final_items.append((p, qty, subtotal))
    if not final_items:
        con.close(); return None, "No hay productos disponibles en el pedido"
    if len(seller_ids) > 1:
        con.close(); return None, "Por ahora cada pago puede incluir productos de un solo vendedor. Separá la compra en dos pedidos."
    seller_id = next(iter(seller_ids))
    seller_token = MP_ACCESS_TOKEN
    seller_name = "Compra y Venta"
    if seller_id is not None:
        seller = cur.execute("SELECT name,mp_access_token FROM users WHERE id=?", (seller_id,)).fetchone()
        if not seller or not seller["mp_access_token"]:
            con.close(); return None, "Este vendedor todavía no conectó su cuenta de Mercado Pago."
        seller_token = seller["mp_access_token"]
        seller_name = seller["name"]
    con.close()
    return {
        "total": round(total, 2), "items": final_items, "seller_id": seller_id,
        "seller_token": seller_token, "seller_name": seller_name,
        "fee": round(total * COMMISSION_RATE, 2) if seller_id is not None else 0,
    }, None


@app.post("/api/mp/pro-test")
def mp_pro_test():
    data = request.get_json(force=True)
    items = data.get("items", [])

    cart_data, error = build_cart(items)
    if error:
        return jsonify({"error": error}), 400

    if cart_data["seller_id"] is None:
        return jsonify({"error": "Esta prueba es solo para productos de vendedores externos"}), 400

    preference = {
        "items": [
            {
                "id": str(p["id"]),
                "title": p["name"],
                "currency_id": "ARS",
                "quantity": qty,
                "unit_price": float(p["price"]),
            }
            for p, qty, subtotal in cart_data["items"]
        ],
        "marketplace_fee": cart_data["fee"],
        "external_reference": f"TEST-{int(time.time())}",
    }

    try:
        r = requests.post(
            "https://api.mercadopago.com/checkout/preferences",
            headers={
                "Authorization": f"Bearer {cart_data['seller_token']}",
                "Content-Type": "application/json",
            },
            json=preference,
            timeout=25,
        )
        result = r.json()

        if not r.ok:
            return jsonify({
                "error": "Mercado Pago rechazó la preferencia",
                "detail": result
            }), 400

        return jsonify({
            "ok": True,
            "init_point": result.get("init_point"),
            "sandbox_init_point": result.get("sandbox_init_point"),
            "preference_id": result.get("id"),
            "marketplace_fee": cart_data["fee"],
        })

    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.post("/api/mp/pay")
def mp_pay():
    data = request.get_json(force=True)
    customer = data.get("customer", {})
    items = data.get("items", [])
    form_data = data.get("payment", {}) or {}
    selected_payment_method = str(data.get("selected_payment_method", "") or "").strip()
    name = str(customer.get("name", "")).strip()
    phone = str(customer.get("phone", "")).strip()
    email = str(customer.get("email", "")).strip()
    address = str(customer.get("address", "")).strip()
    notes = str(customer.get("notes", "")).strip()
    if not name or not phone or not email or not address:
        return jsonify({"error": "Completá nombre, teléfono, email y dirección"}), 400

    cart_data, error = build_cart(items)
    if error:
        return jsonify({"error": error}), 400
    if not cart_data["seller_token"]:
        return jsonify({"error": "Mercado Pago todavía no está configurado en el servidor"}), 503

    token = form_data.get("token")
    payment_method_id = form_data.get("payment_method_id")
    installments = int(form_data.get("installments") or 1)
    if not token or not payment_method_id:
        return jsonify({"error": "Faltan los datos tokenizados de la tarjeta"}), 400

    code = f"CV-{str(int(time.time()*1000))[-8:]}"

    # La aplicación fue creada como Checkout API vía Orders. Para productos propios
    # usamos la API /v1/orders (recomendada por Mercado Pago para esta integración).
    # Para sellers conectados por OAuth conservamos /v1/payments porque el Split 1:1
    # documenta application_fee en esa API.
    try:
        if cart_data["seller_id"] is None:
            pm_type = selected_payment_method
            if pm_type not in {"credit_card", "debit_card"}:
                # Payment Brick puede no entregar el tipo en algunas versiones.
                # Para la prueba actual con tarjeta, credit_card es el caso esperado.
                pm_type = "credit_card"

            amount = f"{cart_data['total']:.2f}"
            payload = {
                "type": "online",
                "processing_mode": "automatic",
                "total_amount": amount,
                "external_reference": code,
                "payer": {"email": email},
                "transactions": {
                    "payments": [{
                        "amount": amount,
                        "payment_method": {
                            "id": payment_method_id,
                            "type": pm_type,
                            "token": token,
                            "installments": installments,
                        }
                    }]
                }
            }
            r = requests.post(
                "https://api.mercadopago.com/v1/orders",
                headers={
                    "Authorization": f"Bearer {cart_data['seller_token']}",
                    "Content-Type": "application/json",
                    "X-Idempotency-Key": secrets.token_hex(16),
                },
                json=payload,
                timeout=25,
            )
            mp_data = r.json()
            if not r.ok:
                details = mp_data.get("errors") or mp_data.get("cause") or mp_data.get("message") or mp_data
                return jsonify({
                    "error": "Mercado Pago rechazó la orden",
                    "mp_status": r.status_code,
                    "mp_detail": str(details)[:700],
                }), 400

            order_mp_id = str(mp_data.get("id", ""))
            payment_status = str(mp_data.get("status", ""))
            status_detail = str(mp_data.get("status_detail", ""))
            payments = ((mp_data.get("transactions") or {}).get("payments") or [])
            payment_id = str(payments[0].get("id", "")) if payments and isinstance(payments[0], dict) else order_mp_id
            approved = payment_status == "processed" and status_detail == "accredited"
        else:
            payer = form_data.get("payer") or {}
            payer["email"] = email
            payload = {
                "transaction_amount": cart_data["total"],
                "token": token,
                "description": f"Compra y Venta - {cart_data['seller_name']}",
                "installments": installments,
                "payment_method_id": payment_method_id,
                "issuer_id": form_data.get("issuer_id"),
                "payer": payer,
                "external_reference": code,
                "application_fee": cart_data["fee"],
            }
            payload = {k: v for k, v in payload.items() if v not in (None, "")}
            r = requests.post(
                "https://api.mercadopago.com/v1/payments",
                headers={
                    "Authorization": f"Bearer {cart_data['seller_token']}",
                    "Content-Type": "application/json",
                    "X-Idempotency-Key": secrets.token_hex(16),
                },
                json=payload,
                timeout=25,
            )
            mp_data = r.json()
            if not r.ok:
                details = mp_data.get("cause") or mp_data.get("message") or mp_data
                return jsonify({
                    "error": "Mercado Pago rechazó el pago del vendedor",
                    "mp_status": r.status_code,
                    "mp_detail": str(details)[:700],
                }), 400
            payment_id = str(mp_data.get("id", ""))
            payment_status = str(mp_data.get("status", ""))
            status_detail = str(mp_data.get("status_detail", ""))
            approved = payment_status == "approved"

    except Exception as exc:
        return jsonify({"error": "No pudimos comunicarnos con Mercado Pago", "detail": str(exc)[:250]}), 502

    con = db(); cur = con.cursor()
    cur.execute("""
        INSERT INTO orders(code,customer_name,customer_phone,customer_email,customer_address,notes,total,status,payment_id,payment_status,marketplace_fee)
        VALUES(?,?,?,?,?,?,?,?,?,?,?)
    """, (code, name, phone, email, address, notes, cart_data["total"], "Pagado" if approved else "Pendiente", payment_id, f"{payment_status}:{status_detail}", cart_data["fee"]))
    order_id = cur.lastrowid
    rows = []
    for p, qty, subtotal in cart_data["items"]:
        commission = round(subtotal * COMMISSION_RATE, 2) if p["seller_id"] is not None else 0
        seller_net = round(subtotal - commission, 2) if p["seller_id"] is not None else subtotal
        rows.append((order_id, p["id"], p["name"], float(p["price"]), qty, p["seller_id"], commission, seller_net))
    cur.executemany("""
        INSERT INTO order_items(order_id,product_id,product_name,price,quantity,seller_id,commission,seller_net)
        VALUES(?,?,?,?,?,?,?,?)
    """, rows)
    con.commit(); con.close()

    return jsonify({
        "ok": True,
        "code": code,
        "payment_id": payment_id,
        "status": "approved" if approved else payment_status,
        "status_detail": status_detail,
        "total": cart_data["total"],
        "marketplace_fee": cart_data["fee"],
    }), 201


# ---------- Productos ----------
@app.get("/api/products")
def get_products():
    con = db()
    rows = con.execute("""
        SELECT p.*, COALESCE(u.name,'Compra y Venta') AS seller_name,
               CASE WHEN p.seller_id IS NULL OR (u.mp_access_token IS NOT NULL AND u.mp_access_token != '') THEN 1 ELSE 0 END AS seller_mp_connected
        FROM products p LEFT JOIN users u ON u.id=p.seller_id
        ORDER BY p.id DESC
    """).fetchall()
    con.close()
    return jsonify([dict(r) for r in rows])


def validate_product_form():
    name = request.form.get("name", "").strip()
    category = request.form.get("category", "otros").strip()
    description = request.form.get("description", "").strip()
    stock = 1 if request.form.get("stock", "1") == "1" else 0
    if not name:
        return None, "Falta el nombre"
    try:
        price = float(request.form.get("price", "0").strip())
        if price <= 0:
            raise ValueError
    except Exception:
        return None, "Precio inválido"
    return (name, price, category, description, stock), None


@app.post("/api/my/products")
@user_required
def create_my_product():
    values, error = validate_product_form()
    if error:
        return jsonify({"error": error}), 400
    image_path = save_image(request.files.get("image"))
    con = db()
    cur = con.cursor()
    cur.execute("""
        INSERT INTO products(name,price,category,description,stock,image,seller_id)
        VALUES(?,?,?,?,?,?,?)
    """, (*values, image_path, session["user_id"]))
    con.commit()
    new_id = cur.lastrowid
    row = con.execute("""
        SELECT p.*,u.name seller_name FROM products p JOIN users u ON u.id=p.seller_id WHERE p.id=?
    """, (new_id,)).fetchone()
    con.close()
    return jsonify(dict(row)), 201


@app.get("/api/my/products")
@user_required
def my_products():
    con = db()
    rows = con.execute("SELECT * FROM products WHERE seller_id=? ORDER BY id DESC", (session["user_id"],)).fetchall()
    con.close()
    return jsonify([dict(r) for r in rows])


@app.delete("/api/my/products/<int:product_id>")
@user_required
def delete_my_product(product_id):
    con = db()
    row = con.execute("SELECT seller_id FROM products WHERE id=?", (product_id,)).fetchone()
    if not row or row["seller_id"] != session["user_id"]:
        con.close()
        return jsonify({"error": "No autorizado"}), 403
    con.execute("DELETE FROM products WHERE id=?", (product_id,))
    con.commit()
    con.close()
    return jsonify({"ok": True})


@app.post("/api/products")
@admin_required
def create_product_admin():
    values, error = validate_product_form()
    if error:
        return jsonify({"error": error}), 400
    image_path = save_image(request.files.get("image"))
    con = db()
    cur = con.cursor()
    cur.execute("INSERT INTO products(name,price,category,description,stock,image,seller_id) VALUES(?,?,?,?,?,?,NULL)", (*values, image_path))
    con.commit()
    row = con.execute("SELECT p.*, 'Compra y Venta' seller_name FROM products p WHERE id=?", (cur.lastrowid,)).fetchone()
    con.close()
    return jsonify(dict(row)), 201


@app.put("/api/products/<int:product_id>")
@admin_required
def update_product(product_id):
    values, error = validate_product_form()
    if error:
        return jsonify({"error": error}), 400
    con = db()
    existing = con.execute("SELECT * FROM products WHERE id=?", (product_id,)).fetchone()
    if not existing:
        con.close()
        return jsonify({"error": "Producto no encontrado"}), 404
    image_path = existing["image"]
    new_image = save_image(request.files.get("image"))
    if new_image:
        image_path = new_image
    con.execute("UPDATE products SET name=?,price=?,category=?,description=?,stock=?,image=? WHERE id=?", (*values, image_path, product_id))
    con.commit()
    row = con.execute("""
        SELECT p.*,COALESCE(u.name,'Compra y Venta') seller_name
        FROM products p LEFT JOIN users u ON u.id=p.seller_id WHERE p.id=?
    """, (product_id,)).fetchone()
    con.close()
    return jsonify(dict(row))


@app.delete("/api/products/<int:product_id>")
@admin_required
def delete_product(product_id):
    con = db()
    con.execute("DELETE FROM products WHERE id=?", (product_id,))
    con.commit()
    con.close()
    return jsonify({"ok": True})


# ---------- Pedidos ----------
@app.post("/api/orders")
def create_order():
    data = request.get_json(force=True)
    customer = data.get("customer", {})
    items = data.get("items", [])
    name = str(customer.get("name", "")).strip()
    phone = str(customer.get("phone", "")).strip()
    email = str(customer.get("email", "")).strip()
    address = str(customer.get("address", "")).strip()
    notes = str(customer.get("notes", "")).strip()
    if not name or not phone or not address:
        return jsonify({"error": "Completá nombre, teléfono y dirección"}), 400
    if not items:
        return jsonify({"error": "El carrito está vacío"}), 400

    con = db()
    cur = con.cursor()
    total = 0
    final_items = []
    for item in items:
        try:
            pid = int(item["id"]); qty = max(1, int(item["qty"]))
        except Exception:
            continue
        p = cur.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
        if not p or not p["stock"]:
            continue
        subtotal = float(p["price"]) * qty
        commission = round(subtotal * COMMISSION_RATE, 2) if p["seller_id"] else 0
        seller_net = round(subtotal - commission, 2) if p["seller_id"] else subtotal
        total += subtotal
        final_items.append((pid, p["name"], float(p["price"]), qty, p["seller_id"], commission, seller_net))

    if not final_items:
        con.close()
        return jsonify({"error": "No hay productos disponibles en el pedido"}), 400

    code = f"CV-{str(int(time.time()*1000))[-8:]}"
    cur.execute("""
        INSERT INTO orders(code,customer_name,customer_phone,customer_email,customer_address,notes,total,status)
        VALUES(?,?,?,?,?,?,?,?)
    """, (code, name, phone, email, address, notes, total, "Pendiente"))
    order_id = cur.lastrowid
    cur.executemany("""
        INSERT INTO order_items(order_id,product_id,product_name,price,quantity,seller_id,commission,seller_net)
        VALUES(?,?,?,?,?,?,?,?)
    """, [(order_id, *x) for x in final_items])
    con.commit(); con.close()
    return jsonify({"ok": True, "code": code, "total": total}), 201


@app.get("/api/orders")
@admin_required
def get_orders():
    con = db()
    orders = con.execute("SELECT * FROM orders ORDER BY id DESC").fetchall()
    result = []
    for o in orders:
        items = con.execute("""
            SELECT oi.*, COALESCE(u.name,'Compra y Venta') seller_name
            FROM order_items oi LEFT JOIN users u ON u.id=oi.seller_id
            WHERE oi.order_id=?
        """, (o["id"],)).fetchall()
        d = dict(o); d["items"] = [dict(i) for i in items]; result.append(d)
    con.close(); return jsonify(result)


@app.patch("/api/orders/<int:order_id>/status")
@admin_required
def update_order_status(order_id):
    data = request.get_json(force=True)
    status = data.get("status", "Pendiente")
    allowed = ["Pendiente", "Preparando", "Enviado", "Entregado", "Cancelado"]
    if status not in allowed:
        return jsonify({"error": "Estado inválido"}), 400
    con = db(); con.execute("UPDATE orders SET status=? WHERE id=?", (status, order_id)); con.commit(); con.close()
    return jsonify({"ok": True})


@app.get("/robots.txt")
def robots():
    return "User-agent: *\nAllow: /\n", 200, {"Content-Type": "text/plain; charset=utf-8"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
