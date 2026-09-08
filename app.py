
from flask import Flask, render_template, request, jsonify, session, send_from_directory
import sqlite3
from pathlib import Path
from werkzeug.utils import secure_filename
import time, os, secrets, hashlib, hmac

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DATA_DIR", str(BASE_DIR)))
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "mercado_express.db"
UPLOAD_FOLDER = DATA_DIR / "uploads"
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = db()
    cur = con.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        price REAL NOT NULL,
        category TEXT NOT NULL,
        description TEXT DEFAULT '',
        stock INTEGER NOT NULL DEFAULT 1,
        image TEXT DEFAULT '',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)

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

    cur.execute("""
    CREATE TABLE IF NOT EXISTS order_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL,
        product_id INTEGER,
        product_name TEXT NOT NULL,
        price REAL NOT NULL,
        quantity INTEGER NOT NULL,
        FOREIGN KEY(order_id) REFERENCES orders(id)
    )
    """)

    count = cur.execute("SELECT COUNT(*) c FROM products").fetchone()["c"]
    if count == 0:
        seed = [
            ("Chomba clásica", 24999, "ropa", "Chomba cómoda de corte clásico.", 1, ""),
            ("Buzo urbano", 39999, "ropa", "Buzo unisex de estilo urbano.", 1, ""),
            ("Pantalón cargo", 44999, "ropa", "Pantalón cargo con bolsillos laterales.", 1, ""),
            ("Módulo iPhone 11", 69999, "modulos", "Consultar calidad y compatibilidad.", 1, ""),
            ("Módulo Samsung A06", 54999, "modulos", "Módulo compatible con Samsung Galaxy A06.", 1, ""),
            ("Cable USB-C", 8999, "accesorios", "Cable USB-C para carga.", 1, "")
        ]
        cur.executemany("""
        INSERT INTO products(name,price,category,description,stock,image)
        VALUES(?,?,?,?,?,?)
        """, seed)

    con.commit()
    con.close()


init_db()

def verify_admin_password(password):
    if not ADMIN_PASSWORD:
        return False
    return hmac.compare_digest(password, ADMIN_PASSWORD)

def admin_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return jsonify({"error":"No autorizado"}), 401
        return fn(*args, **kwargs)
    return wrapper

@app.get("/api/admin/status")
def admin_status():
    return jsonify({"logged_in": bool(session.get("admin_logged_in"))})

@app.post("/api/admin/login")
def admin_login():
    data = request.get_json(force=True)
    username = str(data.get("username","")).strip()
    password = str(data.get("password",""))
    if username == ADMIN_USERNAME and verify_admin_password(password):
        session["admin_logged_in"] = True
        return jsonify({"ok":True})
    return jsonify({"error":"Usuario o contraseña incorrectos"}), 401

@app.post("/api/admin/logout")
def admin_logout():
    session.clear()
    return jsonify({"ok":True})

@app.get("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route("/")
def home():
    return render_template("index.html")

@app.get("/api/products")
def get_products():
    con = db()
    rows = con.execute("SELECT * FROM products ORDER BY id DESC").fetchall()
    con.close()
    return jsonify([dict(r) for r in rows])

@app.post("/api/products")
@admin_required
def create_product():
    name = request.form.get("name","").strip()
    price = request.form.get("price","0").strip()
    category = request.form.get("category","ropa").strip()
    description = request.form.get("description","").strip()
    stock = 1 if request.form.get("stock","1") == "1" else 0

    if not name:
        return jsonify({"error":"Falta el nombre"}), 400
    try:
        price = float(price)
    except:
        return jsonify({"error":"Precio inválido"}), 400

    image_path = ""
    file = request.files.get("image")
    if file and file.filename:
        safe = secure_filename(file.filename)
        ext = Path(safe).suffix.lower()
        filename = f"{int(time.time()*1000)}{ext}"
        file.save(UPLOAD_FOLDER / filename)
        image_path = f"/uploads/{filename}"

    con = db()
    cur = con.cursor()
    cur.execute("""
        INSERT INTO products(name,price,category,description,stock,image)
        VALUES(?,?,?,?,?,?)
    """, (name, price, category, description, stock, image_path))
    con.commit()
    new_id = cur.lastrowid
    row = con.execute("SELECT * FROM products WHERE id=?", (new_id,)).fetchone()
    con.close()
    return jsonify(dict(row)), 201

@app.put("/api/products/<int:product_id>")
@admin_required
def update_product(product_id):
    name = request.form.get("name","").strip()
    price = request.form.get("price","0").strip()
    category = request.form.get("category","ropa").strip()
    description = request.form.get("description","").strip()
    stock = 1 if request.form.get("stock","1") == "1" else 0

    try:
        price = float(price)
    except:
        return jsonify({"error":"Precio inválido"}), 400

    con = db()
    existing = con.execute("SELECT * FROM products WHERE id=?", (product_id,)).fetchone()
    if not existing:
        con.close()
        return jsonify({"error":"Producto no encontrado"}), 404

    image_path = existing["image"]
    file = request.files.get("image")
    if file and file.filename:
        safe = secure_filename(file.filename)
        ext = Path(safe).suffix.lower()
        filename = f"{int(time.time()*1000)}{ext}"
        file.save(UPLOAD_FOLDER / filename)
        image_path = f"/uploads/{filename}"

    con.execute("""
        UPDATE products
        SET name=?, price=?, category=?, description=?, stock=?, image=?
        WHERE id=?
    """, (name, price, category, description, stock, image_path, product_id))
    con.commit()
    row = con.execute("SELECT * FROM products WHERE id=?", (product_id,)).fetchone()
    con.close()
    return jsonify(dict(row))

@app.delete("/api/products/<int:product_id>")
@admin_required
def delete_product(product_id):
    con = db()
    con.execute("DELETE FROM products WHERE id=?", (product_id,))
    con.commit()
    con.close()
    return jsonify({"ok":True})

@app.post("/api/orders")
def create_order():
    data = request.get_json(force=True)
    customer = data.get("customer", {})
    items = data.get("items", [])

    name = str(customer.get("name","")).strip()
    phone = str(customer.get("phone","")).strip()
    email = str(customer.get("email","")).strip()
    address = str(customer.get("address","")).strip()
    notes = str(customer.get("notes","")).strip()

    if not name or not phone or not address:
        return jsonify({"error":"Completá nombre, teléfono y dirección"}), 400
    if not items:
        return jsonify({"error":"El carrito está vacío"}), 400

    con = db()
    cur = con.cursor()
    total = 0
    final_items = []

    for item in items:
        try:
            product_id = int(item["id"])
            qty = max(1, int(item["qty"]))
        except:
            continue

        p = cur.execute("SELECT * FROM products WHERE id=?", (product_id,)).fetchone()
        if not p or not p["stock"]:
            continue

        subtotal = float(p["price"]) * qty
        total += subtotal
        final_items.append((product_id, p["name"], float(p["price"]), qty))

    if not final_items:
        con.close()
        return jsonify({"error":"No hay productos disponibles en el pedido"}), 400

    code = f"MX-{str(int(time.time()*1000))[-8:]}"
    cur.execute("""
        INSERT INTO orders(code,customer_name,customer_phone,customer_email,customer_address,notes,total,status)
        VALUES(?,?,?,?,?,?,?,?)
    """, (code,name,phone,email,address,notes,total,"Pendiente"))
    order_id = cur.lastrowid

    cur.executemany("""
        INSERT INTO order_items(order_id,product_id,product_name,price,quantity)
        VALUES(?,?,?,?,?)
    """, [(order_id,*x) for x in final_items])

    con.commit()
    con.close()
    return jsonify({"ok":True,"code":code,"total":total}), 201

@app.get("/api/orders")
@admin_required
def get_orders():
    con = db()
    orders = con.execute("SELECT * FROM orders ORDER BY id DESC").fetchall()
    result = []
    for o in orders:
        items = con.execute("SELECT * FROM order_items WHERE order_id=?", (o["id"],)).fetchall()
        d = dict(o)
        d["items"] = [dict(i) for i in items]
        result.append(d)
    con.close()
    return jsonify(result)

@app.patch("/api/orders/<int:order_id>/status")
@admin_required
def update_order_status(order_id):
    data = request.get_json(force=True)
    status = data.get("status","Pendiente")
    allowed = ["Pendiente","Preparando","Enviado","Entregado","Cancelado"]
    if status not in allowed:
        return jsonify({"error":"Estado inválido"}), 400

    con = db()
    con.execute("UPDATE orders SET status=? WHERE id=?", (status, order_id))
    con.commit()
    con.close()
    return jsonify({"ok":True})

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
