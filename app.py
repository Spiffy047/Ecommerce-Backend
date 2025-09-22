from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import bcrypt
from models import get_db, close_db, init_db

app = Flask(__name__)
CORS(app)
app.teardown_appcontext(close_db)
app.config["JWT_SECRET_KEY"] = "dev-secret"
jwt = JWTManager(app)

# --- AUTH ---
@app.post("/api/auth/register")
def register():
    data = request.get_json()
    email, password, name = data.get("email"), data.get("password"), data.get("name")
    if not email or not password:
        return jsonify(error="Email/password required"), 400
    db = get_db()
    if db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone():
        return jsonify(error="Email already in use"), 400
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    cur = db.execute("INSERT INTO users (email, password_hash, name) VALUES (?, ?, ?)",
                     (email, hashed, name))
    db.commit()
    token = create_access_token(identity=cur.lastrowid)
    return jsonify(token=token, user={"id": cur.lastrowid, "email": email, "name": name})

@app.post("/api/auth/login")
def login():
    data = request.get_json()
    email, password = data.get("email"), data.get("password")
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not user or not bcrypt.checkpw(password.encode(), user["password_hash"]):
        return jsonify(error="Invalid credentials"), 400
    token = create_access_token(identity=user["id"])
    return jsonify(token=token, user={"id": user["id"], "email": user["email"], "name": user["name"]})

# --- PRODUCTS ---
@app.get("/api/products")
def get_products():
    db = get_db()
    rows = db.execute("SELECT * FROM products").fetchall()
    return jsonify([dict(r) for r in rows])

@app.get("/api/products/<int:pid>")
def get_product(pid):
    db = get_db()
    row = db.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    if not row:
        return jsonify(error="Not found"), 404
    return jsonify(dict(row))

# --- REVIEWS ---
@app.get("/api/products/<int:pid>/reviews")
def get_reviews(pid):
    db = get_db()
    rows = db.execute("""SELECT r.*, u.email, u.name
                         FROM reviews r JOIN users u ON r.user_id=u.id
                         WHERE product_id=? ORDER BY created_at DESC""", (pid,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.post("/api/products/<int:pid>/reviews")
@jwt_required()
def add_review(pid):
    uid = get_jwt_identity()
    data = request.get_json()
    rating, title, body = data.get("rating"), data.get("title"), data.get("body")
    db = get_db()
    purchased = db.execute("""SELECT oi.id FROM order_items oi
                               JOIN orders o ON oi.order_id=o.id
                               WHERE o.user_id=? AND oi.product_id=?""", (uid, pid)).fetchone()
    if not purchased:
        return jsonify(error="Must purchase before reviewing"), 403
    cur = db.execute("INSERT INTO reviews (user_id, product_id, rating, title, body) VALUES (?, ?, ?, ?, ?)",
                     (uid, pid, rating, title, body))
    db.commit()
    return jsonify(dict(db.execute("SELECT * FROM reviews WHERE id=?", (cur.lastrowid,)).fetchone()))

# --- ORDERS ---
@app.post("/api/orders/checkout")
@jwt_required()
def checkout():
    uid = get_jwt_identity()
    items = request.get_json().get("items")
    if not items:
        return jsonify(error="No items"), 400
    db = get_db()
    cur = db.execute("INSERT INTO orders (user_id, status) VALUES (?, ?)", (uid, "completed"))
    order_id = cur.lastrowid
    for it in items:
        pid, qty = it["productId"], it["quantity"]
        prod = db.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
        if not prod or prod["inventory"] < qty:
            return jsonify(error="Invalid product or insufficient inventory"), 400
        db.execute("INSERT INTO order_items (order_id, product_id, quantity, price_at_purchase) VALUES (?,?,?,?)",
                   (order_id, pid, qty, prod["price"]))
        db.execute("UPDATE products SET inventory=inventory-? WHERE id=?", (qty, pid))
    db.commit()
    return jsonify(orderId=order_id)

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
