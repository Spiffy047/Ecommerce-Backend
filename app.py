import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import bcrypt
import sqlite3
from datetime import datetime

app = Flask(__name__)
CORS(app, origins=["*"], methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
app.config["JWT_SECRET_KEY"] = os.environ.get('JWT_SECRET_KEY', 'dev-secret')
jwt = JWTManager(app)

def get_db():
    return sqlite3.connect('ecommerce.db')

# AUTH ENDPOINTS
@app.post("/api/auth/login")
def login():
    data = request.get_json()
    email, password = data.get("email"), data.get("password")
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, password_hash, name, is_admin FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):
        return jsonify(error="Invalid credentials"), 401
    
    token = create_access_token(identity=user[0])
    return jsonify(access_token=token, user={"id": user[0], "name": user[2], "email": email, "is_admin": user[3]})

@app.post("/api/auth/admin-login")
def admin_login():
    data = request.get_json()
    email, password = data.get("email"), data.get("password")
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, password_hash, name FROM users WHERE email = ? AND is_admin = 1", (email,))
    user = cursor.fetchone()
    conn.close()
    
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):
        return jsonify(error="Invalid admin credentials"), 401
    
    token = create_access_token(identity=user[0])
    return jsonify(access_token=token, user={"id": user[0], "name": user[2], "email": email, "is_admin": 1})

@app.post("/api/auth/register")
def register():
    data = request.get_json()
    email, password, name = data.get("email"), data.get("password"), data.get("name")
    
    if not all([email, password, name]):
        return jsonify(error="Missing required fields"), 400
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Check if user exists
    cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
    if cursor.fetchone():
        conn.close()
        return jsonify(error="User already exists"), 409
    
    # Create user
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    cursor.execute("INSERT INTO users (email, password_hash, name) VALUES (?, ?, ?)", 
                   (email, password_hash, name))
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    token = create_access_token(identity=user_id)
    return jsonify(access_token=token, user={"id": user_id, "name": name, "email": email})

# PRODUCT ENDPOINTS
@app.get("/api/products")
def get_products():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, description, price, image_url, stock FROM products")
    products = [{"id": row[0], "name": row[1], "description": row[2], "price": row[3], "image_url": row[4], "stock": row[5]} 
                for row in cursor.fetchall()]
    conn.close()
    return jsonify(products)

@app.get("/api/products/<int:pid>")
def get_product(pid):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, description, price, image_url, stock FROM products WHERE id = ?", (pid,))
    product = cursor.fetchone()
    conn.close()
    
    if not product:
        return jsonify(error="Product not found"), 404
    
    return jsonify({"id": product[0], "name": product[1], "description": product[2], 
                   "price": product[3], "image_url": product[4], "stock": product[5]})

@app.post("/api/products")
@jwt_required()
def add_product():
    user_id = get_jwt_identity()
    
    # Check admin
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT is_admin FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if not user or not user[0]:
        conn.close()
        return jsonify(error="Admin access required"), 403
    
    data = request.get_json()
    name = data.get("name")
    description = data.get("description")
    price = data.get("price")
    image_url = data.get("image_url")
    stock = data.get("stock", 0)
    
    if not name:
        conn.close()
        return jsonify(error="Product name required"), 400
    
    cursor.execute("INSERT INTO products (name, description, price, image_url, stock) VALUES (?, ?, ?, ?, ?)",
                   (name, description, price, image_url, stock))
    product_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return jsonify({"id": product_id, "name": name, "description": description, 
                   "price": price, "image_url": image_url, "stock": stock}), 201

@app.put("/api/products/<int:pid>")
@jwt_required()
def update_product(pid):
    user_id = get_jwt_identity()
    
    # Check admin
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT is_admin FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if not user or not user[0]:
        conn.close()
        return jsonify(error="Admin access required"), 403
    
    data = request.get_json()
    cursor.execute("UPDATE products SET name=?, description=?, price=?, image_url=?, stock=? WHERE id=?",
                   (data.get("name"), data.get("description"), data.get("price"), 
                    data.get("image_url"), data.get("stock"), pid))
    conn.commit()
    conn.close()
    
    return jsonify({"id": pid, **data})

@app.delete("/api/products/<int:pid>")
@jwt_required()
def delete_product(pid):
    user_id = get_jwt_identity()
    
    # Check admin
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT is_admin FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if not user or not user[0]:
        conn.close()
        return jsonify(error="Admin access required"), 403
    
    cursor.execute("DELETE FROM products WHERE id = ?", (pid,))
    conn.commit()
    conn.close()
    
    return jsonify(message="Product deleted")

# REVIEW ENDPOINTS
@app.get("/api/products/<int:pid>/reviews")
def get_reviews(pid):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT r.id, r.rating, r.comment, r.created_at, u.name 
        FROM reviews r 
        JOIN users u ON r.user_id = u.id 
        WHERE r.product_id = ?
    """, (pid,))
    reviews = [{"id": row[0], "rating": row[1], "comment": row[2], 
               "created_at": row[3], "user_name": row[4]} 
               for row in cursor.fetchall()]
    conn.close()
    return jsonify(reviews)

@app.post("/api/products/<int:pid>/reviews")
@jwt_required()
def add_review(pid):
    user_id = get_jwt_identity()
    data = request.get_json()
    rating = data.get("rating")
    comment = data.get("comment")
    
    if not rating or not comment:
        return jsonify(error="Rating and comment required"), 400
    
    if not isinstance(rating, int) or rating < 1 or rating > 5:
        return jsonify(error="Rating must be 1-5"), 400
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Check if product exists
    cursor.execute("SELECT id FROM products WHERE id = ?", (pid,))
    if not cursor.fetchone():
        conn.close()
        return jsonify(error="Product not found"), 404
    
    # Add review
    cursor.execute("INSERT INTO reviews (user_id, product_id, rating, comment) VALUES (?, ?, ?, ?)",
                   (user_id, pid, rating, comment))
    review_id = cursor.lastrowid
    
    # Get user name
    cursor.execute("SELECT name FROM users WHERE id = ?", (user_id,))
    user_name = cursor.fetchone()[0]
    
    conn.commit()
    conn.close()
    
    return jsonify({"id": review_id, "rating": rating, "comment": comment, 
                   "user_name": user_name, "created_at": datetime.now().isoformat()}), 201

# CHECKOUT ENDPOINT
@app.post("/api/orders/checkout")
@jwt_required()
def checkout():
    user_id = get_jwt_identity()
    data = request.get_json()
    items = data.get("items", [])
    
    if not items:
        return jsonify(error="No items"), 400
    
    conn = get_db()
    cursor = conn.cursor()
    
    total_amount = 0
    
    # Create order
    cursor.execute("INSERT INTO orders (user_id, status, total_amount) VALUES (?, ?, ?)",
                   (user_id, "completed", 0))
    order_id = cursor.lastrowid
    
    # Process items
    for item in items:
        product_id = item.get("productId")
        quantity = item.get("quantity")
        
        # Get product
        cursor.execute("SELECT price, stock FROM products WHERE id = ?", (product_id,))
        product = cursor.fetchone()
        
        if not product or product[1] < quantity:
            conn.rollback()
            conn.close()
            return jsonify(error="Insufficient stock"), 400
        
        price = product[0]
        total_amount += price * quantity
        
        # Add order item
        cursor.execute("INSERT INTO order_items (order_id, product_id, quantity, price_at_time) VALUES (?, ?, ?, ?)",
                       (order_id, product_id, quantity, price))
        
        # Update stock
        cursor.execute("UPDATE products SET stock = stock - ?, total_sold = total_sold + ? WHERE id = ?",
                       (quantity, quantity, product_id))
    
    # Update order total
    cursor.execute("UPDATE orders SET total_amount = ? WHERE id = ?", (total_amount, order_id))
    
    conn.commit()
    conn.close()
    
    return jsonify(message="Checkout successful", order_id=order_id)

# ADMIN ENDPOINTS
@app.get("/api/admin/bestsellers")
@jwt_required()
def get_bestsellers():
    user_id = get_jwt_identity()
    
    # Check admin
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT is_admin FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if not user or not user[0]:
        conn.close()
        return jsonify(error="Admin access required"), 403
    
    cursor.execute("SELECT id, name, total_sold, price, image_url FROM products ORDER BY total_sold DESC LIMIT 10")
    bestsellers = [{"id": row[0], "name": row[1], "total_sold": row[2], "price": row[3], "image_url": row[4]} 
                   for row in cursor.fetchall()]
    conn.close()
    return jsonify(bestsellers)

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)