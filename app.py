# app.py
import os
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from functools import wraps
import bcrypt
from models import get_db, init_db, User, Product, Review, Order, order_items_table
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import and_

# --- Flask & SQLAlchemy Setup ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
REACT_BUILD_DIR = os.path.join(BASE_DIR, '..', 'frontend', 'dist')

app = Flask(__name__, static_folder=REACT_BUILD_DIR)
CORS(app) 
app.config["JWT_SECRET_KEY"] = "dev-secret"
jwt = JWTManager(app)

# Admin authentication decorator
def admin_required(f):
    @wraps(f)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        user_id = get_jwt_identity()
        user = session.query(User).filter_by(id=user_id).first()
        if not user or not user.is_admin:
            return jsonify(error="Admin access required"), 403
        return f(*args, **kwargs)
    return decorated_function

engine = create_engine('sqlite:///ecommerce.db')
Session = sessionmaker(bind=engine)
session = Session()

# This route serves your React app's static files
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    if path != "" and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    else:
        return send_from_directory(app.static_folder, 'index.html')

# --- AUTH ---
@app.post("/api/auth/register")
def register():
    data = request.get_json()
    email, password, name = data.get("email"), data.get("password"), data.get("name")
    
    if not email or not password:
        return jsonify(error="Email and password are required"), 400
    
    existing_user = session.query(User).filter_by(email=email).first()
    if existing_user:
        return jsonify(error="User already exists"), 409
        
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    new_user = User(email=email, password_hash=password_hash, name=name)
    session.add(new_user)
    session.commit()
    
    access_token = create_access_token(identity=new_user.id)
    return jsonify(message="User created successfully", access_token=access_token), 201

@app.post("/api/auth/login")
def login():
    data = request.get_json()
    email, password = data.get("email"), data.get("password")
    
    user = session.query(User).filter_by(email=email).first()
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
        return jsonify(error="Invalid email or password"), 401
    
    access_token = create_access_token(identity=user.id)
    return jsonify(access_token=access_token), 200

@app.post("/api/auth/change-password")
@jwt_required()
def change_password():
    try:
        user_id = get_jwt_identity()
        user = session.query(User).filter_by(id=user_id).first()
        if not user:
            return jsonify(error="User not found"), 404
            
        data = request.get_json()
        current_password = data.get("currentPassword")
        new_password = data.get("newPassword")
        
        if not current_password or not new_password:
            return jsonify(error="Current and new passwords are required"), 400
            
        if not bcrypt.checkpw(current_password.encode('utf-8'), user.password_hash.encode('utf-8')):
            return jsonify(error="Current password is incorrect"), 400
            
        user.password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        session.commit()
        
        return jsonify(message="Password changed successfully"), 200
        
    except Exception as e:
        session.rollback()
        print(f"Error changing password: {e}")
        return jsonify(error="Failed to change password"), 500

# --- PRODUCTS ---
@app.get("/api/products")
def get_products():
    try:
        products = session.query(Product).all()
        product_list = []
        for p in products:
            product_list.append({
                'id': p.id,
                'name': p.name,
                'description': p.description,
                'price': p.price,
                'image_url': p.image_url,
                'stock': p.stock
            })
        return jsonify(product_list)
    except Exception as e:
        print(f"Error fetching products: {e}")
        import traceback
        traceback.print_exc()
        return jsonify([]), 200

@app.get("/api/products/<int:pid>")
def get_product(pid):
    try:
        product = session.query(Product).filter_by(id=pid).first()
        if not product:
            return jsonify(error="Product not found"), 404
        
        return jsonify({
            'id': product.id,
            'name': product.name,
            'description': product.description,
            'price': product.price,
            'image_url': product.image_url,
            'stock': product.stock
        }), 200
    except Exception as e:
        print(f"Error fetching product: {e}")
        return jsonify(error="Product not found"), 404

@app.post("/api/products")
@admin_required
def add_product():
    data = request.get_json()
    name = data.get("name")
    if not name:
        return jsonify(error="Product name is required"), 400
    
    new_product = Product(
        name=name,
        description=data.get("description"),
        price=data.get("price"),
        image_url=data.get("image_url"),
        stock=data.get("stock")
    )
    session.add(new_product)
    session.commit()
    return jsonify(new_product.to_dict()), 201

@app.put("/api/products/<int:pid>")
@admin_required
def update_product(pid):
    try:
        product = session.query(Product).filter_by(id=pid).first()
        if not product:
            return jsonify(error="Product not found"), 404
        
        data = request.get_json()
        print(f"Updating product {pid} with data:", data)
        
        # Update all fields
        if "name" in data:
            product.name = data["name"]
        if "description" in data:
            product.description = data["description"]
        if "price" in data:
            product.price = float(data["price"])
        if "stock" in data:
            product.stock = int(data["stock"])
        if "image_url" in data:
            product.image_url = data["image_url"]
            print(f"Updated image_url to: {product.image_url}")
        
        session.commit()
        updated_product = product.to_dict()
        print(f"Product updated successfully:", updated_product)
        return jsonify(updated_product)
        
    except Exception as e:
        session.rollback()
        print(f"Error updating product: {e}")
        return jsonify(error=str(e)), 500

@app.delete("/api/products/<int:pid>")
@admin_required
def delete_product(pid):
    product = session.query(Product).filter_by(id=pid).first()
    if not product:
        return jsonify(error="Product not found"), 404
    
    session.delete(product)
    session.commit()
    return jsonify(message="Product deleted"), 200

# --- REVIEWS ---
@app.get("/api/products/<int:pid>/reviews")
def get_reviews(pid):
    try:
        reviews = session.query(Review).filter_by(product_id=pid).all()
        review_list = []
        for r in reviews:
            review_list.append({
                'id': r.id,
                'rating': r.rating,
                'comment': r.comment,
                'created_at': r.created_at.isoformat() if r.created_at else None
            })
        return jsonify(review_list), 200
    except Exception as e:
        print(f"Error fetching reviews: {e}")
        return jsonify([]), 200

@app.post("/api/products/<int:pid>/reviews")
def add_review(pid):
    try:
        # Check if product exists
        product = session.query(Product).filter_by(id=pid).first()
        if not product:
            return jsonify(error="Product not found"), 404
            
        data = request.get_json()
        rating, comment = data.get("rating"), data.get("comment")
        
        if not rating or not comment:
            return jsonify(error="Rating and comment are required"), 400
            
        if not isinstance(rating, int) or rating < 1 or rating > 5:
            return jsonify(error="Rating must be between 1 and 5"), 400
        
        # Ensure default user exists
        default_user = session.query(User).filter_by(email="demo@example.com").first()
        if not default_user:
            return jsonify(error="Default user not found"), 500
        
        new_review = Review(
            user_id=default_user.id, 
            product_id=pid, 
            rating=rating, 
            comment=comment
        )
        session.add(new_review)
        session.commit()
        
        return jsonify({
            'id': new_review.id,
            'rating': new_review.rating,
            'comment': new_review.comment,
            'created_at': new_review.created_at.isoformat() if new_review.created_at else None
        }), 201
        
    except Exception as e:
        session.rollback()
        print(f"Error adding review: {e}")
        return jsonify(error="Failed to add review"), 500

# --- ORDERS ---
@app.post("/api/orders/checkout")
@jwt_required()
def checkout():
    user_id = get_jwt_identity()
    items = request.get_json().get("items")
    if not items:
        return jsonify(error="No items"), 400

    new_order = Order(user_id=user_id, status="completed")
    session.add(new_order)
    
    for item_data in items:
        product = session.query(Product).filter_by(id=item_data["productId"]).first()
        if not product or product.stock < item_data["quantity"]:
            session.rollback()
            return jsonify(error="Invalid product or insufficient inventory"), 400
        
        # This will automatically add to the order_items association table
        new_order.products.append(product)
        product.stock -= item_data["quantity"]
        session.add(product)

    session.commit()
    return jsonify(message="Checkout successful"), 200

if __name__ == "__main__":
    with app.app_context():
        # This will create tables if they don't exist
        init_db() 
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)