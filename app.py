import os
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import bcrypt
from models import get_db, init_db, User, Product, Review, Order, order_items_table
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import and_

# --- Flask & SQLAlchemy Setup ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
# This line correctly points to the `dist` folder inside your `frontend` directory
REACT_BUILD_DIR = os.path.join(BASE_DIR, '..', 'frontend', 'dist')

app = Flask(__name__, static_folder=REACT_BUILD_DIR)
CORS(app) 
app.config["JWT_SECRET_KEY"] = "dev-secret"
jwt = JWTManager(app)

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
        return jsonify(error="Email/password required"), 400
    
    existing_user = session.query(User).filter_by(email=email).first()
    if existing_user:
        return jsonify(error="Email already in use"), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    new_user = User(email=email, password_hash=hashed_password, name=name)
    session.add(new_user)
    session.commit()
    token = create_access_token(identity=new_user.id)
    return jsonify(token=token, user=new_user.to_dict()), 201

@app.post("/api/auth/login")
def login():
    data = request.get_json()
    email, password = data.get("email"), data.get("password")
    user = session.query(User).filter_by(email=email).first()
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
        return jsonify(error="Invalid credentials"), 400
    
    token = create_access_token(identity=user.id)
    return jsonify(token=token, user=user.to_dict())

# --- PRODUCTS (Full CRUD) ---
@app.get("/api/products")
def get_products():
    products = session.query(Product).all()
    return jsonify([p.to_dict() for p in products])

@app.get("/api/products/<int:pid>")
def get_product(pid):
    product = session.query(Product).filter_by(id=pid).first()
    if not product:
        return jsonify(error="Product not found"), 404
    return jsonify(product.to_dict())

@app.post("/api/products")
def add_product():
    data = request.get_json()
    try:
        new_product = Product(
            name=data["name"],
            description=data.get("description"),
            price=data["price"],
            image_url=data.get("image_url"),
            stock=data.get("stock")
        )
        session.add(new_product)
        session.commit()
        return jsonify(new_product.to_dict()), 201
    except KeyError:
        return jsonify(error="Missing required fields"), 400

@app.patch("/api/products/<int:pid>")
def update_product(pid):
    product = session.query(Product).filter_by(id=pid).first()
    if not product:
        return jsonify(error="Product not found"), 404
    
    data = request.get_json()
    for key, value in data.items():
        setattr(product, key, value)
    
    session.commit()
    return jsonify(product.to_dict())

@app.delete("/api/products/<int:pid>")
def delete_product(pid):
    product = session.query(Product).filter_by(id=pid).first()
    if not product:
        return jsonify(error="Product not found"), 404
    
    session.delete(product)
    session.commit()
    return jsonify(message="Product deleted"), 204

# --- REVIEWS ---
@app.get("/api/products/<int:pid>/reviews")
def get_reviews(pid):
    reviews = session.query(Review).filter_by(product_id=pid).order_by(Review.created_at.desc()).all()
    return jsonify([r.to_dict() for r in reviews])

@app.post("/api/products/<int:pid>/reviews")
def add_review(pid):
    data = request.get_json()
    rating, comment = data.get("rating"), data.get("comment")
    
    if not rating or not comment:
        return jsonify(error="Rating and comment are required"), 400
    
    # For demo purposes, using a default user_id of 1
    # In production, this would use JWT authentication
    new_review = Review(user_id=1, product_id=pid, rating=rating, comment=comment)
    session.add(new_review)
    session.commit()
    return jsonify(new_review.to_dict()), 201

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
    return jsonify(orderId=new_order.id), 201

if __name__ == "__main__":
    from models import init_db
    init_db()
    app.run(port=5000, debug=True)