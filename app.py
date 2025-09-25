# app.py
import os
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from functools import wraps
import bcrypt
from models import get_db, init_db, User, Product, Review, Order, OrderItem
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# --- Flask & SQLAlchemy Setup ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
REACT_BUILD_DIR = os.path.join(BASE_DIR, '..', 'frontend', 'dist')

app = Flask(__name__, static_folder=REACT_BUILD_DIR)
CORS(app, origins=[
    "http://localhost:3000", "http://localhost:5173", 
    "http://127.0.0.1:3000", "http://127.0.0.1:5173", 
    "https://sportzone-ecommerce.netlify.app", 
    "https://sportzone-ecommerce.vercel.app", 
    "https://sportzone-t1e0.onrender.com"
], methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
allow_headers=["Content-Type", "Authorization"])

app.config["JWT_SECRET_KEY"] = os.environ.get('JWT_SECRET_KEY', 'dev-secret-key-change-in-production')
jwt = JWTManager(app)

engine = create_engine('sqlite:///ecommerce.db')
Session = sessionmaker(bind=engine)

def get_session():
    return Session()

# Admin authentication decorator
def admin_required(f):
    @wraps(f)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        user_id = get_jwt_identity()
        session = get_session()
        try:
            user = session.query(User).filter_by(id=user_id).first()
            if not user or not user.is_admin:
                return jsonify(error="Admin access required"), 403
            return f(*args, **kwargs)
        finally:
            session.close()
    return decorated_function

# --- AUTH ---
@app.post("/api/auth/register")
def register():
    session = get_session()
    try:
        data = request.get_json()
        required_fields = ["email", "password", "name", "security_question_1", "security_answer_1", "security_question_2", "security_answer_2"]
        
        for field in required_fields:
            if not data.get(field):
                return jsonify(error=f"{field.replace('_', ' ').title()} is required"), 400
        
        existing_user = session.query(User).filter_by(email=data["email"]).first()
        if existing_user:
            return jsonify(error="User already exists"), 409
            
        password_hash = bcrypt.hashpw(data["password"].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        answer1_hash = bcrypt.hashpw(data["security_answer_1"].lower().encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        answer2_hash = bcrypt.hashpw(data["security_answer_2"].lower().encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        new_user = User(
            email=data["email"],
            password_hash=password_hash,
            name=data["name"],
            phone=data.get("phone"),
            address=data.get("address"),
            security_question_1=data["security_question_1"],
            security_answer_1=answer1_hash,
            security_question_2=data["security_question_2"],
            security_answer_2=answer2_hash
        )
        session.add(new_user)
        session.commit()
        
        access_token = create_access_token(identity=new_user.id)
        return jsonify(message="User created successfully", access_token=access_token, user={"id": new_user.id, "name": new_user.name, "email": new_user.email}), 201
    except Exception as e:
        session.rollback()
        print(f"Registration error: {e}")
        return jsonify(error="Registration failed"), 500
    finally:
        session.close()

@app.post("/api/auth/login")
def login():
    session = get_session()
    try:
        data = request.get_json()
        email, password = data.get("email"), data.get("password")
        
        user = session.query(User).filter_by(email=email).first()
        if not user or not bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            return jsonify(error="Invalid email or password"), 401
        
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token, user={"id": user.id, "name": user.name, "email": user.email, "is_admin": user.is_admin}), 200
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify(error="Login failed"), 500
    finally:
        session.close()

@app.post("/api/auth/admin-login")
def admin_login():
    session = get_session()
    try:
        data = request.get_json()
        email, password = data.get("email"), data.get("password")
        
        user = session.query(User).filter_by(email=email, is_admin=1).first()
        if not user or not bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            return jsonify(error="Invalid admin credentials"), 401
        
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token, user={"id": user.id, "name": user.name, "email": user.email, "is_admin": user.is_admin}), 200
    except Exception as e:
        print(f"Admin login error: {e}")
        return jsonify(error="Admin login failed"), 500
    finally:
        session.close()

@app.post("/api/auth/forgot-password")
def forgot_password():
    session = get_session()
    try:
        data = request.get_json()
        email = data.get("email")
        
        user = session.query(User).filter_by(email=email).first()
        if not user:
            return jsonify(error="User not found"), 404
        
        return jsonify({
            "security_questions": [
                user.security_question_1,
                user.security_question_2
            ]
        }), 200
    finally:
        session.close()

@app.post("/api/auth/verify-security")
def verify_security():
    session = get_session()
    try:
        data = request.get_json()
        email = data.get("email")
        answers = data.get("answers")
        
        user = session.query(User).filter_by(email=email).first()
        if not user:
            return jsonify(error="User not found"), 404
        
        if not (bcrypt.checkpw(answers[0].lower().encode('utf-8'), user.security_answer_1.encode('utf-8')) and
                bcrypt.checkpw(answers[1].lower().encode('utf-8'), user.security_answer_2.encode('utf-8'))):
            return jsonify(error="Security answers incorrect"), 401
        
        reset_token = create_access_token(identity=user.id)
        return jsonify(reset_token=reset_token), 200
    finally:
        session.close()

@app.post("/api/auth/reset-password")
@jwt_required()
def reset_password():
    session = get_session()
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        new_password = data.get("new_password")
        
        user = session.query(User).filter_by(id=user_id).first()
        if not user:
            return jsonify(error="User not found"), 404
        
        user.password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        session.commit()
        
        return jsonify(message="Password reset successfully"), 200
    except Exception as e:
        session.rollback()
        print(f"Password reset error: {e}")
        return jsonify(error="Password reset failed"), 500
    finally:
        session.close()

@app.post("/api/auth/change-password")
@jwt_required()
def change_password():
    session = get_session()
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
    finally:
        session.close()

@app.get("/api/user/profile")
@jwt_required()
def get_profile():
    session = get_session()
    try:
        user_id = get_jwt_identity()
        user = session.query(User).filter_by(id=user_id).first()
        if not user:
            return jsonify(error="User not found"), 404
        
        return jsonify({
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "phone": user.phone,
            "address": user.address
        }), 200
    finally:
        session.close()

@app.put("/api/user/profile")
@jwt_required()
def update_profile():
    session = get_session()
    try:
        user_id = get_jwt_identity()
        user = session.query(User).filter_by(id=user_id).first()
        if not user:
            return jsonify(error="User not found"), 404
        
        data = request.get_json()
        if "name" in data:
            user.name = data["name"]
        if "phone" in data:
            user.phone = data["phone"]
        if "address" in data:
            user.address = data["address"]
        
        session.commit()
        return jsonify(message="Profile updated successfully"), 200
    except Exception as e:
        session.rollback()
        print(f"Profile update error: {e}")
        return jsonify(error="Profile update failed"), 500
    finally:
        session.close()

# --- PRODUCTS ---
@app.get("/api/products")
def get_products():
    session = get_session()
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
        return jsonify([]), 200
    finally:
        session.close()

@app.get("/api/products/<int:pid>")
def get_product(pid):
    session = get_session()
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
    finally:
        session.close()

@app.post("/api/products")
@admin_required
def add_product():
    session = get_session()
    try:
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
    except Exception as e:
        session.rollback()
        print(f"Add product error: {e}")
        return jsonify(error="Failed to add product"), 500
    finally:
        session.close()

@app.put("/api/products/<int:pid>")
@admin_required
def update_product(pid):
    session = get_session()
    try:
        product = session.query(Product).filter_by(id=pid).first()
        if not product:
            return jsonify(error="Product not found"), 404
        
        data = request.get_json()
        
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
        
        session.commit()
        return jsonify(product.to_dict())
        
    except Exception as e:
        session.rollback()
        print(f"Error updating product: {e}")
        return jsonify(error=str(e)), 500
    finally:
        session.close()

@app.delete("/api/products/<int:pid>")
@admin_required
def delete_product(pid):
    session = get_session()
    try:
        product = session.query(Product).filter_by(id=pid).first()
        if not product:
            return jsonify(error="Product not found"), 404
        
        session.delete(product)
        session.commit()
        return jsonify(message="Product deleted"), 200
    except Exception as e:
        session.rollback()
        print(f"Delete product error: {e}")
        return jsonify(error="Failed to delete product"), 500
    finally:
        session.close()

# --- REVIEWS ---
@app.get("/api/products/<int:pid>/reviews")
def get_reviews(pid):
    session = get_session()
    try:
        reviews = session.query(Review).filter_by(product_id=pid).all()
        review_list = []
        for r in reviews:
            review_list.append({
                'id': r.id,
                'rating': r.rating,
                'comment': r.comment,
                'user_name': r.user.name if r.user else 'Anonymous',
                'created_at': r.created_at.isoformat() if r.created_at else None
            })
        return jsonify(review_list), 200
    except Exception as e:
        print(f"Error fetching reviews: {e}")
        return jsonify([]), 200
    finally:
        session.close()

@app.post("/api/products/<int:pid>/reviews")
@jwt_required()
def add_review(pid):
    session = get_session()
    try:
        user_id = get_jwt_identity()
        product = session.query(Product).filter_by(id=pid).first()
        if not product:
            return jsonify(error="Product not found"), 404
            
        data = request.get_json()
        rating, comment = data.get("rating"), data.get("comment")
        
        if not rating or not comment:
            return jsonify(error="Rating and comment are required"), 400
            
        if not isinstance(rating, int) or rating < 1 or rating > 5:
            return jsonify(error="Rating must be between 1 and 5"), 400
        
        new_review = Review(
            user_id=user_id, 
            product_id=pid, 
            rating=rating, 
            comment=comment
        )
        session.add(new_review)
        session.commit()
        
        user = session.query(User).filter_by(id=user_id).first()
        return jsonify({
            'id': new_review.id,
            'rating': new_review.rating,
            'comment': new_review.comment,
            'user_name': user.name,
            'created_at': new_review.created_at.isoformat() if new_review.created_at else None
        }), 201
        
    except Exception as e:
        session.rollback()
        print(f"Error adding review: {e}")
        return jsonify(error="Failed to add review"), 500
    finally:
        session.close()

# --- ORDERS ---
@app.post("/api/orders/checkout")
@jwt_required()
def checkout():
    session = get_session()
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        if not data or not data.get("items"):
            return jsonify(error="No items provided"), 400
        
        items = data.get("items")
        if not items:
            return jsonify(error="No items in cart"), 400

        total_amount = 0
        new_order = Order(user_id=user_id, status="completed")
        session.add(new_order)
        session.flush()  # Get order ID
        
        for item_data in items:
            if not item_data.get("productId") or not item_data.get("quantity"):
                session.rollback()
                return jsonify(error="Invalid item data"), 400
                
            product = session.query(Product).filter_by(id=item_data["productId"]).first()
            if not product:
                session.rollback()
                return jsonify(error=f"Product {item_data['productId']} not found"), 400
                
            if product.stock < item_data["quantity"]:
                session.rollback()
                return jsonify(error=f"Insufficient stock for {product.name}"), 400
            
            order_item = OrderItem(
                order_id=new_order.id,
                product_id=product.id,
                quantity=item_data["quantity"],
                price_at_time=product.price
            )
            session.add(order_item)
            
            product.stock -= item_data["quantity"]
            product.total_sold += item_data["quantity"]
            total_amount += product.price * item_data["quantity"]

        new_order.total_amount = total_amount
        session.commit()
        return jsonify(message="Checkout successful", order_id=new_order.id), 200
    except Exception as e:
        session.rollback()
        print(f"Checkout error: {e}")
        return jsonify(error="Checkout failed"), 500
    finally:
        session.close()

@app.get("/api/user/orders")
@jwt_required()
def get_user_orders():
    session = get_session()
    try:
        user_id = get_jwt_identity()
        orders = session.query(Order).filter_by(user_id=user_id).all()
        
        order_list = []
        for order in orders:
            items = []
            for item in order.order_items:
                items.append({
                    "product_name": item.product.name,
                    "quantity": item.quantity,
                    "price": item.price_at_time,
                    "image_url": item.product.image_url
                })
            
            order_list.append({
                "id": order.id,
                "order_date": order.order_date.isoformat(),
                "status": order.status,
                "total_amount": order.total_amount,
                "items": items
            })
        
        return jsonify(order_list), 200
    finally:
        session.close()

@app.get("/api/admin/bestsellers")
@admin_required
def get_bestsellers():
    session = get_session()
    try:
        products = session.query(Product).order_by(Product.total_sold.desc()).limit(10).all()
        bestsellers = []
        for p in products:
            bestsellers.append({
                "id": p.id,
                "name": p.name,
                "total_sold": p.total_sold,
                "price": p.price,
                "image_url": p.image_url
            })
        return jsonify(bestsellers), 200
    finally:
        session.close()

def initialize_app():
    """Initialize database and create admin user if needed"""
    with app.app_context():
        init_db()
        
        session = get_session()
        try:
            # Check if admin user exists, create if not
            admin_user = session.query(User).filter_by(email="admin@sportzone.com").first()
            if not admin_user:
                admin_user = User(
                    email="admin@sportzone.com",
                    password_hash=bcrypt.hashpw("Admin@123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
                    name="Admin User",
                    is_admin=1
                )
                session.add(admin_user)
                
                # Add sample products if none exist
                if session.query(Product).count() == 0:
                    products = [
                        Product(name="Professional Basketball", description="Official size basketball", price=3899, image_url="/images/products/basketball.jpg", stock=50),
                        Product(name="Smart Fitness Watch", description="Advanced fitness tracking", price=32499, image_url="/images/products/watch.jpg", stock=30),
                        Product(name="Yoga Mat Premium", description="Non-slip yoga mat", price=6499, image_url="/images/products/yoga.jpg", stock=100)
                    ]
                    session.add_all(products)
                
                session.commit()
                print("Database initialized with admin user and sample data")
        finally:
            session.close()

# Initialize on startup
initialize_app()

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)