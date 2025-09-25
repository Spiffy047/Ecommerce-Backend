from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import pg8000
import bcrypt
from datetime import datetime, timedelta
import os
import traceback

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

CORS(app, resources={
    r"/api/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})
jwt = JWTManager(app)

def get_db_connection():
    try:
        database_url = os.getenv('DATABASE_URL', 'postgresql://ecommerce_sporty_user:mSbKLG3SqU1GvXoYWlipjUaJpoby5Ojz@dpg-d3anv03uibrs73b12tig-a.oregon-postgres.render.com/ecommerce_sporty')
        import urllib.parse as urlparse
        url = urlparse.urlparse(database_url)
        conn = pg8000.connect(
            host=url.hostname,
            port=url.port or 5432,
            user=url.username,
            password=url.password,
            database=url.path[1:],
            ssl_context=True
        )
        return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        return None

def get_user_id():
    try:
        identity = get_jwt_identity()
        return int(identity) if identity else None
    except (ValueError, TypeError):
        return None

def init_db():
    try:
        conn = get_db_connection()
        if not conn:
            print("Could not connect to PostgreSQL database")
            return
        
        cursor = conn.cursor()
        
        # Check if all required tables exist
        required_tables = ['users', 'products', 'orders', 'order_items', 'reviews']
        all_tables_exist = True
        
        try:
            for table in required_tables:
                cursor.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = %s)", (table,))
                if not cursor.fetchone()[0]:
                    all_tables_exist = False
                    break
        except:
            all_tables_exist = False
            
        if all_tables_exist:
            print("Database tables already exist - preserving existing data")
            conn.close()
            return
            
        print("Creating database tables...")
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                name VARCHAR(255) NOT NULL,
                phone VARCHAR(50),
                address TEXT,
                is_admin INTEGER DEFAULT 0,
                security_question_1 TEXT,
                security_answer_1 TEXT,
                security_question_2 TEXT,
                security_answer_2 TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS products (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                description TEXT,
                price DECIMAL(10,2) NOT NULL CHECK(price > 0),
                image_url TEXT,
                stock INTEGER DEFAULT 0 CHECK(stock >= 0),
                total_sold INTEGER DEFAULT 0 CHECK(total_sold >= 0)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS orders (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status VARCHAR(50) DEFAULT 'pending',
                total_amount DECIMAL(10,2) NOT NULL CHECK(total_amount >= 0),
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS order_items (
                id SERIAL PRIMARY KEY,
                order_id INTEGER NOT NULL,
                product_id INTEGER NOT NULL,
                quantity INTEGER NOT NULL CHECK(quantity > 0),
                price_at_time DECIMAL(10,2) NOT NULL CHECK(price_at_time > 0),
                FOREIGN KEY (order_id) REFERENCES orders (id),
                FOREIGN KEY (product_id) REFERENCES products (id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reviews (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                product_id INTEGER NOT NULL,
                rating INTEGER NOT NULL CHECK(rating >= 1 AND rating <= 5),
                comment TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (product_id) REFERENCES products (id),
                UNIQUE(user_id, product_id)
            )
        ''')
        
        # Create admin user if not exists
        cursor.execute('SELECT id FROM users WHERE email = %s', ('admin@sportzone.com',))
        if not cursor.fetchone():
            admin_password = bcrypt.hashpw('Admin@123'.encode('utf-8'), bcrypt.gensalt())
            cursor.execute('''
                INSERT INTO users (email, password_hash, name, is_admin, security_question_1, security_answer_1, security_question_2, security_answer_2)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ''', ('admin@sportzone.com', admin_password.decode('utf-8'), 'Admin User', 1, 
                  'What is your favorite color?', bcrypt.hashpw('blue'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
                  'What city were you born in?', bcrypt.hashpw('admin'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')))
            print('Admin user created')
        else:
            print('Admin user already exists')
        
        conn.commit()
        conn.close()
        print("PostgreSQL database initialization completed successfully")
        
    except Exception as e:
        print(f"Database initialization error: {e}")
        raise

@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        required_fields = ['email', 'password', 'name', 'security_question_1', 'security_answer_1', 'security_question_2', 'security_answer_2']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE email = %s', (data['email'],))
        if cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Email already exists'}), 400
        
        password_hash = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
        security_answer_1 = bcrypt.hashpw(data['security_answer_1'].encode('utf-8'), bcrypt.gensalt())
        security_answer_2 = bcrypt.hashpw(data['security_answer_2'].encode('utf-8'), bcrypt.gensalt())
        
        cursor.execute('''
            INSERT INTO users (email, password_hash, name, phone, address, security_question_1, security_answer_1, security_question_2, security_answer_2)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id
        ''', (data['email'], password_hash.decode('utf-8'), data['name'], 
              data.get('phone', ''), data.get('address', ''),
              data['security_question_1'], security_answer_1.decode('utf-8'),
              data['security_question_2'], security_answer_2.decode('utf-8')))
        
        user_id = cursor.fetchone()[0]
        conn.commit()
        conn.close()
        
        access_token = create_access_token(identity=str(user_id))
        return jsonify({'access_token': access_token, 'user': {'id': user_id, 'name': data['name'], 'email': data['email']}}), 201
        
    except Exception as e:
        print(f"Register error: {e}")
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data or not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password required'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = %s', (data['email'],))
        user = cursor.fetchone()
        conn.close()
        
        if user and bcrypt.checkpw(data['password'].encode('utf-8'), user[2].encode('utf-8')):
            access_token = create_access_token(identity=str(user[0]))
            return jsonify({
                'access_token': access_token,
                'user': {'id': user[0], 'name': user[3], 'email': user[1], 'is_admin': user[6]}
            }), 200
        
        return jsonify({'error': 'Invalid credentials'}), 401
        
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'error': 'Login failed'}), 500

@app.route('/api/auth/admin-login', methods=['POST'])
def admin_login():
    try:
        data = request.get_json()
        if not data or not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password required'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = %s AND is_admin = 1', (data['email'],))
        user = cursor.fetchone()
        conn.close()
        
        if user and bcrypt.checkpw(data['password'].encode('utf-8'), user[2].encode('utf-8')):
            access_token = create_access_token(identity=str(user[0]))
            return jsonify({
                'access_token': access_token,
                'user': {'id': user[0], 'name': user[3], 'email': user[1], 'is_admin': user[6]}
            }), 200
        
        return jsonify({'error': 'Invalid admin credentials'}), 401
        
    except Exception as e:
        print(f"Admin login error: {e}")
        return jsonify({'error': 'Admin login failed'}), 500

@app.route('/api/products', methods=['GET'])
def get_products():
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM products ORDER BY id')
        products = cursor.fetchall()
        conn.close()
        
        return jsonify([{
            'id': p[0], 'name': p[1], 'description': p[2], 'price': float(p[3]), 
            'image_url': p[4], 'stock': p[5], 'total_sold': p[6]
        } for p in products])
        
    except Exception as e:
        print(f"Get products error: {e}")
        return jsonify({'error': 'Failed to fetch products'}), 500

@app.route('/api/products', methods=['POST'])
@jwt_required()
def add_product():
    try:
        user_id = get_user_id()
        if not user_id:
            return jsonify({'error': 'Invalid token'}), 401
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        required_fields = ['name', 'description', 'price', 'image_url', 'stock']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        cursor.execute('SELECT is_admin FROM users WHERE id = %s', (user_id,))
        user = cursor.fetchone()
        
        if not user or not user[0]:
            conn.close()
            return jsonify({'error': 'Admin access required'}), 403
        
        cursor.execute('''
            INSERT INTO products (name, description, price, image_url, stock)
            VALUES (%s, %s, %s, %s, %s)
        ''', (data['name'], data['description'], data['price'], data['image_url'], data['stock']))
        
        conn.commit()
        conn.close()
        return jsonify({'message': 'Product added successfully'}), 201
        
    except Exception as e:
        print(f"Add product error: {e}")
        return jsonify({'error': 'Failed to add product'}), 500

@app.route('/api/products/<int:product_id>', methods=['GET'])
def get_product(product_id):
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM products WHERE id = %s', (product_id,))
        product = cursor.fetchone()
        conn.close()
        
        if not product:
            return jsonify({'error': 'Product not found'}), 404
        
        return jsonify({
            'id': product[0], 'name': product[1], 'description': product[2], 'price': float(product[3]),
            'image_url': product[4], 'stock': product[5], 'total_sold': product[6]
        })
        
    except Exception as e:
        print(f"Get product error: {e}")
        return jsonify({'error': 'Failed to fetch product'}), 500

@app.route('/api/products/<int:product_id>', methods=['PUT'])
@jwt_required()
def update_product(product_id):
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        required_fields = ['name', 'description', 'price', 'image_url', 'stock']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        cursor.execute('SELECT is_admin FROM users WHERE id = %s', (user_id,))
        user = cursor.fetchone()
        
        if not user or not user[0]:
            conn.close()
            return jsonify({'error': 'Admin access required'}), 403
        
        cursor.execute('''
            UPDATE products SET name = %s, description = %s, price = %s, image_url = %s, stock = %s
            WHERE id = %s
        ''', (data['name'], data['description'], data['price'], data['image_url'], data['stock'], product_id))
        
        conn.commit()
        conn.close()
        return jsonify({'message': 'Product updated successfully'}), 200
        
    except Exception as e:
        print(f"Update product error: {e}")
        return jsonify({'error': 'Failed to update product'}), 500

@app.route('/api/products/<int:product_id>', methods=['DELETE'])
@jwt_required()
def delete_product(product_id):
    try:
        user_id = get_user_id()
        if not user_id:
            return jsonify({'error': 'Invalid token'}), 401
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        cursor.execute('SELECT is_admin FROM users WHERE id = %s', (user_id,))
        user = cursor.fetchone()
        
        if not user or not user[0]:
            conn.close()
            return jsonify({'error': 'Admin access required'}), 403
        
        cursor.execute('DELETE FROM reviews WHERE product_id = %s', (product_id,))
        cursor.execute('DELETE FROM products WHERE id = %s', (product_id,))
        
        conn.commit()
        conn.close()
        return jsonify({'message': 'Product deleted successfully'}), 200
        
    except Exception as e:
        print(f"Delete product error: {e}")
        return jsonify({'error': 'Failed to delete product'}), 500

@app.route('/api/products/<int:product_id>/reviews', methods=['GET'])
def get_reviews(product_id):
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        cursor.execute('''
            SELECT r.*, u.name FROM reviews r
            JOIN users u ON r.user_id = u.id
            WHERE r.product_id = %s
            ORDER BY r.created_at DESC
        ''', (product_id,))
        reviews = cursor.fetchall()
        conn.close()
        
        return jsonify([{
            'id': r[0], 'user_id': r[1], 'product_id': r[2], 'rating': r[3],
            'comment': r[4], 'created_at': str(r[5]), 'user_name': r[6]
        } for r in reviews])
        
    except Exception as e:
        print(f"Get reviews error: {e}")
        return jsonify({'error': 'Failed to fetch reviews'}), 500

@app.route('/api/products/<int:product_id>/reviews', methods=['POST'])
@jwt_required()
def add_review(product_id):
    try:
        user_id = get_user_id()
        if not user_id:
            return jsonify({'error': 'Invalid token'}), 401
        data = request.get_json()
        
        if not data or 'rating' not in data or 'comment' not in data:
            return jsonify({'error': 'Rating and comment required'}), 400
        
        if not (1 <= data['rating'] <= 5):
            return jsonify({'error': 'Rating must be between 1 and 5'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM reviews WHERE user_id = %s AND product_id = %s', (user_id, product_id))
        if cursor.fetchone():
            conn.close()
            return jsonify({'error': 'You have already reviewed this product'}), 400
        
        cursor.execute('''
            INSERT INTO reviews (user_id, product_id, rating, comment)
            VALUES (%s, %s, %s, %s)
        ''', (user_id, product_id, data['rating'], data['comment']))
        
        conn.commit()
        conn.close()
        return jsonify({'message': 'Review added successfully'}), 201
        
    except Exception as e:
        print(f"Add review error: {e}")
        return jsonify({'error': 'Failed to add review'}), 500

@app.route('/api/orders/checkout', methods=['POST'])
@jwt_required()
def checkout():
    try:
        user_id = get_user_id()
        if not user_id:
            return jsonify({'error': 'Invalid token'}), 401
        data = request.get_json()
        
        if not data or not data.get('items'):
            return jsonify({'error': 'No items provided'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        
        total_amount = 0
        for item in data['items']:
            cursor.execute('SELECT price, stock FROM products WHERE id = %s', (item['productId'],))
            product = cursor.fetchone()
            if not product:
                conn.close()
                return jsonify({'error': f'Product {item["productId"]} not found'}), 404
            
            if product[1] < item['quantity']:
                conn.close()
                return jsonify({'error': f'Insufficient stock for product {item["productId"]}'}), 400
            
            total_amount += float(product[0]) * item['quantity']
        
        cursor.execute('''
            INSERT INTO orders (user_id, total_amount, status)
            VALUES (%s, %s, %s) RETURNING id
        ''', (user_id, total_amount, 'completed'))
        
        order_id = cursor.fetchone()[0]
        
        for item in data['items']:
            cursor.execute('SELECT price FROM products WHERE id = %s', (item['productId'],))
            product = cursor.fetchone()
            if product:
                cursor.execute('''
                    INSERT INTO order_items (order_id, product_id, quantity, price_at_time)
                    VALUES (%s, %s, %s, %s)
                ''', (order_id, item['productId'], item['quantity'], product[0]))
                
                cursor.execute('''
                    UPDATE products SET stock = stock - %s, total_sold = total_sold + %s
                    WHERE id = %s
                ''', (item['quantity'], item['quantity'], item['productId']))
        
        conn.commit()
        conn.close()
        return jsonify({'message': 'Order placed successfully', 'order_id': order_id}), 201
        
    except Exception as e:
        print(f"Checkout error: {e}")
        return jsonify({'error': 'Checkout failed'}), 500

@app.route('/api/user/profile', methods=['GET'])
@jwt_required()
def get_user_profile():
    try:
        user_id = get_jwt_identity()
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        cursor.execute('SELECT email, name, phone, address FROM users WHERE id = %s', (user_id,))
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'email': user[0],
            'name': user[1],
            'phone': user[2] or '',
            'address': user[3] or ''
        })
        
    except Exception as e:
        print(f"Get user profile error: {e}")
        return jsonify({'error': 'Failed to fetch profile'}), 500

@app.route('/api/user/profile', methods=['PUT'])
@jwt_required()
def update_user_profile():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE users SET name = %s, phone = %s, address = %s
            WHERE id = %s
        ''', (data.get('name'), data.get('phone'), data.get('address'), user_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Profile updated successfully'})
        
    except Exception as e:
        print(f"Update user profile error: {e}")
        return jsonify({'error': 'Failed to update profile'}), 500

@app.route('/api/user/orders', methods=['GET'])
@jwt_required()
def get_user_orders():
    try:
        user_id = get_jwt_identity()
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        cursor.execute('''
            SELECT o.id, o.order_date, o.status, o.total_amount
            FROM orders o
            WHERE o.user_id = %s
            ORDER BY o.order_date DESC
        ''', (user_id,))
        orders = cursor.fetchall()
        
        order_list = []
        for order in orders:
            cursor.execute('''
                SELECT oi.quantity, oi.price_at_time, p.name, p.image_url
                FROM order_items oi
                JOIN products p ON oi.product_id = p.id
                WHERE oi.order_id = %s
            ''', (order[0],))
            items = cursor.fetchall()
            
            order_list.append({
                'id': order[0],
                'order_date': str(order[1]),
                'status': order[2],
                'total_amount': float(order[3]),
                'items': [{
                    'quantity': item[0],
                    'price': float(item[1]),
                    'product_name': item[2],
                    'image_url': item[3]
                } for item in items]
            })
        
        conn.close()
        return jsonify(order_list)
        
    except Exception as e:
        print(f"Get user orders error: {e}")
        return jsonify({'error': 'Failed to fetch orders'}), 500

@app.route('/api/admin/bestsellers', methods=['GET'])
@jwt_required()
def get_bestsellers():
    try:
        user_id = get_jwt_identity()
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        cursor.execute('SELECT is_admin FROM users WHERE id = %s', (user_id,))
        user = cursor.fetchone()
        
        if not user or not user[0]:
            conn.close()
            return jsonify({'error': 'Admin access required'}), 403
        
        cursor.execute('SELECT * FROM products ORDER BY total_sold DESC LIMIT 5')
        products = cursor.fetchall()
        conn.close()
        
        return jsonify([{
            'id': p[0], 'name': p[1], 'description': p[2], 'price': float(p[3]),
            'image_url': p[4], 'stock': p[5], 'total_sold': p[6]
        } for p in products])
        
    except Exception as e:
        print(f"Get bestsellers error: {e}")
        return jsonify({'error': 'Failed to fetch bestsellers'}), 500

@app.route('/api/auth/forgot-password', methods=['POST'])
def forgot_password():
    try:
        data = request.get_json()
        if not data or not data.get('email'):
            return jsonify({'error': 'Email required'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        cursor.execute('SELECT security_question_1, security_question_2 FROM users WHERE email = %s', (data['email'],))
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return jsonify({'error': 'Email not found'}), 404
        
        return jsonify({
            'security_questions': [user[0], user[1]]
        }), 200
        
    except Exception as e:
        print(f"Forgot password error: {e}")
        return jsonify({'error': 'Failed to process request'}), 500

@app.route('/api/auth/verify-security', methods=['POST'])
def verify_security():
    try:
        data = request.get_json()
        if not data or not data.get('email') or not data.get('answers'):
            return jsonify({'error': 'Email and answers required'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        cursor.execute('SELECT id, security_answer_1, security_answer_2 FROM users WHERE email = %s', (data['email'],))
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if (bcrypt.checkpw(data['answers'][0].encode('utf-8'), user[1].encode('utf-8')) and
            bcrypt.checkpw(data['answers'][1].encode('utf-8'), user[2].encode('utf-8'))):
            reset_token = create_access_token(identity=str(user[0]), expires_delta=timedelta(minutes=15))
            return jsonify({'reset_token': reset_token}), 200
        
        return jsonify({'error': 'Security answers do not match'}), 401
        
    except Exception as e:
        print(f"Verify security error: {e}")
        return jsonify({'error': 'Failed to verify security answers'}), 500

@app.route('/api/auth/reset-password', methods=['POST'])
@jwt_required()
def reset_password():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        if not data or not data.get('new_password'):
            return jsonify({'error': 'New password required'}), 400
        
        password_hash = bcrypt.hashpw(data['new_password'].encode('utf-8'), bcrypt.gensalt())
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET password_hash = %s WHERE id = %s', (password_hash.decode('utf-8'), user_id))
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Password reset successfully'}), 200
        
    except Exception as e:
        print(f"Reset password error: {e}")
        return jsonify({'error': 'Failed to reset password'}), 500

@app.route('/api/auth/change-password', methods=['POST'])
@jwt_required()
def change_password():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        if not data or not data.get('currentPassword') or not data.get('newPassword'):
            return jsonify({'error': 'Current and new password required'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash FROM users WHERE id = %s', (user_id,))
        user = cursor.fetchone()
        
        if not user or not bcrypt.checkpw(data['currentPassword'].encode('utf-8'), user[0].encode('utf-8')):
            conn.close()
            return jsonify({'error': 'Current password is incorrect'}), 401
        
        new_password_hash = bcrypt.hashpw(data['newPassword'].encode('utf-8'), bcrypt.gensalt())
        cursor.execute('UPDATE users SET password_hash = %s WHERE id = %s', (new_password_hash.decode('utf-8'), user_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Password changed successfully'})
        
    except Exception as e:
        print(f"Change password error: {e}")
        return jsonify({'error': 'Failed to change password'}), 500

# Initialize database on startup
with app.app_context():
    try:
        init_db()
    except Exception as e:
        print(f"Database initialization failed: {e}")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)