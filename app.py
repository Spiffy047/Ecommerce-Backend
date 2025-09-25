from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import sqlite3
import bcrypt
from datetime import datetime, timedelta
import os

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

CORS(app)
jwt = JWTManager(app)

def init_db():
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT NOT NULL,
            phone TEXT,
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
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            price REAL NOT NULL,
            image_url TEXT,
            stock INTEGER DEFAULT 0,
            total_sold INTEGER DEFAULT 0
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'pending',
            total_amount REAL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS order_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER,
            product_id INTEGER,
            quantity INTEGER,
            price_at_time REAL,
            FOREIGN KEY (order_id) REFERENCES orders (id),
            FOREIGN KEY (product_id) REFERENCES products (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            product_id INTEGER,
            rating INTEGER,
            comment TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (product_id) REFERENCES products (id)
        )
    ''')
    
    # Check if admin exists
    cursor.execute('SELECT * FROM users WHERE email = ?', ('admin@sportzone.com',))
    if not cursor.fetchone():
        admin_password = bcrypt.hashpw('Admin@123'.encode('utf-8'), bcrypt.gensalt())
        cursor.execute('''
            INSERT INTO users (email, password_hash, name, is_admin, security_question_1, security_answer_1, security_question_2, security_answer_2)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', ('admin@sportzone.com', admin_password.decode('utf-8'), 'Admin User', 1, 
              'What is your favorite color?', bcrypt.hashpw('blue'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
              'What city were you born in?', bcrypt.hashpw('admin'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')))
    
    # Add sample products
    cursor.execute('SELECT COUNT(*) FROM products')
    if cursor.fetchone()[0] == 0:
        products = [
            ('Nike Air Max', 'Premium running shoes', 129.99, 'https://images.unsplash.com/photo-1542291026-7eec264c27ff?w=400', 50),
            ('Adidas Football', 'Professional football', 29.99, 'https://images.unsplash.com/photo-1486286701208-1d58e9338013?w=400', 30),
            ('Basketball Jersey', 'Team basketball jersey', 49.99, 'https://images.unsplash.com/photo-1571019613454-1cb2f99b2d8b?w=400', 25),
            ('Tennis Racket', 'Professional tennis racket', 89.99, 'https://images.unsplash.com/photo-1551698618-1dfe5d97d256?w=400', 15),
            ('Yoga Mat', 'Premium yoga mat', 39.99, 'https://images.unsplash.com/photo-1544367567-0f2fcb009e0b?w=400', 40)
        ]
        cursor.executemany('INSERT INTO products (name, description, price, image_url, stock) VALUES (?, ?, ?, ?, ?)', products)
    
    conn.commit()
    conn.close()

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users WHERE email = ?', (data['email'],))
    if cursor.fetchone():
        conn.close()
        return jsonify({'error': 'Email already exists'}), 400
    
    password_hash = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
    security_answer_1 = bcrypt.hashpw(data['securityAnswer1'].encode('utf-8'), bcrypt.gensalt())
    security_answer_2 = bcrypt.hashpw(data['securityAnswer2'].encode('utf-8'), bcrypt.gensalt())
    
    cursor.execute('''
        INSERT INTO users (email, password_hash, name, phone, address, security_question_1, security_answer_1, security_question_2, security_answer_2)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (data['email'], password_hash.decode('utf-8'), data['name'], 
          data.get('phone', ''), data.get('address', ''),
          data['securityQuestion1'], security_answer_1.decode('utf-8'),
          data['securityQuestion2'], security_answer_2.decode('utf-8')))
    
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    access_token = create_access_token(identity=user_id)
    return jsonify({'access_token': access_token, 'user': {'id': user_id, 'name': data['name'], 'email': data['email']}}), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users WHERE email = ?', (data['email'],))
    user = cursor.fetchone()
    conn.close()
    
    if user and bcrypt.checkpw(data['password'].encode('utf-8'), user[2].encode('utf-8')):
        access_token = create_access_token(identity=user[0])
        return jsonify({
            'access_token': access_token,
            'user': {'id': user[0], 'name': user[3], 'email': user[1], 'is_admin': user[6]}
        }), 200
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/auth/admin-login', methods=['POST'])
def admin_login():
    data = request.get_json()
    
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users WHERE email = ? AND is_admin = 1', (data['email'],))
    user = cursor.fetchone()
    conn.close()
    
    if user and bcrypt.checkpw(data['password'].encode('utf-8'), user[2].encode('utf-8')):
        access_token = create_access_token(identity=user[0])
        return jsonify({
            'access_token': access_token,
            'user': {'id': user[0], 'name': user[3], 'email': user[1], 'is_admin': user[6]}
        }), 200
    
    return jsonify({'error': 'Invalid admin credentials'}), 401

@app.route('/api/products', methods=['GET'])
def get_products():
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM products')
    products = cursor.fetchall()
    conn.close()
    
    return jsonify([{
        'id': p[0], 'name': p[1], 'description': p[2], 'price': p[3], 
        'image_url': p[4], 'stock': p[5], 'total_sold': p[6]
    } for p in products])

@app.route('/api/products', methods=['POST'])
@jwt_required()
def add_product():
    user_id = get_jwt_identity()
    
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.cursor()
    cursor.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    
    if not user or not user[0]:
        conn.close()
        return jsonify({'error': 'Admin access required'}), 403
    
    data = request.get_json()
    cursor.execute('''
        INSERT INTO products (name, description, price, image_url, stock)
        VALUES (?, ?, ?, ?, ?)
    ''', (data['name'], data['description'], data['price'], data['image_url'], data['stock']))
    
    conn.commit()
    conn.close()
    return jsonify({'message': 'Product added successfully'}), 201

@app.route('/api/products/<int:product_id>/reviews', methods=['GET'])
def get_reviews(product_id):
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT r.*, u.name FROM reviews r
        JOIN users u ON r.user_id = u.id
        WHERE r.product_id = ?
        ORDER BY r.created_at DESC
    ''', (product_id,))
    reviews = cursor.fetchall()
    conn.close()
    
    return jsonify([{
        'id': r[0], 'user_id': r[1], 'product_id': r[2], 'rating': r[3],
        'comment': r[4], 'created_at': r[5], 'user_name': r[6]
    } for r in reviews])

@app.route('/api/products/<int:product_id>/reviews', methods=['POST'])
@jwt_required()
def add_review(product_id):
    user_id = get_jwt_identity()
    data = request.get_json()
    
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO reviews (user_id, product_id, rating, comment)
        VALUES (?, ?, ?, ?)
    ''', (user_id, product_id, data['rating'], data['comment']))
    
    conn.commit()
    conn.close()
    return jsonify({'message': 'Review added successfully'}), 201

@app.route('/api/orders/checkout', methods=['POST'])
@jwt_required()
def checkout():
    user_id = get_jwt_identity()
    data = request.get_json()
    
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO orders (user_id, total_amount, status)
        VALUES (?, ?, ?)
    ''', (user_id, data['total'], 'completed'))
    
    order_id = cursor.lastrowid
    
    for item in data['items']:
        cursor.execute('''
            INSERT INTO order_items (order_id, product_id, quantity, price_at_time)
            VALUES (?, ?, ?, ?)
        ''', (order_id, item['id'], item['quantity'], item['price']))
        
        cursor.execute('''
            UPDATE products SET stock = stock - ?, total_sold = total_sold + ?
            WHERE id = ?
        ''', (item['quantity'], item['quantity'], item['id']))
    
    conn.commit()
    conn.close()
    return jsonify({'message': 'Order placed successfully', 'order_id': order_id}), 201

@app.route('/api/products/<int:product_id>', methods=['GET'])
def get_product(product_id):
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM products WHERE id = ?', (product_id,))
    product = cursor.fetchone()
    conn.close()
    
    if not product:
        return jsonify({'error': 'Product not found'}), 404
    
    return jsonify({
        'id': product[0], 'name': product[1], 'description': product[2], 'price': product[3],
        'image_url': product[4], 'stock': product[5], 'total_sold': product[6]
    })

@app.route('/api/products/<int:product_id>', methods=['PUT'])
@jwt_required()
def update_product(product_id):
    user_id = get_jwt_identity()
    
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.cursor()
    cursor.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    
    if not user or not user[0]:
        conn.close()
        return jsonify({'error': 'Admin access required'}), 403
    
    data = request.get_json()
    cursor.execute('''
        UPDATE products SET name = ?, description = ?, price = ?, image_url = ?, stock = ?
        WHERE id = ?
    ''', (data['name'], data['description'], data['price'], data['image_url'], data['stock'], product_id))
    
    conn.commit()
    conn.close()
    return jsonify({'message': 'Product updated successfully'}), 200

@app.route('/api/products/<int:product_id>', methods=['DELETE'])
@jwt_required()
def delete_product(product_id):
    user_id = get_jwt_identity()
    
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.cursor()
    cursor.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    
    if not user or not user[0]:
        conn.close()
        return jsonify({'error': 'Admin access required'}), 403
    
    cursor.execute('DELETE FROM products WHERE id = ?', (product_id,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Product deleted successfully'}), 200

@app.route('/api/admin/bestsellers', methods=['GET'])
@jwt_required()
def get_bestsellers():
    user_id = get_jwt_identity()
    
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.cursor()
    cursor.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    
    if not user or not user[0]:
        conn.close()
        return jsonify({'error': 'Admin access required'}), 403
    
    cursor.execute('SELECT * FROM products ORDER BY total_sold DESC LIMIT 5')
    products = cursor.fetchall()
    conn.close()
    
    return jsonify([{
        'id': p[0], 'name': p[1], 'description': p[2], 'price': p[3],
        'image_url': p[4], 'stock': p[5], 'total_sold': p[6]
    } for p in products])

@app.route('/api/auth/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.cursor()
    cursor.execute('SELECT security_question_1, security_question_2 FROM users WHERE email = ?', (data['email'],))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return jsonify({'error': 'Email not found'}), 404
    
    return jsonify({
        'security_questions': [user[0], user[1]]
    }), 200

@app.route('/api/auth/verify-security', methods=['POST'])
def verify_security():
    data = request.get_json()
    
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, security_answer_1, security_answer_2 FROM users WHERE email = ?', (data['email'],))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if (bcrypt.checkpw(data['answers'][0].encode('utf-8'), user[1].encode('utf-8')) and
        bcrypt.checkpw(data['answers'][1].encode('utf-8'), user[2].encode('utf-8'))):
        reset_token = create_access_token(identity=user[0], expires_delta=timedelta(minutes=15))
        return jsonify({'reset_token': reset_token}), 200
    
    return jsonify({'error': 'Security answers do not match'}), 401

@app.route('/api/auth/reset-password', methods=['POST'])
@jwt_required()
def reset_password():
    user_id = get_jwt_identity()
    data = request.get_json()
    
    password_hash = bcrypt.hashpw(data['new_password'].encode('utf-8'), bcrypt.gensalt())
    
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET password_hash = ? WHERE id = ?', (password_hash.decode('utf-8'), user_id))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Password reset successfully'}), 200

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)