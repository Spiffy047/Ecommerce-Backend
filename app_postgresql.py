from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import psycopg2
import psycopg2.extras
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
        conn = psycopg2.connect(
            host=os.getenv('POSTGRES_HOST', 'localhost'),
            database=os.getenv('POSTGRES_DB', 'ecommerce'),
            user=os.getenv('POSTGRES_USER', 'postgres'),
            password=os.getenv('POSTGRES_PASSWORD', 'password'),
            port=os.getenv('POSTGRES_PORT', '5432')
        )
        return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        return None

def get_user_id():
    """Get user ID from JWT token and convert to int"""
    try:
        identity = get_jwt_identity()
        return int(identity) if identity else None
    except (ValueError, TypeError):
        return None

def init_db():
    try:
        conn = get_db_connection()
        if not conn:
            raise Exception("Could not connect to PostgreSQL database")
        
        cursor = conn.cursor()
        
        # Check if tables exist
        cursor.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'users')")
        if cursor.fetchone()[0]:
            print("Database already exists - preserving existing data")
            conn.close()
            return
        
        # Create tables with proper constraints
        cursor.execute('''
            CREATE TABLE users (
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
            CREATE TABLE products (
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
            CREATE TABLE orders (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status VARCHAR(50) DEFAULT 'pending',
                total_amount DECIMAL(10,2) NOT NULL CHECK(total_amount >= 0),
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE order_items (
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
            CREATE TABLE reviews (
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
        
        # Create admin user only if not exists
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
        
        conn.commit()
        conn.close()
        print("PostgreSQL database initialized successfully")
        
    except Exception as e:
        print(f"Database initialization error: {e}")
        print(f"Traceback: {traceback.format_exc()}")
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
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Registration failed', 'details': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data or not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password required'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cursor.execute('SELECT * FROM users WHERE email = %s', (data['email'],))
        user = cursor.fetchone()
        conn.close()
        
        if user and bcrypt.checkpw(data['password'].encode('utf-8'), user['password_hash'].encode('utf-8')):
            access_token = create_access_token(identity=str(user['id']))
            return jsonify({
                'access_token': access_token,
                'user': {'id': user['id'], 'name': user['name'], 'email': user['email'], 'is_admin': user['is_admin']}
            }), 200
        
        return jsonify({'error': 'Invalid credentials'}), 401
        
    except Exception as e:
        print(f"Login error: {e}")
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Login failed', 'details': str(e)}), 500

@app.route('/api/auth/admin-login', methods=['POST'])
def admin_login():
    try:
        data = request.get_json()
        if not data or not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password required'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cursor.execute('SELECT * FROM users WHERE email = %s AND is_admin = 1', (data['email'],))
        user = cursor.fetchone()
        conn.close()
        
        if user and bcrypt.checkpw(data['password'].encode('utf-8'), user['password_hash'].encode('utf-8')):
            access_token = create_access_token(identity=str(user['id']))
            return jsonify({
                'access_token': access_token,
                'user': {'id': user['id'], 'name': user['name'], 'email': user['email'], 'is_admin': user['is_admin']}
            }), 200
        
        return jsonify({'error': 'Invalid admin credentials'}), 401
        
    except Exception as e:
        print(f"Admin login error: {e}")
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Admin login failed', 'details': str(e)}), 500

@app.route('/api/products', methods=['GET'])
def get_products():
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cursor.execute('SELECT * FROM products ORDER BY id')
        products = cursor.fetchall()
        conn.close()
        
        return jsonify([dict(p) for p in products])
        
    except Exception as e:
        print(f"Get products error: {e}")
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Failed to fetch products', 'details': str(e)}), 500

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
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Failed to add product', 'details': str(e)}), 500

# Add all other endpoints with PostgreSQL syntax...
# (Similar pattern for all other routes - replace sqlite3 with psycopg2)

@app.route('/api/admin/bestsellers', methods=['GET'])
@jwt_required()
def get_bestsellers():
    try:
        user_id = get_jwt_identity()
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cursor.execute('SELECT is_admin FROM users WHERE id = %s', (user_id,))
        user = cursor.fetchone()
        
        if not user or not user['is_admin']:
            conn.close()
            return jsonify({'error': 'Admin access required'}), 403
        
        cursor.execute('SELECT * FROM products ORDER BY total_sold DESC LIMIT 5')
        products = cursor.fetchall()
        conn.close()
        
        return jsonify([dict(p) for p in products])
        
    except Exception as e:
        print(f"Get bestsellers error: {e}")
        return jsonify({'error': 'Failed to fetch bestsellers', 'details': str(e)}), 500

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)