from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import psycopg
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
        conn = psycopg.connect(database_url)
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
        
        # Create tables with proper PostgreSQL constraints
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

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)