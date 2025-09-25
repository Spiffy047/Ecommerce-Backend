#!/usr/bin/env python3
import sqlite3

def create_database():
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT,
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
    
    # Products table
    cursor.execute('''
        CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            price REAL NOT NULL,
            image_url TEXT,
            stock INTEGER DEFAULT 0,
            total_sold INTEGER DEFAULT 0
        )
    ''')
    
    # Reviews table
    cursor.execute('''
        CREATE TABLE reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rating INTEGER,
            comment TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            product_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (product_id) REFERENCES products (id)
        )
    ''')
    
    # Orders table
    cursor.execute('''
        CREATE TABLE orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT,
            total_amount REAL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Order items table
    cursor.execute('''
        CREATE TABLE order_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER,
            product_id INTEGER,
            quantity INTEGER,
            price_at_time REAL,
            FOREIGN KEY (order_id) REFERENCES orders (id),
            FOREIGN KEY (product_id) REFERENCES products (id)
        )
    ''')
    
    # Create fresh admin user with pre-computed hash for Admin@123
    cursor.execute('''
        INSERT INTO users (email, password_hash, name, is_admin)
        VALUES (?, ?, ?, ?)
    ''', ('admin@sportzone.com', '$2b$12$8Ny02eSVGIoMQqnFx.tHKOCiAH7YGtqOi/o9lQfHh8SkVMGaa8.Gy', 'Admin User', 1))
    
    # Create sample user with pre-computed hash for user123
    cursor.execute('''
        INSERT INTO users (email, password_hash, name)
        VALUES (?, ?, ?)
    ''', ('user@example.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj6hsxq5S/kS', 'John Doe'))
    
    # Create sample products
    products = [
        ('Professional Basketball', 'Official size basketball', 3899, '/images/products/basketball.jpg', 50, 0),
        ('Smart Fitness Watch', 'Advanced fitness tracking', 32499, '/images/products/watch.jpg', 30, 0),
        ('Yoga Mat Premium', 'Non-slip yoga mat', 6499, '/images/products/yoga.jpg', 100, 0)
    ]
    
    for product in products:
        cursor.execute('''
            INSERT INTO products (name, description, price, image_url, stock, total_sold)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', product)
    
    conn.commit()
    conn.close()
    print("✅ Fresh database created with admin@sportzone.com / Admin@123")

if __name__ == "__main__":
    create_database()