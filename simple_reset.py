#!/usr/bin/env python3
"""
Simple database reset script
"""

import sqlite3
import os

def reset_database():
    """Reset the database with new schema"""
    db_path = 'ecommerce.db'
    
    # Remove existing database
    if os.path.exists(db_path):
        os.remove(db_path)
        print("Removed existing database")
    
    # Create new database with updated schema
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create users table with new fields
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
    
    # Create products table with total_sold
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
    
    # Create reviews table
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
    
    # Create orders table
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
    
    # Create order_items table
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
    
    # Insert admin user (password: admin123)
    cursor.execute('''
        INSERT INTO users (email, password_hash, name, is_admin, security_question_1, security_answer_1, security_question_2, security_answer_2)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        'admin@sportzone.com',
        '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj6hsxq5S/kS',  # admin123
        'Admin User',
        1,
        'What is your favorite sport?',
        '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj6hsxq5S/kS',  # football
        'What city were you born in?',
        '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj6hsxq5S/kS'   # nairobi
    ))
    
    # Insert sample user (password: user123)
    cursor.execute('''
        INSERT INTO users (email, password_hash, name, phone, address, security_question_1, security_answer_1, security_question_2, security_answer_2)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        'user@example.com',
        '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj6hsxq5S/kS',  # user123
        'John Doe',
        '+254700123456',
        '123 Sports Street, Nairobi, Kenya',
        'What was the name of your first pet?',
        '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj6hsxq5S/kS',  # buddy
        'What is your mother\'s maiden name?',
        '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj6hsxq5S/kS'   # smith
    ))
    
    # Insert sample products
    products = [
        ('Professional Basketball', 'Official size basketball for professional games', 3899.00, '/images/products/basketball.jpg', 50, 25),
        ('Smart Fitness Watch', 'Advanced fitness tracking with heart rate monitor', 32499.00, '/images/products/watch.jpg', 30, 15),
        ('Yoga Mat Premium', 'Non-slip yoga mat with carrying strap', 6499.00, '/images/products/yoga.jpg', 100, 40),
        ('Running Shoes', 'Lightweight running shoes with cushioned sole', 12999.00, '/images/products/shoes.jpg', 75, 30),
        ('Tennis Racket', 'Professional tennis racket with carbon fiber frame', 18999.00, '/images/products/racket.jpg', 25, 10)
    ]
    
    for product in products:
        cursor.execute('''
            INSERT INTO products (name, description, price, image_url, stock, total_sold)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', product)
    
    # Insert sample reviews
    reviews = [
        (2, 1, 5, 'Excellent quality basketball! Perfect for outdoor games.'),
        (2, 2, 4, 'Great fitness tracker with accurate heart rate monitoring.'),
        (2, 3, 5, 'Very comfortable and non-slip. Perfect for my daily yoga practice.')
    ]
    
    for review in reviews:
        cursor.execute('''
            INSERT INTO reviews (user_id, product_id, rating, comment)
            VALUES (?, ?, ?, ?)
        ''', review)
    
    conn.commit()
    conn.close()
    
    print("✅ Database reset successfully!")
    print("\n📋 Sample Data Created:")
    print("👤 Admin User:")
    print("   Email: admin@sportzone.com")
    print("   Password: admin123")
    print("\n👤 Sample User:")
    print("   Email: user@example.com")
    print("   Password: user123")
    print(f"\n📦 Products: {len(products)} items created")
    print(f"⭐ Reviews: {len(reviews)} reviews created")

if __name__ == "__main__":
    reset_database()