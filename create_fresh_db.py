#!/usr/bin/env python3
import sqlite3
import bcrypt
import os

def create_fresh_database():
    # Delete existing database if it exists
    if os.path.exists('ecommerce.db'):
        os.remove('ecommerce.db')
        print("Removed existing database")
    
    # Create fresh database
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.cursor()
    
    # Create users table
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
    
    # Create products table
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
    
    # Create orders table
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
    
    # Create order_items table
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
    
    # Create reviews table
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
    
    # Create admin user with correct password
    admin_password = bcrypt.hashpw('Admin@123'.encode('utf-8'), bcrypt.gensalt())
    cursor.execute('''
        INSERT INTO users (email, password_hash, name, is_admin, security_question_1, security_answer_1, security_question_2, security_answer_2)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', ('admin@sportzone.com', admin_password.decode('utf-8'), 'Admin User', 1, 
          'What is your favorite color?', bcrypt.hashpw('blue'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
          'What city were you born in?', bcrypt.hashpw('admin'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')))
    
    # Add sample products
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
    
    print("Fresh database created successfully")
    print("Admin credentials: admin@sportzone.com / Admin@123")

if __name__ == '__main__':
    create_fresh_database()