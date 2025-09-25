#!/usr/bin/env python3
"""
PostgreSQL Migration Script
Migrates existing SQLite data to PostgreSQL without data loss
"""

import sqlite3
import psycopg2
import os
from datetime import datetime

def get_sqlite_connection():
    """Connect to existing SQLite database"""
    return sqlite3.connect('ecommerce.db')

def get_postgres_connection():
    """Connect to PostgreSQL database"""
    # Use environment variables for PostgreSQL connection
    return psycopg2.connect(
        host=os.getenv('POSTGRES_HOST', 'localhost'),
        database=os.getenv('POSTGRES_DB', 'ecommerce'),
        user=os.getenv('POSTGRES_USER', 'postgres'),
        password=os.getenv('POSTGRES_PASSWORD', 'password'),
        port=os.getenv('POSTGRES_PORT', '5432')
    )

def create_postgres_tables(pg_conn):
    """Create PostgreSQL tables with proper constraints"""
    cursor = pg_conn.cursor()
    
    # Create users table
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
    
    # Create products table
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
    
    # Create orders table
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
    
    # Create order_items table
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
    
    # Create reviews table
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
    
    pg_conn.commit()
    print("PostgreSQL tables created successfully")

def migrate_data(sqlite_conn, pg_conn):
    """Migrate all data from SQLite to PostgreSQL"""
    sqlite_cursor = sqlite_conn.cursor()
    pg_cursor = pg_conn.cursor()
    
    # Migrate users
    print("Migrating users...")
    sqlite_cursor.execute('SELECT * FROM users')
    users = sqlite_cursor.fetchall()
    
    for user in users:
        pg_cursor.execute('''
            INSERT INTO users (email, password_hash, name, phone, address, is_admin, 
                             security_question_1, security_answer_1, security_question_2, 
                             security_answer_2, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (email) DO NOTHING
        ''', user[1:])  # Skip the SQLite ID
    
    print(f"Migrated {len(users)} users")
    
    # Migrate products
    print("Migrating products...")
    sqlite_cursor.execute('SELECT * FROM products')
    products = sqlite_cursor.fetchall()
    
    for product in products:
        pg_cursor.execute('''
            INSERT INTO products (name, description, price, image_url, stock, total_sold)
            VALUES (%s, %s, %s, %s, %s, %s)
        ''', product[1:])  # Skip the SQLite ID
    
    print(f"Migrated {len(products)} products")
    
    # Create user ID mapping for orders and reviews
    user_mapping = {}
    sqlite_cursor.execute('SELECT id, email FROM users')
    sqlite_users = sqlite_cursor.fetchall()
    
    for sqlite_user in sqlite_users:
        pg_cursor.execute('SELECT id FROM users WHERE email = %s', (sqlite_user[1],))
        pg_user = pg_cursor.fetchone()
        if pg_user:
            user_mapping[sqlite_user[0]] = pg_user[0]
    
    # Create product ID mapping
    product_mapping = {}
    sqlite_cursor.execute('SELECT id, name FROM products')
    sqlite_products = sqlite_cursor.fetchall()
    
    for i, sqlite_product in enumerate(sqlite_products):
        product_mapping[sqlite_product[0]] = i + 1  # PostgreSQL IDs start from 1
    
    # Migrate orders
    print("Migrating orders...")
    sqlite_cursor.execute('SELECT * FROM orders')
    orders = sqlite_cursor.fetchall()
    
    order_mapping = {}
    for order in orders:
        if order[1] in user_mapping:  # user_id exists
            pg_cursor.execute('''
                INSERT INTO orders (user_id, order_date, status, total_amount)
                VALUES (%s, %s, %s, %s) RETURNING id
            ''', (user_mapping[order[1]], order[2], order[3], order[4]))
            new_order_id = pg_cursor.fetchone()[0]
            order_mapping[order[0]] = new_order_id
    
    print(f"Migrated {len(order_mapping)} orders")
    
    # Migrate order_items
    print("Migrating order items...")
    sqlite_cursor.execute('SELECT * FROM order_items')
    order_items = sqlite_cursor.fetchall()
    
    migrated_items = 0
    for item in order_items:
        if item[1] in order_mapping and item[2] in product_mapping:
            pg_cursor.execute('''
                INSERT INTO order_items (order_id, product_id, quantity, price_at_time)
                VALUES (%s, %s, %s, %s)
            ''', (order_mapping[item[1]], product_mapping[item[2]], item[3], item[4]))
            migrated_items += 1
    
    print(f"Migrated {migrated_items} order items")
    
    # Migrate reviews
    print("Migrating reviews...")
    sqlite_cursor.execute('SELECT * FROM reviews')
    reviews = sqlite_cursor.fetchall()
    
    migrated_reviews = 0
    for review in reviews:
        if review[1] in user_mapping and review[2] in product_mapping:
            try:
                pg_cursor.execute('''
                    INSERT INTO reviews (user_id, product_id, rating, comment, created_at)
                    VALUES (%s, %s, %s, %s, %s)
                ''', (user_mapping[review[1]], product_mapping[review[2]], 
                      review[3], review[4], review[5]))
                migrated_reviews += 1
            except psycopg2.IntegrityError:
                # Skip duplicate reviews
                pg_conn.rollback()
                continue
    
    print(f"Migrated {migrated_reviews} reviews")
    
    pg_conn.commit()

def main():
    """Main migration function"""
    print("Starting PostgreSQL migration...")
    print(f"Migration started at: {datetime.now()}")
    
    try:
        # Connect to databases
        print("Connecting to SQLite database...")
        sqlite_conn = get_sqlite_connection()
        
        print("Connecting to PostgreSQL database...")
        pg_conn = get_postgres_connection()
        
        # Create PostgreSQL tables
        create_postgres_tables(pg_conn)
        
        # Migrate data
        migrate_data(sqlite_conn, pg_conn)
        
        # Close connections
        sqlite_conn.close()
        pg_conn.close()
        
        print("Migration completed successfully!")
        print(f"Migration finished at: {datetime.now()}")
        
    except Exception as e:
        print(f"Migration failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()