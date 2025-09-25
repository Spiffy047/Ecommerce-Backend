import sqlite3
import psycopg2
import psycopg2.extras

DATABASE_URL = "postgresql://ecommerce_sporty_user:mSbKLG3SqU1GvXoYWlipjUaJpoby5Ojz@dpg-d3anv03uibrs73b12tig-a.oregon-postgres.render.com/ecommerce_sporty"

def migrate():
    # Connect to SQLite
    sqlite_conn = sqlite3.connect('ecommerce.db')
    sqlite_cursor = sqlite_conn.cursor()
    
    # Connect to PostgreSQL
    pg_conn = psycopg2.connect(DATABASE_URL)
    pg_cursor = pg_conn.cursor()
    
    # Create products table
    pg_cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            description TEXT,
            price DECIMAL(10,2) NOT NULL,
            image_url TEXT,
            stock INTEGER DEFAULT 0,
            total_sold INTEGER DEFAULT 0
        )
    ''')
    
    # Migrate products
    sqlite_cursor.execute('SELECT name, description, price, image_url, stock, total_sold FROM products')
    products = sqlite_cursor.fetchall()
    
    for product in products:
        pg_cursor.execute('''
            INSERT INTO products (name, description, price, image_url, stock, total_sold)
            VALUES (%s, %s, %s, %s, %s, %s)
        ''', product)
    
    pg_conn.commit()
    print(f"Migrated {len(products)} products to PostgreSQL")
    
    sqlite_conn.close()
    pg_conn.close()

if __name__ == '__main__':
    migrate()