#!/usr/bin/env python3
"""
Complete fix and setup script for the ecommerce backend
"""

import os
import sys
from models import init_db, Product, User, Review
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import bcrypt

def setup_database():
    """Initialize database and add sample data"""
    print("Setting up database...")
    
    # Initialize database
    init_db()
    
    # Create session
    engine = create_engine('sqlite:///ecommerce.db')
    Session = sessionmaker(bind=engine)
    session = Session()
    
    # Clear existing data
    session.query(Review).delete()
    session.query(Product).delete()
    session.query(User).delete()
    session.commit()
    
    # Create default user
    default_user = User(
        email="demo@example.com",
        password_hash=bcrypt.hashpw("password".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
        name="Demo User"
    )
    session.add(default_user)
    session.commit()
    
    # Create products with updated images
    products = [
        Product(
            name="Premium Wireless Headphones",
            description="Experience crystal-clear audio with our premium wireless headphones featuring active noise cancellation, 30-hour battery life, and premium comfort padding.",
            price=299.99,
            image_url="/images/products/2f214881-fac9-4619-87c9-117078c1c44b.jpeg",
            stock=50
        ),
        Product(
            name="Smart Fitness Watch",
            description="Track your health and fitness goals with this advanced smartwatch. Features heart rate monitoring, GPS tracking, and 7-day battery life.",
            price=249.99,
            image_url="/images/products/10b88481-d58a-4fc6-9232-5814ace71ca7.jpeg",
            stock=30
        ),
        Product(
            name="Wireless Charging Pad",
            description="Fast wireless charging for all Qi-enabled devices. Sleek design with LED indicators and overcharge protection.",
            price=49.99,
            image_url="/images/products/18ad4ffb-f3b0-4c93-beb3-aea044962fac.jpeg",
            stock=100
        ),
        Product(
            name="Bluetooth Speaker",
            description="Portable Bluetooth speaker with 360-degree sound, waterproof design, and 12-hour battery life. Perfect for outdoor adventures.",
            price=89.99,
            image_url="/images/products/40bd8805-7950-45a9-bfdd-65742489eecc.jpeg",
            stock=75
        ),
        Product(
            name="USB-C Hub",
            description="7-in-1 USB-C hub with HDMI, USB 3.0 ports, SD card reader, and fast charging. Essential for modern laptops and tablets.",
            price=79.99,
            image_url="/images/products/6f7c380c-ec50-4361-bdf5-d8aad68ee148.jpeg",
            stock=60
        ),
        Product(
            name="Wireless Mouse",
            description="Ergonomic wireless mouse with precision tracking, customizable buttons, and long-lasting battery. Perfect for work and gaming.",
            price=39.99,
            image_url="/images/products/7f364abb-8aa3-4dff-8d21-200a327535cc.jpeg",
            stock=120
        )
    ]
    
    session.add_all(products)
    session.commit()
    session.close()
    
    print("✅ Database setup complete!")
    print("✅ Sample products added!")
    print("✅ Default user created (demo@example.com / password)")

if __name__ == "__main__":
    setup_database()
    print("\n🚀 Ready to start the server!")
    print("Run: python app.py")