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
        name="Demo User",
        is_admin=0
    )
    session.add(default_user)
    
    # Create admin user
    admin_user = User(
        email="admin@sportzone.com",
        password_hash=bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
        name="Admin User",
        is_admin=1
    )
    session.add(admin_user)
    session.commit()
    
    # Create sports products with updated images
    products = [
        Product(
            name="Professional Basketball",
            description="Official size and weight basketball with superior grip and durability. Perfect for indoor and outdoor courts with premium leather construction.",
            price=3899,
            image_url="/images/products/2f214881-fac9-4619-87c9-117078c1c44b.jpeg",
            stock=50
        ),
        Product(
            name="Smart Fitness Watch",
            description="Track your health and fitness goals with this advanced smartwatch. Features heart rate monitoring, GPS tracking, and 7-day battery life.",
            price=32499,
            image_url="/images/products/10b88481-d58a-4fc6-9232-5814ace71ca7.jpeg",
            stock=30
        ),
        Product(
            name="Yoga Mat Premium",
            description="High-quality non-slip yoga mat with extra cushioning. Eco-friendly materials, perfect grip, and easy to clean. Ideal for all yoga practices.",
            price=6499,
            image_url="/images/products/18ad4ffb-f3b0-4c93-beb3-aea044962fac.jpeg",
            stock=100
        ),
        Product(
            name="Wireless Sports Earbuds",
            description="Sweat-resistant wireless earbuds designed for athletes. Secure fit, premium sound quality, and 8-hour battery life. Perfect for workouts.",
            price=11699,
            image_url="/images/products/40bd8805-7950-45a9-bfdd-65742489eecc.jpeg",
            stock=75
        ),
        Product(
            name="Resistance Band Set",
            description="Complete resistance band set with multiple resistance levels. Includes door anchor, handles, and ankle straps. Perfect for home workouts.",
            price=4399,
            image_url="/images/products/6f7c380c-ec50-4361-bdf5-d8aad68ee148.jpeg",
            stock=60
        ),
        Product(
            name="Running Shoes",
            description="Lightweight running shoes with advanced cushioning and breathable mesh upper. Designed for comfort and performance on any terrain.",
            price=12999,
            image_url="/images/products/7f364abb-8aa3-4dff-8d21-200a327535cc.jpeg",
            stock=120
        )
    ]
    
    session.add_all(products)
    session.commit()
    session.close()
    
    print("✅ Database setup complete!")
    print("✅ Sample sports products added!")
    print("✅ Default user created (demo@example.com / password)")
    print("✅ Admin user created (admin@sportzone.com / admin123)")

if __name__ == "__main__":
    setup_database()
    print("\n🚀 Ready to start the server!")
    print("Run: python app.py")