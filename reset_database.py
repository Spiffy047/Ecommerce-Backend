#!/usr/bin/env python3
"""
Database reset script for the enhanced e-commerce system
This script will drop all tables and recreate them with the new schema
"""

import os
import sys
import bcrypt
from models import clear_db, init_db, get_db, User, Product, Review, Order, OrderItem

def reset_database():
    """Reset the database with new schema and sample data"""
    print("Resetting database...")
    
    # Clear existing database
    clear_db()
    
    # Initialize new database with updated schema
    init_db()
    
    # Get database session
    session = get_db()
    
    try:
        # Create admin user
        admin_password = bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        admin_user = User(
            email="admin@sportzone.com",
            password_hash=admin_password,
            name="Admin User",
            is_admin=1,
            security_question_1="What is your favorite sport?",
            security_answer_1=bcrypt.hashpw("football".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
            security_question_2="What city were you born in?",
            security_answer_2=bcrypt.hashpw("nairobi".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        )
        session.add(admin_user)
        
        # Create sample user
        user_password = bcrypt.hashpw("user123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        sample_user = User(
            email="user@example.com",
            password_hash=user_password,
            name="John Doe",
            phone="+254700123456",
            address="123 Sports Street, Nairobi, Kenya",
            security_question_1="What was the name of your first pet?",
            security_answer_1=bcrypt.hashpw("buddy".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
            security_question_2="What is your mother's maiden name?",
            security_answer_2=bcrypt.hashpw("smith".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        )
        session.add(sample_user)
        
        # Create sample products
        products = [
            Product(
                name="Professional Basketball",
                description="Official size basketball for professional games",
                price=3899.00,
                image_url="/images/products/basketball.jpg",
                stock=50,
                total_sold=25
            ),
            Product(
                name="Smart Fitness Watch",
                description="Advanced fitness tracking with heart rate monitor",
                price=32499.00,
                image_url="/images/products/watch.jpg",
                stock=30,
                total_sold=15
            ),
            Product(
                name="Yoga Mat Premium",
                description="Non-slip yoga mat with carrying strap",
                price=6499.00,
                image_url="/images/products/yoga.jpg",
                stock=100,
                total_sold=40
            ),
            Product(
                name="Running Shoes",
                description="Lightweight running shoes with cushioned sole",
                price=12999.00,
                image_url="/images/products/shoes.jpg",
                stock=75,
                total_sold=30
            ),
            Product(
                name="Tennis Racket",
                description="Professional tennis racket with carbon fiber frame",
                price=18999.00,
                image_url="/images/products/racket.jpg",
                stock=25,
                total_sold=10
            )
        ]
        
        for product in products:
            session.add(product)
        
        session.commit()
        
        # Create sample reviews
        reviews = [
            Review(
                user_id=sample_user.id,
                product_id=1,  # Basketball
                rating=5,
                comment="Excellent quality basketball! Perfect for outdoor games."
            ),
            Review(
                user_id=sample_user.id,
                product_id=2,  # Fitness Watch
                rating=4,
                comment="Great fitness tracker with accurate heart rate monitoring."
            ),
            Review(
                user_id=sample_user.id,
                product_id=3,  # Yoga Mat
                rating=5,
                comment="Very comfortable and non-slip. Perfect for my daily yoga practice."
            )
        ]
        
        for review in reviews:
            session.add(review)
        
        session.commit()
        
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
        
    except Exception as e:
        session.rollback()
        print(f"❌ Error resetting database: {e}")
        sys.exit(1)
    finally:
        session.close()

if __name__ == "__main__":
    reset_database()