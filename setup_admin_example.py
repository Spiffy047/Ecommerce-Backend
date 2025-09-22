#!/usr/bin/env python3
"""
Example admin setup script - Copy and modify for your environment
DO NOT commit actual credentials to version control
"""

from app import session, app
from models import User, init_db
import bcrypt
import os

with app.app_context():
    init_db()
    
    # Get credentials from environment variables or prompt
    admin_email = os.getenv('ADMIN_EMAIL') or input("Admin email: ")
    admin_password = os.getenv('ADMIN_PASSWORD') or input("Admin password: ")
    
    if not admin_email or not admin_password:
        print("Email and password are required")
        exit(1)
    
    # Check if admin already exists
    existing_admin = session.query(User).filter_by(email=admin_email).first()
    if existing_admin:
        existing_admin.is_admin = 1
        session.commit()
        print(f"Updated existing user {admin_email} to admin")
    else:
        admin_user = User(
            email=admin_email,
            password_hash=bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
            name="Admin User",
            is_admin=1
        )
        session.add(admin_user)
        session.commit()
        print(f"Created admin user: {admin_email}")
    
    session.close()
    print("Admin setup complete!")