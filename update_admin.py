#!/usr/bin/env python3
"""
Update admin password to match README
"""

import bcrypt
from models import get_db, User

def update_admin_password():
    """Update admin password to Admin@123"""
    session = get_db()
    
    try:
        # Find admin user
        admin_user = session.query(User).filter_by(email="admin@sportzone.com").first()
        
        if admin_user:
            # Hash the new password: Admin@123
            new_password_hash = bcrypt.hashpw("Admin@123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            admin_user.password_hash = new_password_hash
            session.commit()
            print("✅ Admin password updated to: Admin@123")
        else:
            # Create admin user if doesn't exist
            new_password_hash = bcrypt.hashpw("Admin@123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            answer_hash = bcrypt.hashpw("football".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            admin_user = User(
                email="admin@sportzone.com",
                password_hash=new_password_hash,
                name="Admin User",
                is_admin=1,
                security_question_1="What is your favorite sport?",
                security_answer_1=answer_hash,
                security_question_2="What city were you born in?",
                security_answer_2=answer_hash
            )
            session.add(admin_user)
            session.commit()
            print("✅ Admin user created with password: Admin@123")
            
    except Exception as e:
        session.rollback()
        print(f"❌ Error: {e}")
    finally:
        session.close()

if __name__ == "__main__":
    update_admin_password()