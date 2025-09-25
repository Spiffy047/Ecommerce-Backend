#!/usr/bin/env python3
"""
PostgreSQL Setup Script
Sets up PostgreSQL database and migrates existing SQLite data
"""

import os
import subprocess
import sys

def install_dependencies():
    """Install PostgreSQL dependencies"""
    print("Installing PostgreSQL dependencies...")
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', 'requirements_postgresql.txt'])

def setup_environment():
    """Set up environment variables for PostgreSQL"""
    print("\nPostgreSQL Environment Setup")
    print("=" * 40)
    
    # Get PostgreSQL connection details
    host = input("PostgreSQL Host (default: localhost): ").strip() or "localhost"
    port = input("PostgreSQL Port (default: 5432): ").strip() or "5432"
    database = input("Database Name (default: ecommerce): ").strip() or "ecommerce"
    user = input("PostgreSQL Username: ").strip()
    password = input("PostgreSQL Password: ").strip()
    
    # Create .env file
    env_content = f"""# PostgreSQL Configuration
POSTGRES_HOST={host}
POSTGRES_PORT={port}
POSTGRES_DB={database}
POSTGRES_USER={user}
POSTGRES_PASSWORD={password}
"""
    
    with open('.env', 'w') as f:
        f.write(env_content)
    
    print("\n✓ Environment configuration saved to .env file")
    return host, port, database, user, password

def test_connection(host, port, database, user, password):
    """Test PostgreSQL connection"""
    try:
        import psycopg2
        conn = psycopg2.connect(
            host=host,
            database=database,
            user=user,
            password=password,
            port=port
        )
        conn.close()
        print("✓ PostgreSQL connection successful")
        return True
    except Exception as e:
        print(f"✗ PostgreSQL connection failed: {e}")
        return False

def main():
    print("SportZone PostgreSQL Migration Setup")
    print("=" * 40)
    
    # Install dependencies
    install_dependencies()
    
    # Setup environment
    host, port, database, user, password = setup_environment()
    
    # Test connection
    if not test_connection(host, port, database, user, password):
        print("\nPlease check your PostgreSQL configuration and try again.")
        return
    
    print("\n" + "=" * 40)
    print("Setup completed successfully!")
    print("\nNext steps:")
    print("1. Run: python migrate_to_postgresql.py")
    print("2. Replace app.py with app_postgresql.py")
    print("3. Deploy with PostgreSQL configuration")
    print("\nYour existing SQLite data will be preserved during migration.")

if __name__ == '__main__':
    main()