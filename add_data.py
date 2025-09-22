from app import session, app
from models import Product, User, init_db
import bcrypt

# Initialize the database and create tables
with app.app_context():
    init_db()

# Create a default user for reviews
default_user = User(
    email="demo@example.com",
    password_hash=bcrypt.hashpw("password".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
    name="Demo User"
)
session.add(default_user)
session.commit()

# Create and add new products
new_products = [
    Product(
        name="Wireless Headphones",
        description="High-fidelity wireless headphones with active noise cancellation.",
        price=199.99,
        image_url="https://images.unsplash.com/photo-1505740420928-5e994784775b",
        stock=50
    ),
    Product(
        name="Smart Watch",
        description="Track your fitness and stay connected with a sleek, modern smartwatch.",
        price=129.99,
        image_url="https://images.unsplash.com/photo-1546868871-7041f2a55e12",
        stock=25
    ),
    # Add more products here
]

session.add_all(new_products)
session.commit()
session.close()

print("Products and default user added successfully!")