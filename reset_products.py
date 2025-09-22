from app import session, app
from models import Product, User, Review, Order, init_db
import bcrypt

# Initialize the database and create tables
with app.app_context():
    init_db()

# Clear existing products
session.query(Product).delete()
session.commit()

# Create a default user for reviews if not exists
existing_user = session.query(User).filter_by(email="demo@example.com").first()
if not existing_user:
    default_user = User(
        email="demo@example.com",
        password_hash=bcrypt.hashpw("password".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
        name="Demo User"
    )
    session.add(default_user)
    session.commit()

# Create and add new products with local images
new_products = [
    Product(
        name="Premium Wireless Headphones",
        description="Experience crystal-clear audio with our premium wireless headphones featuring active noise cancellation, 30-hour battery life, and premium comfort padding.",
        price=299.99,
        image_url="/images/products/placeholder.svg",
        stock=50
    ),
    Product(
        name="Smart Fitness Watch",
        description="Track your health and fitness goals with this advanced smartwatch. Features heart rate monitoring, GPS tracking, and 7-day battery life.",
        price=249.99,
        image_url="/images/products/placeholder.svg",
        stock=30
    ),
    Product(
        name="Wireless Charging Pad",
        description="Fast wireless charging for all Qi-enabled devices. Sleek design with LED indicators and overcharge protection.",
        price=49.99,
        image_url="/images/products/placeholder.svg",
        stock=100
    ),
    Product(
        name="Bluetooth Speaker",
        description="Portable Bluetooth speaker with 360-degree sound, waterproof design, and 12-hour battery life. Perfect for outdoor adventures.",
        price=89.99,
        image_url="/images/products/placeholder.svg",
        stock=75
    ),
    Product(
        name="USB-C Hub",
        description="7-in-1 USB-C hub with HDMI, USB 3.0 ports, SD card reader, and fast charging. Essential for modern laptops and tablets.",
        price=79.99,
        image_url="/images/products/placeholder.svg",
        stock=60
    ),
    Product(
        name="Wireless Mouse",
        description="Ergonomic wireless mouse with precision tracking, customizable buttons, and long-lasting battery. Perfect for work and gaming.",
        price=39.99,
        image_url="/images/products/placeholder.svg",
        stock=120
    )
]

session.add_all(new_products)
session.commit()
session.close()

print("Database reset complete! New products added with local images.")
print("You can now replace the placeholder.svg files in /frontend/public/images/products/ with your actual product images.")