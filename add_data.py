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

# Create and add new sports products with local images
new_products = [
    Product(
        name="Professional Basketball",
        description="Official size and weight basketball with superior grip and durability. Perfect for indoor and outdoor courts with premium leather construction.",
        price=38.99,
        image_url="/images/products/2f214881-fac9-4619-87c9-117078c1c44b.jpeg",
        stock=50
    ),
    Product(
        name="Smart Fitness Watch",
        description="Track your health and fitness goals with this advanced smartwatch. Features heart rate monitoring, GPS tracking, and 7-day battery life.",
        price=324.99,
        image_url="/images/products/placeholder.svg",
        stock=30
    ),
    Product(
        name="Yoga Mat Premium",
        description="High-quality non-slip yoga mat with extra cushioning. Eco-friendly materials, perfect grip, and easy to clean. Ideal for all yoga practices.",
        price=64.99,
        image_url="/images/products/placeholder.svg",
        stock=100
    ),
    Product(
        name="Wireless Sports Earbuds",
        description="Sweat-resistant wireless earbuds designed for athletes. Secure fit, premium sound quality, and 8-hour battery life. Perfect for workouts.",
        price=116.99,
        image_url="/images/products/placeholder.svg",
        stock=75
    ),
    Product(
        name="Resistance Band Set",
        description="Complete resistance band set with multiple resistance levels. Includes door anchor, handles, and ankle straps. Perfect for home workouts.",
        price=43.99,
        image_url="/images/products/placeholder.svg",
        stock=60
    ),
    Product(
        name="Running Shoes",
        description="Lightweight running shoes with advanced cushioning and breathable mesh upper. Designed for comfort and performance on any terrain.",
        price=129.99,
        image_url="/images/products/placeholder.svg",
        stock=120
    )
]

session.add_all(new_products)
session.commit()
session.close()

print("Sports products and default user added successfully!")