from app import session, app
from models import Product

with app.app_context():
    # Map sports products to new images
    image_updates = [
        {"name": "Professional Basketball", "image": "/images/products/2f214881-fac9-4619-87c9-117078c1c44b.jpeg"},
        {"name": "Smart Fitness Watch", "image": "/images/products/10b88481-d58a-4fc6-9232-5814ace71ca7.jpeg"},
        {"name": "Yoga Mat Premium", "image": "/images/products/18ad4ffb-f3b0-4c93-beb3-aea044962fac.jpeg"},
        {"name": "Wireless Sports Earbuds", "image": "/images/products/40bd8805-7950-45a9-bfdd-65742489eecc.jpeg"},
        {"name": "Resistance Band Set", "image": "/images/products/6f7c380c-ec50-4361-bdf5-d8aad68ee148.jpeg"},
        {"name": "Running Shoes", "image": "/images/products/7f364abb-8aa3-4dff-8d21-200a327535cc.jpeg"},
    ]
    
    for update in image_updates:
        product = session.query(Product).filter_by(name=update["name"]).first()
        if product:
            product.image_url = update["image"]
            print(f"Updated {product.name} -> {update['image']}")
        else:
            print(f"Sports item not found: {update['name']}")
    
    session.commit()
    session.close()
    print("\nAll sports item images updated successfully!")