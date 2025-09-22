from app import session, app
from models import Product

with app.app_context():
    # Update specific sports products with better images
    products_to_update = [
        {"name": "Professional Basketball", "image": "/images/products/basketball.svg"},
        {"name": "Smart Fitness Watch", "image": "/images/products/smartwatch.svg"},
    ]
    
    for product_data in products_to_update:
        product = session.query(Product).filter_by(name=product_data["name"]).first()
        if product:
            product.image_url = product_data["image"]
            print(f"Updated {product.name} image to {product.image_url}")
    
    session.commit()
    session.close()
    print("Sports product images updated successfully!")