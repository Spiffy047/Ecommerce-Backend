#!/usr/bin/env python3
"""
Simple script to add new products to the database.
Usage: python add_product.py
"""

from app import session, app
from models import Product

def add_product():
    with app.app_context():
        print("=== Add New Product ===")
        
        name = input("Product Name: ")
        description = input("Product Description: ")
        
        while True:
            try:
                price = float(input("Price ($): "))
                break
            except ValueError:
                print("Please enter a valid price (e.g., 29.99)")
        
        image_filename = input("Image filename (e.g., product.jpg): ")
        image_url = f"/images/products/{image_filename}"
        
        while True:
            try:
                stock = int(input("Stock quantity: "))
                break
            except ValueError:
                print("Please enter a valid stock number")
        
        # Create new product
        new_product = Product(
            name=name,
            description=description,
            price=price,
            image_url=image_url,
            stock=stock
        )
        
        session.add(new_product)
        session.commit()
        
        print(f"\n✅ Product '{name}' added successfully!")
        print(f"📁 Make sure to add the image file '{image_filename}' to:")
        print("   frontend/public/images/products/")
        print(f"💰 Price: ${price}")
        print(f"📦 Stock: {stock}")
        
        session.close()

if __name__ == "__main__":
    add_product()