#!/usr/bin/env python3
import requests
import json
import time
import subprocess
import sys

BASE_URL = "http://localhost:5000"

def test_endpoint(method, endpoint, data=None, headers=None, expected_status=200):
    url = f"{BASE_URL}{endpoint}"
    try:
        if method == "GET":
            response = requests.get(url, headers=headers)
        elif method == "POST":
            response = requests.post(url, json=data, headers=headers)
        elif method == "PUT":
            response = requests.put(url, json=data, headers=headers)
        elif method == "DELETE":
            response = requests.delete(url, headers=headers)
        
        print(f"{method} {endpoint}: {response.status_code}")
        if response.status_code != expected_status:
            print(f"  Expected: {expected_status}, Got: {response.status_code}")
            print(f"  Response: {response.text}")
        else:
            print("  ✓ Success")
        
        return response
    except Exception as e:
        print(f"{method} {endpoint}: ERROR - {e}")
        return None

def main():
    print("=== TESTING ALL ENDPOINTS ===")
    
    # Test 1: Get products
    response = test_endpoint("GET", "/api/products")
    if response and response.status_code == 200:
        products = response.json()
        print(f"  Found {len(products)} products")
        if products:
            print(f"  Sample: {products[0]['name']} - KSh {products[0]['price']}")
    
    # Test 2: Admin login
    admin_data = {"email": "admin@sportzone.com", "password": "Admin@123"}
    response = test_endpoint("POST", "/api/auth/admin-login", admin_data)
    
    if response and response.status_code == 200:
        token = response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Test 3: Add product
        new_product = {
            "name": "Test Product",
            "description": "This is a test product for validation",
            "price": 5000.00,
            "stock": 10,
            "image_url": "https://example.com/test.jpg"
        }
        test_endpoint("POST", "/api/products", new_product, headers, 201)
        
        # Test 4: Update product
        update_data = {
            "name": "Updated Test Product",
            "description": "Updated description for test product",
            "price": 6000.00,
            "stock": 15,
            "image_url": "https://example.com/updated.jpg"
        }
        test_endpoint("PUT", "/api/products/1", update_data, headers)
        
        # Test 5: Get single product
        test_endpoint("GET", "/api/products/1")
        
        # Test 6: Get bestsellers
        test_endpoint("GET", "/api/admin/bestsellers", headers=headers)
    
    # Test 7: User registration
    user_data = {
        "email": "test@example.com",
        "password": "Test123!",
        "name": "Test User",
        "phone": "1234567890",
        "address": "Test Address",
        "security_question_1": "What is your favorite color?",
        "security_answer_1": "blue",
        "security_question_2": "What city were you born in?",
        "security_answer_2": "testcity"
    }
    response = test_endpoint("POST", "/api/auth/register", user_data, expected_status=201)
    
    if response and response.status_code == 201:
        user_token = response.json()["access_token"]
        user_headers = {"Authorization": f"Bearer {user_token}"}
        
        # Test 8: Get user profile
        test_endpoint("GET", "/api/user/profile", headers=user_headers)
        
        # Test 9: Get user orders
        test_endpoint("GET", "/api/user/orders", headers=user_headers)
        
        # Test 10: Add review
        review_data = {"rating": 5, "comment": "Great product!"}
        test_endpoint("POST", "/api/products/1/reviews", review_data, user_headers, 201)
        
        # Test 11: Get reviews
        test_endpoint("GET", "/api/products/1/reviews")

if __name__ == "__main__":
    main()