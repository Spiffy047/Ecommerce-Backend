# models.py
import sqlalchemy
from sqlalchemy import create_engine, MetaData, orm, Table
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text
from sqlalchemy_serializer import SerializerMixin
from datetime import datetime

convention = {
    "ix": 'ix_%(column_0_label)s',
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
}

metadata = MetaData(naming_convention=convention)
Base = declarative_base(metadata=metadata)

# Define the association table for the many-to-many relationship
order_items_table = Table(
    "order_items",
    Base.metadata,
    Column("order_id", Integer, ForeignKey("orders.id"), primary_key=True),
    Column("product_id", Integer, ForeignKey("products.id"), primary_key=True),
    Column("quantity", Integer),
)

class User(Base, SerializerMixin):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    name = Column(String)

    reviews = relationship("Review", back_populates="user")
    orders = relationship("Order", back_populates="user")

    def __repr__(self):
        return f'<User id={self.id} email={self.email}>'

class Product(Base, SerializerMixin):
    __tablename__ = "products"
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    description = Column(String)
    price = Column(Float, nullable=False)
    image_url = Column(String)
    stock = Column(Integer, default=0)

    reviews = relationship("Review", back_populates="product")
    orders = relationship("Order", secondary=order_items_table, back_populates="products")

    def __repr__(self):
        return f'<Product id={self.id} name={self.name}>'

class Review(Base, SerializerMixin):
    __tablename__ = "reviews"
    id = Column(Integer, primary_key=True)
    rating = Column(Integer)
    comment = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

    user_id = Column(Integer, ForeignKey("users.id"))
    product_id = Column(Integer, ForeignKey("products.id"))

    user = relationship("User", back_populates="reviews")
    product = relationship("Product", back_populates="reviews")

    def __repr__(self):
        return f'<Review id={self.id} rating={self.rating}>'

class Order(Base, SerializerMixin):
    __tablename__ = "orders"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    order_date = Column(DateTime, default=datetime.utcnow)
    status = Column(String)

    user = relationship("User", back_populates="orders")
    products = relationship("Product", secondary=order_items_table, back_populates="orders")

    def __repr__(self):
        return f'<Order id={self.id}>'

def init_db():
    engine = create_engine('sqlite:///ecommerce.db')
    Base.metadata.create_all(engine)
    print("Database and tables created.")
    
def get_db():
    return orm.scoped_session(orm.sessionmaker(bind=create_engine('sqlite:///ecommerce.db')))

def close_db(e=None):
    db = get_db()
    db.remove()

def clear_db():
    engine = create_engine('sqlite:///ecommerce.db')
    Base.metadata.drop_all(engine)
    print("Database tables cleared.")